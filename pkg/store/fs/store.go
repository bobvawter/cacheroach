// Copyright 2021 The Cockroach Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fs

import (
	"time"

	"context"

	"github.com/Mandala/go-log"
	"github.com/bobvawter/cacheroach/api/file"
	"github.com/bobvawter/cacheroach/api/tenant"
	"github.com/bobvawter/cacheroach/pkg/store/blob"
	"github.com/bobvawter/cacheroach/pkg/store/config"
	"github.com/google/wire"
	"github.com/jackc/pgx/v4/pgxpool"
)

// Set is used by wire.
var Set = wire.NewSet(
	ProvideStore,
	wire.Struct(new(Server), "*"),
	wire.Bind(new(file.FilesServer), new(*Server)),
)

// Store is a factory for FileSystem instances.
type Store struct {
	blobs  *blob.Store
	config *config.Config
	db     *pgxpool.Pool
	logger *log.Logger
}

// ProvideStore is called by wire.
func ProvideStore(
	ctx context.Context,
	blobs *blob.Store,
	config *config.Config,
	db *pgxpool.Pool,
	logger *log.Logger,
) (*Store, func(), error) {
	ctx, cancel := context.WithCancel(ctx)

	s := &Store{
		blobs:  blobs,
		config: config,
		db:     db,
		logger: logger,
	}

	if config.PurgeDuration > 0 && config.PurgeLimit > 0 {
		go func() {
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := s.purge(ctx); err != nil {
						logger.Warnf("could not purge data: %v", err)
					}
				}
			}
		}()
	}

	return s, cancel, nil
}

// FileSystem returns a filesystem abstraction around the store.
func (s *Store) FileSystem(tenant *tenant.ID) *FileSystem {
	return &FileSystem{
		store:  s,
		tenant: tenant,
	}
}

// purge will remove deleted file entries, dangling ropes, and dangling chunks.
// The queries that it executes will
func (s *Store) purge(ctx context.Context) error {
	cutoff := time.Now().Add(-s.config.PurgeDuration)
	if dels, err := s.db.Exec(ctx, `
DELETE FROM files
WHERE dtime IS NOT NULL
AND dtime < $1
LIMIT $2
`,
		cutoff, s.config.PurgeLimit); err == nil {
		s.logger.Debugf("purged %d deleted files", dels.RowsAffected())
	} else {
		return err
	}

	// A rope is used if:
	//   * it's non-null hash is referenced from a file
	//   * has the same ID as a recent upload
	if dels, err := s.db.Exec(ctx, `
WITH
file_refs AS (
  SELECT rope FROM ropes
  JOIN files ON (ropes.hash IS NOT NULL AND ropes.hash = files.hash)),
upload_refs AS (
  SELECT rope FROM ropes
  JOIN uploads ON (ropes.rope = uploads.upload AND uploads.started_at >= $1)),
unused_ropes AS (
  SELECT rope FROM ropes
  EXCEPT SELECT rope FROM file_refs
  EXCEPT SELECT rope FROM upload_refs)
DELETE FROM ropes WHERE rope IN (SELECT DISTINCT rope FROM unused_ropes)
LIMIT $2
`,
		cutoff, s.config.PurgeLimit); err == nil {
		s.logger.Debugf("purged %d dangling ropes", dels.RowsAffected())
	} else {
		return err
	}

	// A chunk is used only if it is referenced by a rope
	if dels, err := s.db.Exec(ctx, `
WITH unused AS (
  SELECT tenant, chunk FROM chunks
  LEFT JOIN ropes USING (tenant, chunk)
  WHERE (ropes.chunk is null)
)
DELETE FROM chunks
WHERE chunk IN (SELECT chunk FROM unused)
LIMIT $1
`,
		s.config.PurgeLimit); err == nil {
		s.logger.Debugf("purged %d dangling chunks", dels.RowsAffected())
	} else {
		return err
	}

	return nil
}
