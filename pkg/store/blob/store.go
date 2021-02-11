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

package blob

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"math"
	"os"
	"time"

	"github.com/Mandala/go-log"
	"github.com/bobvawter/cacheroach/api/tenant"
	"github.com/bobvawter/cacheroach/pkg/cache"
	"github.com/bobvawter/cacheroach/pkg/store/config"
	"github.com/bobvawter/cacheroach/pkg/store/util"
	"github.com/google/uuid"
	"github.com/google/wire"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
)

// Set is used by wire.
var Set = wire.NewSet(ProvideStore)

const (
	blobMetaKey  = "meta:"
	chunkDataKey = "chunk:"
)

// Store provides access to blobs.
type Store struct {
	cache  *cache.Cache
	config *config.Config
	db     *pgxpool.Pool
	logger *log.Logger
	sem    *semaphore.Weighted
}

// ProvideStore is used by wire.
func ProvideStore(
	ctx context.Context,
	cache *cache.Cache,
	config *config.Config,
	db *pgxpool.Pool,
	logger *log.Logger,
) (*Store, func()) {
	ctx, cancel := context.WithCancel(ctx)
	s := &Store{
		cache:  cache,
		config: config,
		db:     db,
		logger: logger,
		sem:    semaphore.NewWeighted(int64(config.ChunkConcurrency)),
	}

	// Start a loop to monitor the cluster's read amplification. If it
	// rises above a user-configurable threshold, we'll steal N-1
	// semaphore entries
	go s.backoffLoop(ctx)

	return s, cancel
}

// CommitRope associates a content hash with the given rope.
func (s *Store) CommitRope(ctx context.Context, tID *tenant.ID, ropeID uuid.UUID, hash Hash) error {
	return util.Retry(ctx, func(ctx context.Context) error {
		_, err := s.db.Exec(ctx,
			"UPDATE ropes SET hash = $1 where rope = $2 AND tenant = $3",
			hash[:], ropeID, tID)
		if pgErr, ok := err.(*pgconn.PgError); ok {
			// Duplicate index entry; we'll delete the UUID that we just created.
			if pgErr.Code == "23505" {
				_, err = s.db.Exec(ctx,
					"DELETE FROM ropes where rope = $1 AND tenant = $2",
					ropeID, tID)
			}
		}
		return err
	})
}

// EnsureBlob will insert the contents provided by the given reader into
// the database, returning a content hash.
//
// This method is idempotent.
func (s *Store) EnsureBlob(ctx context.Context, tID *tenant.ID, data io.Reader) (Hash, error) {
	u := uuid.New()
	h := sha256.New()

	if _, err := s.InsertToRope(ctx, tID, u, data, h, 0); err != nil {
		return Hash{}, err
	}

	var ret Hash
	h.Sum(ret[:0])

	return ret, s.CommitRope(ctx, tID, u, ret)
}

// InsertToRope will append contents provided by the given reader to
// the given rope, starting at the specified offset.
// The data will also be fed to the given hash function.
func (s *Store) InsertToRope(
	ctx context.Context,
	tID *tenant.ID,
	ropeID uuid.UUID,
	data io.Reader,
	hasher hash.Hash,
	offset int64,
) (int64, error) {
	done := false
	empty := true
	var eg errgroup.Group

loop:
	for !done {
		buf := make([]byte, s.config.ChunkSize)
		read, err := io.ReadFull(data, buf)
		switch {
		case errors.Is(err, io.ErrUnexpectedEOF):
			// Short read on final chunk.
			done = true
		case errors.Is(err, io.EOF):
			if !empty {
				break loop
			}
		case err != nil:
			return 0, err
		}
		empty = false

		cOff := offset
		offset += int64(read)

		// Acquire a semaphore entry in an interruptable manner.
		for !s.sem.TryAcquire(1) {
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			case <-time.After(100 * time.Millisecond):
				// Try again.
			}
		}

		eg.Go(func() error {
			err = s.ensureChunkInRope(ctx, tID, ropeID, buf[:read], cOff)
			s.sem.Release(1)
			return err
		})

		// Update the hash after we've started the db transaction.
		hasher.Write(buf[:read])
	}

	return offset, eg.Wait()
}

// OpenBlob returns an encapsulation of a blob with the given hash. This
// method returns os.ErrNotExist if no blob with the given content hash
// exists.
func (s *Store) OpenBlob(ctx context.Context, tID *tenant.ID, hash Hash) (*Blob, error) {
	// Prefer AOST data queries.
	meta, err := s.loadRopeMeta(ctx, tID, hash, true)
	if errors.Is(err, os.ErrNotExist) {
		meta, err = s.loadRopeMeta(ctx, tID, hash, false)
	}

	b := &Blob{
		cache:    s.cache,
		config:   s.config,
		ropeMeta: meta,
		db:       s.db,
		tID:      tID,
	}
	b.mu.ctx = ctx

	return b, errors.Wrapf(err, "OpenBlob %s", hash)
}

// When CockroachDB experiences a heavy write workload, the compaction
// process can back up if there's insufficient disk throughput
// available. This function monitors the cluster's current level of read
// amplification, which serves as a useful proxy metric for detecting an
// overloaded cluster.
func (s *Store) backoffLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	backingOff := false

	update := func() {
		row := s.db.QueryRow(ctx,
			"SELECT max(metrics->'rocksdb.read-amplification') FROM crdb_internal.kv_store_status")

		var ampf float64
		if err := row.Scan(&ampf); err != nil {
			s.logger.Warnf("could not measure cluster read amplification: %v", err)
			return
		}
		amp := int(math.Ceil(ampf))

		if amp <= s.config.ReadAmplificationBackoff {
			if backingOff {
				backingOff = false
				s.sem.Release(int64(s.config.ChunkConcurrency - 1))
				s.logger.Infof("read amplification recovered")
			}
			return
		}

		if backingOff {
			s.logger.Warnf("still backing off due to read amplification %d vs %d",
				amp, s.config.ReadAmplificationBackoff)
		} else {
			s.logger.Warnf("backing off due to read amplification %d vs %d",
				amp, s.config.ReadAmplificationBackoff)
			backingOff = true
			s.sem.Acquire(ctx, int64(s.config.ChunkConcurrency-1))
		}
	}

	for {
		update()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// ensureChunk inserts the given chunks of data, returning the content hash.
func (s *Store) ensureChunk(
	ctx context.Context, tID *tenant.ID, chunk []byte,
) (hash Hash, err error) {
	h := sha256.New()
	if _, err = io.Copy(h, bytes.NewReader(chunk)); err != nil {
		return
	}

	h.Sum(hash[:0])

	err = util.Retry(ctx, func(ctx context.Context) error {
		tag, err := s.db.Exec(ctx,
			"INSERT INTO chunks (tenant, chunk, data) "+
				"VALUES ($1, $2, $3) "+
				"ON CONFLICT DO NOTHING",
			tID, hash[:], chunk)
		if err == nil && tag.RowsAffected() > 0 {
			s.logger.Debugf("stored chunk %q", hash)
		}
		return err
	})
	return
}

func (s *Store) ensureChunkInRope(
	ctx context.Context, tID *tenant.ID, ropeID uuid.UUID, chunk []byte, offset int64,
) error {
	chunkHash, err := s.ensureChunk(ctx, tID, chunk)
	if err != nil {
		return err
	}

	return util.Retry(ctx, func(ctx context.Context) error {
		tag, err := s.db.Exec(ctx,
			"INSERT INTO ropes (tenant, rope, off, chunk, chunk_length) "+
				"VALUES ($1, $2, $3, $4, $5) "+
				"ON CONFLICT DO NOTHING",
			tID, ropeID, offset, chunkHash[:], len(chunk))
		if err == nil && tag.RowsAffected() > 0 {
			s.logger.Debugf("attached chunk %q to rope %q", chunkHash, ropeID)
		}
		return err
	})
}

func (s *Store) loadRopeMeta(
	ctx context.Context, tID *tenant.ID, hash Hash, aost bool,
) (*ropeMeta, error) {
	meta := &ropeMeta{}
	key := blobMetaKey + hash.String()
	if s.cache.Get(key, meta) {
		return meta, nil
	}

	q := "SELECT chunk, chunk_length, off FROM ropes"
	if aost {
		q += fmt.Sprintf(" AS OF SYSTEM TIME '%s'", s.config.AOST)
	}
	q += " WHERE hash = $1 AND tenant = $2 ORDER BY off ASC"

	err := util.Retry(ctx, func(ctx context.Context) error {
		rows, err := s.db.Query(ctx, q, hash[:], tID)
		if err != nil {
			return err
		}
		defer rows.Close()

		meta.hash = hash

		h := make([]byte, HashSize)
		chunkLen := int64(0)
		for i := 0; rows.Next(); i++ {
			meta.chunks = append(meta.chunks, Hash{})
			meta.chunkStart = append(meta.chunkStart, 0)
			if err := rows.Scan(&h, &chunkLen, &meta.chunkStart[i]); err != nil {
				return errors.Wrapf(err, "chunk: %d", i)
			}
			copy(meta.chunks[i][:], h)
			meta.length += chunkLen
		}
		if meta.length == 0 {
			return os.ErrNotExist
		}
		return nil
	})

	if err == nil {
		s.cache.Put(key, meta)
	}
	return meta, errors.Wrapf(err, "loadRopeMeta: %s", hash)
}
