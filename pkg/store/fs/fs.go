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
	"context"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/bobvawter/cacheroach/api/tenant"
	"github.com/bobvawter/cacheroach/pkg/store/blob"
	"github.com/bobvawter/cacheroach/pkg/store/util"
	"github.com/jackc/pgx/v4"
	"github.com/pkg/errors"
)

// FileSystem provides multi-tenant access to named files.
type FileSystem struct {
	store  *Store
	tenant *tenant.ID
}

var _ http.FileSystem = &FileSystem{}

// Delete ensures that no file exists with the given name.
func (f *FileSystem) Delete(ctx context.Context, name string) error {
	return util.Retry(ctx, func(ctx context.Context) error {
		_, err := f.store.db.Exec(ctx,
			"UPDATE files SET dtime = now() WHERE tenant = $1 AND path = $2 AND dtime IS NULL",
			f.tenant, name)
		return err
	})
}

// Get returns an open handle to the named file. If version <= 0, the
// latest version of the file will be returned.
func (f *FileSystem) Get(ctx context.Context, name string, version int64) (*File, error) {
	name = path.Clean(name)

	var hash blob.Hash
	m := &FileMeta{
		Meta:    make(map[string]string),
		Version: version,
	}

	err := util.Retry(ctx, func(ctx context.Context) error {
		var err error
		h := make([]byte, blob.HashSize)

		if version <= 0 {
			row := f.store.db.QueryRow(ctx,
				"SELECT ctime, mtime, meta, hash, version "+
					"FROM files "+
					"WHERE tenant = $1 "+
					"AND path = $2 "+
					"AND dtime IS NULL "+
					"ORDER BY version DESC "+
					"LIMIT 1",
				f.tenant, name)
			err = row.Scan(&m.CTime, &m.MTime, &m.Meta, &h, &m.Version)
		} else {
			row := f.store.db.QueryRow(ctx,
				"SELECT ctime, mtime, meta, hash "+
					"FROM files "+
					"WHERE tenant = $1 "+
					"AND path = $2 "+
					"AND version = $3 "+
					"AND dtime IS NULL "+
					"LIMIT 1",
				f.tenant, name, version)
			err = row.Scan(&m.CTime, &m.MTime, &m.Meta, &h)
		}

		copy(hash[:], h)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, errors.Wrapf(err, "%s:%s", f.tenant, name)
	}

	b, err := f.store.blobs.OpenBlob(ctx, f.tenant, hash)
	if errors.Is(err, os.ErrNotExist) {
		// Empty file, this is OK.
	} else if err != nil {
		return nil, errors.Wrapf(err, "%s:%s", f.tenant, name)
	}

	return &File{
		FileMeta: m,
		Blob:     b,
	}, nil
}

// Open implements http.Filesystem and simply wraps Get. If there is
// no file with that path, Open will look instead to see if there are
// any files with that path prefix.  If so, it will return a File that
// represents a directory listing.
func (f *FileSystem) Open(name string) (http.File, error) {
	ctx := context.Background()
	name = path.Clean(name)

	if name == "/" {
		return &dir{path: "/", fs: f}, nil
	}
	ret, err := f.Get(ctx, name, -1)
	if errors.Is(err, os.ErrNotExist) {
		rows, err := f.store.db.Query(ctx,
			"SELECT path "+
				"FROM files "+
				"WHERE tenant = $1 "+
				"AND path LIKE $2 "+
				"AND dtime IS NULL "+
				"LIMIT 1",
			f.tenant, name+"/%")
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		if rows.Next() {
			return &dir{
				path: name + "/",
				fs:   f,
			}, nil
		}
	}
	return ret, err
}

// Put creates or updates a file that is associated with the given
// content hash. The FileMeta will be updated by this call.
func (f *FileSystem) Put(ctx context.Context, meta *FileMeta, hash blob.Hash) error {
	meta.Path = path.Clean(meta.Path)
	meta.Tenant = f.tenant
	err := util.Retry(ctx, func(ctx context.Context) error {
		tx, err := f.store.db.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)

		// Select the latest version
		row := tx.QueryRow(ctx,
			"SELECT ctime, version FROM files "+
				"WHERE tenant = $1 "+
				"AND path = $2 "+
				"ORDER BY version DESC "+
				"LIMIT 1",
			meta.Tenant, meta.Path)

		var cTime time.Time
		latestVersion := int64(0)
		if err := row.Scan(&cTime, &latestVersion); errors.Is(err, pgx.ErrNoRows) {
			if meta.Version > 0 {
				return util.ErrVersionSkew
			}
		} else if err != nil {
			return err
		} else if meta.Version < 0 {
			// Unconditionally overwrite; used for non-RPC clients.
		} else if meta.Version != latestVersion {
			return util.ErrVersionSkew
		}
		nextVersion := latestVersion + 1

		now := time.Now().UTC()
		if latestVersion == 0 {
			cTime = now
		}

		if _, err := tx.Exec(ctx,
			"INSERT INTO files (tenant, path, version, hash, meta, ctime, mtime) "+
				"VALUES ($1, $2, $3, $4, $5, $6, $7) ",
			f.tenant, meta.Path, nextVersion, hash[:], meta.Meta, cTime, now); err != nil {
			return nil
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}

		meta.CTime = cTime
		meta.MTime = now
		meta.Version = nextVersion
		return nil
	})
	return errors.Wrapf(err, "%s:%s@%d", f.tenant, meta.Path, meta.Version)
}

// Tenant returns the tenant associated with the FileSystem.
func (f *FileSystem) Tenant() *tenant.ID {
	return f.tenant
}
