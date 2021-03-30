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
	"bytes"
	"context"
	"errors"
	"io"
	gofs "io/fs"
	"math/rand"
	"testing"
	"time"

	"github.com/bobvawter/cacheroach/api/tenant"
	"github.com/bobvawter/cacheroach/pkg/store/util"
	"github.com/stretchr/testify/assert"
)

func TestFileFlow(t *testing.T) {
	const blobLength = 512 * 1024
	a := assert.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()

	rig, cleanup, err := testRig(ctx)
	if !a.NoError(err) {
		return
	}
	defer cleanup()

	data := make([]byte, blobLength)
	r := rand.New(rand.NewSource(0))
	r.Read(data)

	tID := tenant.NewID()
	tnt, err := rig.t.Ensure(ctx, &tenant.EnsureRequest{Tenant: &tenant.Tenant{
		Label: "Some Tenant",
		ID:    tID,
	}})
	if !a.NoError(err) {
		return
	}

	hash, err := rig.b.EnsureBlob(ctx, tID, bytes.NewReader(data))
	if !a.NoError(err) {
		return
	}

	const path = "/some/path"
	fs := rig.fs.FileSystem(tID)
	a.Equal(tID, fs.Tenant())

	t.Run("loadMissingFile", func(t *testing.T) {
		a := assert.New(t)
		_, err := fs.Open(path)
		a.Truef(errors.Is(err, gofs.ErrNotExist), "%v", err)
	})

	t.Run("ensureFile", func(t *testing.T) {
		a := assert.New(t)

		m := &FileMeta{
			Meta: map[string]string{
				"foo": "bar",
			},
			Path: path,
		}
		err := fs.Put(ctx, m, hash)
		a.NoError(err)
		a.Equal(int64(1), m.Version)
		a.NotEqual(time.Time{}, m.CTime)
		a.NotEqual(time.Time{}, m.MTime)

		err = fs.Put(ctx, m, hash)
		a.NoError(err)
		a.Equal(int64(2), m.Version)
		a.True(m.MTime.After(m.CTime))

		m.Version = 88
		err = fs.Put(ctx, m, hash)
		a.True(errors.Is(err, util.ErrVersionSkew))
	})

	t.Run("get", func(t *testing.T) {
		a := assert.New(t)
		f, err := fs.OpenVersion(ctx, path, -1)
		if !a.NoError(err) {
			return
		}
		a.Equal(int64(2), f.Version)

		if data, err := io.ReadAll(f); a.NoError(err) {
			a.Equal(data, data)
		}
		a.Equal(int64(len(data)), f.Length())
		a.NoError(f.Close())
	})

	t.Run("list", func(t *testing.T) {
		a := assert.New(t)

		f, err := fs.Open("/")
		if !a.NoError(err) {
			return
		}
		stat, err := f.Stat()
		if !a.NoError(err) {
			return
		}
		a.True(stat.IsDir())

		files, err := f.(gofs.ReadDirFile).ReadDir(-1)
		if !a.NoError(err) {
			return
		}
		if !a.Len(files, 1) {
			return
		}

		some := files[0]
		a.Equal("/some", some.Name())
		a.True(some.IsDir())

		f, err = fs.Open(some.Name())
		if !a.NoError(err) {
			return
		}
		stat, err = f.Stat()
		if !a.NoError(err) {
			return
		}
		a.True(stat.IsDir())
		a.Equal("/some", stat.Name())

		files, err = f.(gofs.ReadDirFile).ReadDir(-1)
		if !a.NoError(err) {
			return
		}
		a.Len(files, 1)

		some = files[0]
		a.Equal("/some/path", some.Name())
		a.False(some.IsDir())
	})

	t.Run("delete", func(t *testing.T) {
		a := assert.New(t)

		// Ensure the deleted file is not in the listing
		root, err := fs.Open("/")
		if !a.NoError(err) {
			return
		}
		files, err := root.(gofs.ReadDirFile).ReadDir(-1)
		if !a.NoError(err) {
			return
		}
		a.Len(files, 1)

		a.NoError(fs.Delete(ctx, path))

		_, err = fs.Open(path)
		a.Truef(errors.Is(err, gofs.ErrNotExist), "%v", err)

		// Ensure the deleted file is not in the listing
		files, err = root.(gofs.ReadDirFile).ReadDir(-1)
		if !a.NoError(err) {
			return
		}
		a.Len(files, 0)
	})

	t.Run("delete tenant and purge", func(t *testing.T) {
		old := rig.cfg.PurgeDuration
		rig.cfg.PurgeDuration = 0
		defer func() { rig.cfg.PurgeDuration = old }()

		_, err := rig.t.Ensure(ctx, &tenant.EnsureRequest{Tenant: tnt.Tenant, Delete: true})
		if !a.NoError(err) {
			return
		}
		a.NoError(rig.fs.purge(ctx))

		ct := -1
		err = rig.fs.db.QueryRow(ctx, "SELECT count(*) FROM chunks").Scan(&ct)
		a.NoError(err)
		a.Equal(0, ct)
	})
}
