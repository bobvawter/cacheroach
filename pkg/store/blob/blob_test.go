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
	"context"
	"math/rand"
	"testing"
	"time"

	"bytes"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/bobvawter/cacheroach/api/tenant"
	"github.com/stretchr/testify/assert"
)

func TestEnsureChunk(t *testing.T) {
	a := assert.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	s, cleanup, err := testRig(ctx)
	if !a.NoError(err) {
		return
	}
	defer cleanup()

	tID := tenant.NewID()
	_, err = s.tenants.Ensure(ctx, &tenant.EnsureRequest{
		Tenant: &tenant.Tenant{
			ID:    tID,
			Label: "Tenant",
		}})
	if !a.NoError(err) {
		return
	}

	r := rand.New(rand.NewSource(0))
	chunk := make([]byte, 512*1024)
	r.Read(chunk)

	h1, e1 := s.ensureChunk(ctx, tID, chunk)
	if !a.NoError(e1) {
		return
	}
	a.NotEqual(Hash{}, h1)

	h2, e2 := s.ensureChunk(ctx, tID, chunk)
	if !a.NoError(e2) {
		return
	}
	a.Equal(h1, h2)
}

func TestRope(t *testing.T) {
	a := assert.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()

	s, cleanup, err := testRig(ctx)
	if !a.NoError(err) {
		return
	}
	defer cleanup()

	tID := tenant.NewID()
	_, err = s.tenants.Ensure(ctx, &tenant.EnsureRequest{
		Tenant: &tenant.Tenant{
			ID:    tID,
			Label: "Tenant",
		}})
	if !a.NoError(err) {
		return
	}

	chunkSize := int64(s.ChunkSize)
	blobLength := 5 * chunkSize

	var hash Hash
	data := make([]byte, blobLength)
	r := rand.New(rand.NewSource(0))
	r.Read(data)

	t.Run("insertBlob", func(t *testing.T) {
		a := assert.New(t)

		h1, err := s.EnsureBlob(ctx, tID, bytes.NewReader(data))
		if !a.NoError(err) {
			return
		}
		a.NotEqual(Hash{}, h1)
		hash = h1
	})

	t.Run("idempotent", func(t *testing.T) {
		a := assert.New(t)
		h2, err := s.EnsureBlob(ctx, tID, bytes.NewReader(data))
		if !a.NoError(err) {
			return
		}
		a.Equal(hash, h2)
	})

	f, err := s.OpenBlob(ctx, tID, hash)
	if !a.NoError(err) {
		return
	}

	t.Run("chunkAt", func(t *testing.T) {
		tcs := []struct {
			pos         int64
			chunkIdx    int
			chunkStart  int64
			chunkLength int64
		}{
			{-1, -1, -1, -1},
			{0, 0, 0, chunkSize},
			{1, 0, 1, chunkSize - 1},
			{chunkSize - 1, 0, chunkSize - 1, 1},
			{chunkSize, 1, 0, chunkSize},
			{chunkSize + 1, 1, 1, chunkSize - 1},
			{blobLength - chunkSize - 1, len(f.chunks) - 2, chunkSize - 1, 1},
			{blobLength - chunkSize, len(f.chunks) - 1, 0, chunkSize},
			{blobLength - 1, len(f.chunks) - 1, chunkSize - 1, 1},
			{blobLength, len(f.chunks) - 1, chunkSize, 0},
			{blobLength + 1, -1, -1, -1},
			{blobLength + 2*chunkSize, -1, -1, -1},
		}

		for _, tc := range tcs {
			t.Run(fmt.Sprintf("%v", tc), func(t *testing.T) {
				a := assert.New(t)
				h, chunkStart, chunkLength := f.chunkAt(tc.pos)
				if tc.chunkIdx < 0 {
					a.Equal(Hash{}, h)
				} else {
					a.Equal(f.chunks[tc.chunkIdx], h)
					a.Equal(tc.chunkStart, chunkStart)
					a.Equal(tc.chunkLength, chunkLength)
				}
			})
		}
	})

	t.Run("read", func(t *testing.T) {
		a := assert.New(t)
		f, err := s.OpenBlob(ctx, tID, hash)
		if !a.NoError(err) {
			return
		}

		if data, err := ioutil.ReadAll(f); a.NoError(err) {
			a.Equal(data, data)
		}
	})

	t.Run("writeTo", func(t *testing.T) {
		a := assert.New(t)
		f, err := s.OpenBlob(ctx, tID, hash)
		if !a.NoError(err) {
			return
		}

		var buf bytes.Buffer
		written, err := io.Copy(&buf, f)
		if a.NoError(err) && a.Equal(int64(blobLength), written) {
			a.Equal(data, buf.Bytes())
		}
	})
}
