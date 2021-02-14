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
	"encoding/hex"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"

	"encoding/gob"

	"github.com/bobvawter/cacheroach/api/tenant"
	"github.com/bobvawter/cacheroach/pkg/cache"
	"github.com/bobvawter/cacheroach/pkg/store/config"
	"github.com/bobvawter/cacheroach/pkg/store/util"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pkg/errors"
)

// HashSize is the number of bytes used in a Hash.
const HashSize = sha256.Size

// Hash is a cryptographically-secure content-hash value.
type Hash [HashSize]byte

// MarshalBinary implements encoding.BinaryMarshaler.
func (h Hash) MarshalBinary() ([]byte, error) {
	return h[:], nil
}

func (h *Hash) String() string {
	return hex.EncodeToString(h[:])
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (h *Hash) UnmarshalBinary(data []byte) error {
	if len(data) != HashSize {
		return errors.Errorf("length mismatch %d vs %d", HashSize, len(data))
	}
	copy(h[:], data)
	return nil
}

// ropeMeta contains the immutable attributes of a rope.
type ropeMeta struct {
	chunks     []Hash  // The underlying chunks.
	chunkStart []int64 // Starting byte offsets; must be sorted.
	hash       Hash    // Content hash of the blob.
	length     int64   // Total number of bytes in the file
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (m *ropeMeta) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(1); err != nil {
		return nil, err
	}
	if err := enc.Encode(m.chunks); err != nil {
		return nil, err
	}
	if err := enc.Encode(m.chunkStart); err != nil {
		return nil, err
	}
	if err := enc.Encode(m.hash); err != nil {
		return nil, err
	}
	if err := enc.Encode(m.length); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (m *ropeMeta) UnmarshalBinary(data []byte) error {
	dec := gob.NewDecoder(bytes.NewReader(data))

	var ver int
	if err := dec.Decode(&ver); err != nil {
		return err
	}
	if err := dec.Decode(&m.chunks); err != nil {
		return err
	}
	if err := dec.Decode(&m.chunkStart); err != nil {
		return err
	}
	if err := dec.Decode(&m.hash); err != nil {
		return err
	}
	if err := dec.Decode(&m.length); err != nil {
		return err
	}

	return nil
}

// A Blob provides access to the contents of an immutable blob. This
// type implements the http.File interface for ease of integration.
type Blob struct {
	*ropeMeta
	cache  *cache.Cache
	config *config.Config
	db     *pgxpool.Pool
	tID    *tenant.ID
	mu     struct {
		sync.Mutex
		ctx           context.Context // Set by the call to Store.OpenBlob().
		lastChunk     []byte          // Cache a chunk in memory to serve small Read() calls
		lastChunkHash Hash            // The cached chunk.
		pos           int64           // The current read position.
	}
}

var (
	_ http.File   = &Blob{}
	_ io.WriterTo = &Blob{}
	_ os.FileInfo = &Blob{}
)

// Close implements io.Closer.
func (b *Blob) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.mu.ctx = util.Canceled
	b.mu.lastChunk = nil
	return nil
}

// Read implements io.Reader.
func (b *Blob) Read(buf []byte) (int, error) {
	w := bytes.NewBuffer(buf[:0])
	count, err := b.WriteN(w, int64(len(buf)))
	return int(count), err
}

// Readdir implements http.File. It returns nothing since a blob is not
// a directory.
func (b *Blob) Readdir(int) ([]os.FileInfo, error) { return nil, nil }

// Seek implements io.Seeker.
func (b *Blob) Seek(offset int64, whence int) (int64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	switch whence {
	case io.SeekStart:
		b.mu.pos = offset
	case io.SeekCurrent:
		b.mu.pos += offset
	case io.SeekEnd:
		b.mu.pos = b.length - offset
	default:
		return 0, errors.Errorf("unexpected whence: %d", whence)
	}

	return b.mu.pos, nil
}

// Hash returns the content hash of the Blob.
func (b *Blob) Hash() Hash { return b.hash }

// Stat implements http.File.
func (b *Blob) Stat() (os.FileInfo, error) { return b, nil }

// IsDir implements os.FileInfo and returns false.
func (b *Blob) IsDir() bool { return false }

// Mode implements os.FileInfo and returns 0666.
func (b *Blob) Mode() os.FileMode { return 0666 }

// ModTime implements os.FileInfo and returns zero.
func (b *Blob) ModTime() time.Time { return time.Time{}.UTC() }

// Name implements os.FileInfo.Name and returns the content hash.
func (b *Blob) Name() string { return b.hash.String() }

// Size implements os.FileInfo.Size.
func (b *Blob) Size() int64 { return b.length }

func (b *Blob) String() string { return b.hash.String() }

// Sys implements os.FileInfo and returns nil.
func (b *Blob) Sys() interface{} { return nil }

// WriteN writes up to count bytes from the current position into w.
func (b *Blob) WriteN(w io.Writer, count int64) (int64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	startPos := b.mu.pos
	if startPos >= b.length {
		return 0, io.EOF
	}

	ctx := b.mu.ctx
	if hasCtx, ok := w.(interface{ Context() context.Context }); ok {
		ctx = hasCtx.Context()
	}

	for b.mu.pos < b.length && count > 0 {
		chunk, start, length := b.chunkAt(b.mu.pos)
		if count < length {
			length = count
		}

		buf, err := b.loadChunkLocked(ctx, chunk, true)
		if errors.Is(err, pgx.ErrNoRows) {
			buf, err = b.loadChunkLocked(ctx, chunk, false)
		}
		if err != nil {
			return b.mu.pos - startPos, err
		}

		written, err := w.Write(buf[start : start+length])
		count -= int64(written)
		b.mu.pos += int64(written)
		if err != nil {
			err = errors.Wrapf(err, "WriteN %s", b.hash)
			return b.mu.pos - startPos, err
		}
	}

	return b.mu.pos - startPos, nil
}

// WriteTo implements io.WriterTo in order to improve efficiency with
// the io.Copy function.
func (b *Blob) WriteTo(w io.Writer) (written int64, err error) {
	return b.WriteN(w, math.MaxInt64)
}

// chunkAt returns the chunk that contains the given offset within the
// blob, the offset within the chunk to read, and the number of bytes to
// read from the chunk.
func (b *Blob) chunkAt(off int64) (chunk Hash, chunkStart, chunkLength int64) {
	if off < 0 {
		return Hash{}, -1, -1
	}
	idx := sort.Search(len(b.chunkStart), func(i int) bool {
		return b.chunkStart[i] >= off
	})
	if idx == len(b.chunks) || b.chunkStart[idx] > off {
		idx--
	}

	var chunkEnd int64
	if idx+1 == len(b.chunks) {
		chunkEnd = b.length
	} else {
		chunkEnd = b.chunkStart[idx+1]
	}

	if off > chunkEnd {
		return Hash{}, -1, -1
	}

	return b.chunks[idx], off - b.chunkStart[idx], chunkEnd - off
}

// loadChunkLocked reads the chunk with the given hash into memory and
// caches it, given that most buffers passed to Read are much smaller
// than the chunk size.
func (b *Blob) loadChunkLocked(
	ctx context.Context, chunk Hash, aost bool,
) (data []byte, err error) {
	if b.mu.lastChunkHash == chunk {
		data = b.mu.lastChunk
		return
	}

	key := chunkDataKey + chunk.String()
	if b.cache.Get(key, &data) {
		b.mu.lastChunk = data
		b.mu.lastChunkHash = chunk
		return
	}

	err = util.Retry(ctx, func(ctx context.Context) error {
		row := b.db.QueryRow(ctx,
			"SELECT data FROM chunks WHERE chunk = $1 AND tenant = $2",
			chunk[:], b.tID)
		return row.Scan(&data)
	})
	err = errors.Wrapf(err, "loadChunk %s", chunk)
	if err == nil {
		b.cache.Put(key, data)
		b.mu.lastChunk = data
		b.mu.lastChunkHash = chunk
	}

	return
}
