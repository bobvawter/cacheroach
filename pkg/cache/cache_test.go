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

package cache

import (
	"context"
	"io/ioutil"
	"os"
	"testing"

	"github.com/Mandala/go-log"
	"github.com/stretchr/testify/assert"
)

func TestCache(t *testing.T) {
	a := assert.New(t)

	ctx := context.Background()
	logger := log.New(os.Stdout).WithDebug().WithoutColor()

	d, err := ioutil.TempDir("", "cacheroach-*")
	if !a.NoError(err) {
		return
	}

	var added, missed []string

	cfg := &Config{
		MaxMem:  1024,
		MaxDisk: 1024,
		Path:    d,
		OnAdd: func(key string, _ []byte) {
			added = append(added, key)
		},
		OnMiss: func(key string) ([]byte, error) {
			missed = append(missed, key)
			return nil, os.ErrNotExist
		},
	}

	c, cleanup, err := testRig(ctx, cfg, logger)
	if !a.NoError(err) {
		return
	}
	defer cleanup()

	const key = "key"
	const val = "Hello world!"
	var x string
	var y []byte

	a.False(c.Get(key, &x))
	a.Empty(x)

	c.Put(key, val)
	a.Equal(1, c.mem.Len())

	a.True(c.Get(key, &x))
	a.Equal(val, x)

	a.True(c.Get(key, &y))
	a.Equal([]byte(val), y)

	// Reset the mem cache to force reload from disk.
	a.NoError(c.mem.Reset())
	a.Equal(0, c.mem.Len())

	a.True(c.Get(key, &x))
	a.Equal(val, x)
	a.Equal(1, c.mem.Len())

	a.Equal([]string{key}, added)
	a.Equal([]string{key}, missed)

	// Check read-through behavior.
	cfg.OnMiss = func(key string) ([]byte, error) {
		return []byte(key), nil
	}
	a.True(c.Get("foo", &x))
	a.Equal("foo", x)
	a.Equal(2, c.mem.Len())

	// Purge the disk cache.
	cfg.MaxDisk = 0
	n, err := c.Prune()
	a.NoError(err)
	a.Equal(2, n)
}
