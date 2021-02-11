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

// Package cache implements a caching strategy for byte slices.
package cache

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"io"
	"io/ioutil"
	mathrand "math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/Mandala/go-log"
	bigcache "github.com/allegro/bigcache/v3"
	"github.com/google/wire"
	"github.com/pkg/errors"
	"github.com/spf13/pflag"
)

// Set is used by wire.
var Set = wire.NewSet(
	ProvideCache,
)

// Config provides knobs for the cache.
type Config struct {
	MaxMem  int    // Maximum in-memory cache size, in MB.
	MaxDisk int    // Maximum on-disk cache size, in MB.
	Path    string // The location of the disk cache.

	// OnAdd is an optional callback that will be notified when new
	// data is added to the cache.
	OnAdd func(key string, data []byte)

	// OnMiss provides an escape-hatch for retrieving cached data from
	// other stores. Any non-nil error may be returned to indicate a
	// cache miss.
	OnMiss func(key string) ([]byte, error)
}

// Bind attaches the configuration to the pflag.FlagSet.
func (c *Config) Bind(flags *pflag.FlagSet) {
	flags.StringVar(&c.Path, "cacheDir", "",
		"persistent cache location")
	flags.IntVar(&c.MaxDisk, "cacheDiskSpace", 1024,
		"the size (in megabytes) of the persistent cache")
	flags.IntVar(&c.MaxMem, "cacheMemory", 256,
		"the size (in megabytes) of the in-memory cache")
}

// Cache implements a 3-level caching strategy.
type Cache struct {
	logger *log.Logger
	cfg    *Config
	mem    *bigcache.BigCache
}

// ProvideCache is called by wire.
func ProvideCache(
	ctx context.Context,
	cfg *Config,
	logger *log.Logger,
) (*Cache, func(), error) {
	cacheCfg := bigcache.DefaultConfig(time.Hour)
	cacheCfg.HardMaxCacheSize = cfg.MaxMem
	cacheCfg.Shards = 128
	cacheCfg.Logger = &logWrapper{logger}

	mem, err := bigcache.NewBigCache(cacheCfg)
	if err != nil {
		return nil, nil, err
	}

	c := &Cache{
		cfg:    cfg,
		logger: logger,
		mem:    mem,
	}

	ctx, cancel := context.WithCancel(ctx)
	go func() {
		defer mem.Close()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if n, err := c.Prune(); err == nil {
					logger.Tracef("pruned %d files", n)
				} else {
					logger.Warnf("could not prune disk cache: %v", err)
				}
			}
		}
	}()

	return c, cancel, nil
}

// Get retrieves a value from the cache, providing it to val, which
// must be a *[]byte, *string, or encoding.BinaryUnmarshaler.
func (c *Cache) Get(key string, val interface{}) bool {
	var storeMem, storeDisk bool
	data, err := c.mem.Get(key)
	if err != nil {
		data, err = c.load(key)
		storeMem = true
	}
	if fn := c.cfg.OnMiss; err != nil && fn != nil {
		data, err = fn(key)
		storeDisk = true
	}
	if err != nil {
		c.logger.Tracef("cache miss on %s: %v", key, err)
		return false
	}
	if storeDisk {
		if err := c.store(key, data); err != nil {
			c.logger.Tracef("could not transfer %s to disk: %v", key, err)
		}
	}
	if storeMem {
		if err := c.mem.Set(key, data); err != nil {
			c.logger.Tracef("could not transfer %s to memory (%d bytes): %v", key, len(data), err)
		}
	}

	switch t := val.(type) {
	case nil:
		return false

	case *[]byte:
		*t = data
		return true

	case *string:
		*t = string(data)
		return true

	case encoding.BinaryUnmarshaler:
		if err := t.UnmarshalBinary(data); err != nil {
			c.logger.Debugf("could not unmarshal key %s: %v", key, err)
			return false
		}
		return true

	default:
		panic(errors.Errorf("unimplemented: %T", t))
	}
}

// Put stores a value into the Cache. The value must be a []byte,
// string, or an object which implements encoding.BinaryMarshaler.
func (c *Cache) Put(key string, val interface{}) {
	var data []byte
	switch t := val.(type) {
	case nil:
		return

	case *[]byte:
		data = *t
	case []byte:
		data = t

	case *string:
		data = []byte(*t)
	case string:
		data = []byte(t)

	case encoding.BinaryMarshaler:
		var err error
		data, err = t.MarshalBinary()
		if err != nil {
			c.logger.Debugf("could not cache key %s: %v", key, err)
			return
		}

	default:
		panic(errors.Errorf("unimplemented: %T", t))
	}

	if err := c.mem.Set(key, data); err != nil {
		c.logger.Debugf("could not cache key %s in memory: %v", key, err)
	}
	if err := c.store(key, data); err != nil {
		c.logger.Debugf("could not store key %s on disk: %v", key, err)
	}
	if fn := c.cfg.OnAdd; fn != nil {
		fn(key, data)
	}
}

// Prune removes cache files until they are below the configured
// threshold. Since atime is often disabled and we don't (yet) maintain
// any other statistics about file access, we select files randomly to
// delete.
func (c *Cache) Prune() (n int, err error) {
	if c.cfg.Path == "" {
		return
	}

	type work struct {
		path string
		size int64
	}

	const elts = 4096
	toDelete := make([]work, 0, elts)
	var totalSize int64

	err = filepath.Walk(c.cfg.Path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		size := info.Size()
		totalSize += size

		if len(toDelete) < elts {
			toDelete = append(toDelete, work{path, size})
		} else {
			if i := mathrand.Intn(elts); i < len(toDelete) {
				toDelete[i] = work{path, size}
			}
		}
		return nil
	})
	if err != nil || len(toDelete) == 0 {
		return
	}

	// Pick a target size of 80% and convert the MB's to bytes.
	target := int64(c.cfg.MaxDisk) * 8 / 10 * 1024 * 1024
	if totalSize < target {
		return
	}

	mathrand.Shuffle(len(toDelete), func(i, j int) {
		toDelete[i], toDelete[j] = toDelete[j], toDelete[i]
	})

	for idx := range toDelete {
		if totalSize <= target {
			return
		}
		if err = os.Remove(toDelete[idx].path); err != nil {
			return
		}
		totalSize -= toDelete[idx].size
		n++
		c.logger.Tracef("purged %s", toDelete[idx].path)
	}

	next, err := c.Prune()
	n += next
	return
}

// keys converts a cache key into a cryptographic key to encrypt the
// contents of the file with, as well as a path to write the data to.
//
// Given a file on disk, it is not possible to recover the cryptographic
// key used to encrypt the file contents nor the original cache key.
func (c *Cache) keys(key string) (block cipher.Block, diskPath string, err error) {
	blockKey := sha256.Sum256([]byte(key))
	block, err = aes.NewCipher(blockKey[:])

	// Hash the block key again to produce a local filesystem path.
	diskKey := sha256.Sum256(blockKey[:])
	diskPath = pathify(c.cfg.Path, hex.EncodeToString(diskKey[:]))

	return
}

// load retrieves the contents of the key from disk.
func (c *Cache) load(key string) ([]byte, error) {
	if c.cfg.Path == "" {
		return nil, os.ErrNotExist
	}

	block, diskPath, err := c.keys(key)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(diskPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Read back the IV that we wrote at the start of the ciphertext.
	iv := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(f, iv); err != nil {
		return nil, err
	}

	// Ciphertext is written in feedback mode.
	r := &cipher.StreamReader{
		S: cipher.NewCFBDecrypter(block, iv),
		R: f,
	}

	return ioutil.ReadAll(r)
}

func (c *Cache) store(key string, data []byte) error {
	if c.cfg.Path == "" || c.cfg.MaxDisk == 0 {
		return nil
	}

	block, diskPath, err := c.keys(key)
	if err != nil {
		return err
	}

	// IV's don't need to be particularly secure.
	iv := make([]byte, block.BlockSize())
	if _, err := mathrand.Read(iv); err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(diskPath), 0700); err != nil {
		return err
	}

	// Write-and-rename pattern. Use exclusive so that if there's a
	// concurrent write to the same key, it'll be skipped.
	f, err := os.OpenFile(diskPath+".tmp", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}

	// Write the IV to the beginning of the file for decryption later.
	if _, err := io.Copy(f, bytes.NewReader(iv)); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return err
	}

	// Create a stream in feedback mode.
	out := &cipher.StreamWriter{
		S: cipher.NewCFBEncrypter(block, iv),
		W: f,
	}

	if _, err := io.Copy(out, bytes.NewReader(data)); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return err
	}

	// This will also close the underlying file.
	if err := out.Close(); err != nil {
		_ = os.Remove(f.Name())
		return err
	}

	err = os.Rename(f.Name(), diskPath)
	if err == nil {
		c.logger.Tracef("wrote key %s to %s", key, diskPath)
	}
	return err
}

type logWrapper struct {
	*log.Logger
}

func (w *logWrapper) Printf(fmt string, args ...interface{}) {
	w.Infof(fmt, args...)
}

// pathify converts an arbitrary string to a filesystem path.
func pathify(base, key string) string {
	d := 4
	for {
		if d >= len(key) {
			base = filepath.Join(base, key)
			break
		}
		base = filepath.Join(base, key[:d])
		key = key[d:]
		d *= 2
	}
	return base
}
