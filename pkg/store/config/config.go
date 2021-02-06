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

// Package config defines a variety of injectable configuration types
// that may be shared across the store packages.
package config

import (
	"time"

	"context"
	"encoding/base64"
	"io/ioutil"

	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/pflag"
)

// Config contains the various pieces of data used by the store code.
type Config struct {
	// The AS OF SYSTEM TIME offset for read-only queries.
	AOST time.Duration
	// Used to limit concurrent DB operations at the chunk level.
	ChunkConcurrency int
	// The ideal size of a chunk.
	ChunkSize int
	// A database connection string.
	ConnectString string
	// The amount of time that a deleted file, dangling rope, or
	// dangling chunk should be retained.
	PurgeDuration time.Duration
	// The deletion batch size to use when purging old data.
	PurgeLimit int
	// Keys for validating HMAC-based JWT tokens. The zeroth entry will
	// be used to sign new tokens.
	SigningKeys [][]byte
	// The period of time for which an upload may be pending.
	UploadTimeout time.Duration

	signingKeys []string
}

// Bind adds to the given flag set and
func (c *Config) Bind(flags *pflag.FlagSet) {
	flags.DurationVar(&c.AOST, "aost", -5*time.Second,
		"the AS OF SYSTEM TIME for immutable queries")
	flags.IntVar(&c.ChunkConcurrency, "chunkConcurrency", 16,
		"the number of concurrent chunk operations")
	flags.IntVar(&c.ChunkSize, "chunkSize", 512*1024,
		"the desired size for newly-stored chunks")
	flags.StringVar(&c.ConnectString, "connect",
		"postgres://root@localhost:26257/cacheroach",
		"the database connection string")
	flags.DurationVar(&c.PurgeDuration, "purgeDuration", 7*24*time.Hour,
		"the length of time for which deleted data should be retained; set to 0 to disable")
	flags.IntVar(&c.PurgeLimit, "purgeLimit", 1000,
		"the deletion batch size to use when purging old data; set to 0 to disable")
	flags.StringSliceVar(&c.signingKeys, "signingKey", nil,
		"a base64-encoded HMAC signing key or @/path/to/base64.key")
	flags.DurationVar(&c.UploadTimeout, "uploadTimeout", time.Hour,
		"the timeout for any multi-part upload process")
}

// Configure is used to cooperate with the start CLI package.
func (c *Config) Configure(_ context.Context) error {
	for _, elt := range c.signingKeys {
		if elt == "" {
			return errors.New("empty --signingKey flag")
		}
		r := base64.NewDecoder(base64.StdEncoding, strings.NewReader(elt))
		data, err := ioutil.ReadAll(r)
		if err != nil {
			return err
		}

		c.SigningKeys = append(c.SigningKeys, data)
	}
	c.signingKeys = nil
	return nil
}
