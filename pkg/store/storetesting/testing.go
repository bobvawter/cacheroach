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

// Package storetesting contains support code for tests.
package storetesting

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/Mandala/go-log"
	"github.com/bobvawter/cacheroach/pkg/cache"
	"github.com/bobvawter/cacheroach/pkg/metrics"
	"github.com/bobvawter/cacheroach/pkg/store/config"
	"github.com/bobvawter/cacheroach/pkg/store/schema"
	"github.com/google/wire"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
)

// Set is used by wire.
var (
	Logger = log.New(os.Stdout).WithDebug().WithoutColor()
	Set    = wire.NewSet(
		cache.Set,
		metrics.Set,
		ProvideCacheConfig,
		ProvideStoreConfig,
		ProvideDB,
		wire.Value(Logger),
	)
)

// ProvideCacheConfig returns a configuration with sane defaults.
func ProvideCacheConfig() (*cache.Config, func(), error) {
	d, err := os.MkdirTemp("", "cacheroach-*")
	if err != nil {
		return nil, nil, err
	}

	cfg := &cache.Config{
		MaxMem:  128,
		MaxDisk: 128,
		Path:    d,
	}

	cleanup := func() {
		_ = os.RemoveAll(d)
	}

	return cfg, cleanup, nil
}

// ProvideStoreConfig returns a configuration with sane defaults.
func ProvideStoreConfig() (*config.Config, error) {
	conn := os.Getenv("TEST_CONNECT_STRING")
	if conn == "" {
		conn = "postgresql://root@localhost:26257/testing"
	}
	conn = fmt.Sprintf("%s_%d", conn, time.Now().UnixNano())

	return &config.Config{
		ChunkConcurrency:         16,
		ChunkSize:                512 * 1024,
		ConnectString:            conn,
		PurgeLimit:               10000,
		ReadAmplificationBackoff: 10,
		SigningKeys:              [][]byte{[]byte("SoupOrSecret")},
		UploadTimeout:            time.Hour,
	}, nil
}

// ProvideDB provides a database connection. It will automatically
// create and tear down a temporary database. This connection also
// disallows full-table scans.
func ProvideDB(
	ctx context.Context,
	config *config.Config,
	logger *log.Logger,
) (*pgxpool.Pool, func(), error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cfg, err := pgxpool.ParseConfig(config.ConnectString)
	if err != nil {
		return nil, nil, err
	}
	if cfg.MaxConns < int32(config.ChunkConcurrency) {
		cfg.MaxConns = int32(config.ChunkConcurrency)
		logger.Infof("raising pool_max_conns to %d", config.ChunkConcurrency)
	}
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET application_name = $1", "cacheroach_testing")
		return err
	}

	conn, err := pgxpool.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}
	logger.Debugf("db config: %s", conn.Config().ConnString())
	dbName := conn.Config().ConnConfig.Database

	if _, err := conn.Exec(ctx,
		fmt.Sprintf("CREATE DATABASE %s", dbName)); err != nil {
		return nil, nil, err
	}

	if err := schema.EnsureSchema(ctx, conn, logger); err != nil {
		return nil, nil, err
	}

	cleanup := func() {
		if os.Getenv("TEST_RETAIN_DATABASE") == "" {
			if _, err := conn.Exec(context.Background(), "DROP DATABASE "+dbName); err != nil {
				logger.Warnf("could not drop test database: %v", err)
			} else {
				logger.Infof("dropped database %q", conn.Config().ConnConfig.Database)
			}
		}
		conn.Close()
	}

	return conn, cleanup, nil
}
