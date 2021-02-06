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

// Package storeproduction provide production-ready configuration.
package storeproduction

import (
	"context"

	"github.com/Mandala/go-log"
	"github.com/bobvawter/cacheroach/pkg/cache"
	"github.com/bobvawter/cacheroach/pkg/store/config"
	"github.com/google/wire"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
)

// Set is used by wire.
var Set = wire.NewSet(
	ProvideDB,
	cache.Set,
)

// ProvideDB creates a database connection pool.
func ProvideDB(
	ctx context.Context,
	cfg *config.Config,
	logger *log.Logger,
) (*pgxpool.Pool, error) {
	pgCfg, err := pgxpool.ParseConfig(cfg.ConnectString)
	if err != nil {
		return nil, nil
	}
	if pgCfg.MaxConns < int32(cfg.ChunkConcurrency) {
		pgCfg.MaxConns = int32(cfg.ChunkConcurrency)
		logger.Infof("raising pool_max_conns to %d", cfg.ChunkConcurrency)
	}
	pgCfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET application_name = $1", "cacheroach")
		return err
	}

	return pgxpool.ConnectConfig(ctx, pgCfg)
}
