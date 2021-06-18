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

// Package schema contains the SQL database schema.
package schema

import (
	"context"
	_ "embed"
	"strings"

	"github.com/Mandala/go-log"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pkg/errors"
)

//go:embed schema.sql
var schema string

// EnsureSchema injects the store's schema into the database.
func EnsureSchema(ctx context.Context, db *pgxpool.Pool, logger *log.Logger) error {
	logger.Info("ensuring schema")
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	parts := strings.Split(schema, ";")

	for idx, q := range parts {
		if _, err := tx.Exec(ctx, q); err != nil {
			return errors.Wrapf(err, "schema %d", idx)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if _, err := db.Exec(ctx, "SET CLUSTER SETTING kv.rangefeed.enabled = true"); err != nil {
		return err
	}
	logger.Info("schema setup complete")

	return nil
}
