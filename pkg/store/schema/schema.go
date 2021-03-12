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

	"github.com/Mandala/go-log"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pkg/errors"
)

// EnsureSchema injects the store's schema into the database.
func EnsureSchema(ctx context.Context, db *pgxpool.Pool, logger *log.Logger) error {
	logger.Info("ensuring schema")
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	for idx, q := range schema {
		if _, err := tx.Exec(ctx, q); err != nil {
			return errors.Wrapf(err, "schema %d", idx)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	logger.Info("schema setup complete")

	return nil
}

// TruncateSchema truncates all tables in the schema.
func TruncateSchema(ctx context.Context, db *pgxpool.Pool, logger *log.Logger) error {
	// Use cascade to do full cleanup.
	names := []string{
		"chunks",
		"ropes",
		"tenants",
		"principals",
		"vhosts",
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	for _, name := range names {
		if _, err := tx.Exec(ctx, "TRUNCATE "+name+" CASCADE"); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	logger.Info("truncated all tables")
	return nil
}

var schema = []string{`
CREATE TABLE IF NOT EXISTS tenants (
  tenant UUID NOT NULL PRIMARY KEY,
  label STRING NOT NULL CHECK (length(label) > 0),
  version INT8 NOT NULL CHECK (version > 0)
)
`, `
CREATE TABLE IF NOT EXISTS chunks (
  tenant UUID NOT NULL REFERENCES tenants(tenant) ON DELETE CASCADE,
  -- Content hash of the chunk.
  chunk BYTES NOT NULL CHECK (length(chunk) > 0),
  data BYTES NOT NULL CHECK (length(data) > 0),
  PRIMARY KEY (tenant, chunk)
)`, `
CREATE TABLE IF NOT EXISTS ropes (
  tenant UUID NOT NULL REFERENCES tenants(tenant) ON DELETE CASCADE,
  -- Allow accumulation of partially-constructed ropes via stable key.
  rope UUID NOT NULL,
  -- This is the hash of the entire file, which is updated once the entire file has been read.
  hash BYTES CHECK (hash IS NULL OR length(hash) > 0),
  -- Offset of the chunk within the file, to allow for partial reads.
  off INT8 NOT NULL CHECK (off >= 0),
  -- Content hash of the chunk.
  chunk BYTES NOT NULL,
  -- Amount of data to read from the chunk, could be less than the underlying chunk length.
  chunk_length INT NOT NULL CHECK (chunk_length >= 0),

  PRIMARY KEY (tenant, rope, off),
  FOREIGN KEY (tenant, chunk) REFERENCES chunks,
  -- Create a partial index once the entire file contents have been read.
  UNIQUE INDEX ordered_chunks (tenant, hash, off) STORING (chunk, chunk_length) WHERE hash IS NOT NULL
)
`, `
CREATE TABLE IF NOT EXISTS files (
  tenant UUID NOT NULL REFERENCES tenants (tenant) ON DELETE CASCADE,
  path STRING NOT NULL CHECK (length(path) > 0),
  version INT8 NOT NULL CHECK (version > 0),

  hash BYTES NOT NULL CHECK (length(hash) > 0),
  ctime TIMESTAMPTZ NOT NULL,
  dtime TIMESTAMPTZ,
  mtime TIMESTAMPTZ NOT NULL,
  meta JSONB,

  PRIMARY KEY (tenant, path, version),
  -- Used for purge jobs.
  INDEX deleted_files (dtime) WHERE dtime IS NOT NULL
)
`, `
CREATE TABLE IF NOT EXISTS principals (
  region STRING NOT NULL DEFAULT IFNULL(crdb_internal.locality_value('region'), 'global') CHECK (length(region)>0),
  principal UUID NOT NULL UNIQUE,

  -- A principal may be created to delegate access to all users within a given email domain.
  email_domain STRING NOT NULL DEFAULT '',

  refresh_after TIMESTAMPTZ NOT NULL DEFAULT 0::TIMESTAMPTZ, -- The time at which the claims must be revalidated
  refresh_status INT8 NOT NULL DEFAULT 0, -- Refresh state enum
  refresh_token STRING NOT NULL DEFAULT '', -- OAuth2 refresh token to achieve revalidation

  -- We're going to store the entire OIDC claim block for future
  -- reference and extract the well-known fields that we care about.
  claims JSONB,
  email STRING NOT NULL AS (lower(IFNULL(claims->>'email', ''))) STORED,
  name STRING NOT NULL AS (IFNULL(claims->>'name', principal::string)) STORED,
  
  version INT8 NOT NULL CHECK (version > 0),
  PRIMARY KEY (region, principal),
  UNIQUE INDEX (email_domain) WHERE email_domain != '',
  UNIQUE INDEX (email) WHERE email != ''
)
`, `
CREATE TABLE IF NOT EXISTS sessions (
  -- We don't expect sessions to move between regions
  region STRING NOT NULL DEFAULT IFNULL(crdb_internal.locality_value('region'), 'global') CHECK (length(region)>0),
  session UUID NOT NULL UNIQUE,
  principal UUID NOT NULL REFERENCES principals (principal) ON DELETE CASCADE,
  tenant UUID REFERENCES tenants (tenant) ON DELETE CASCADE, -- null for principal-only accesses
  path STRING, -- A specific path or prefix wildcard
  super BOOL NOT NULL DEFAULT false, -- A super-token session

  capabilities INT8 NOT NULL, -- a bit-mask field
  expires_at TIMESTAMPTZ NOT NULL,
  issued_at TIMESTAMPTZ NOT NULL,
  jwt_claims JSONB,
  note STRING,
  name STRING, -- Allows the session to have a well-known name for ease of lookup 

  PRIMARY KEY (region, session),
  INDEX (principal, tenant, path),
  UNIQUE INDEX (principal, name) WHERE name != ''
)
`, `
CREATE TABLE IF NOT EXISTS uploads (
  region STRING NOT NULL DEFAULT IFNULL(crdb_internal.locality_value('region'), 'global') CHECK (length(region)>0),
  upload UUID NOT NULL UNIQUE, -- This will also be the rope ID.

  path STRING NOT NULL CHECK (length(path) > 0),
  principal UUID NOT NULL REFERENCES principals (principal) ON DELETE CASCADE,
  session UUID NOT NULL REFERENCES sessions (session) ON DELETE CASCADE,
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  tenant UUID NOT NULL REFERENCES tenants (tenant) ON DELETE CASCADE,

  PRIMARY KEY (region, upload),
  INDEX (started_at)
)
`, `
CREATE TABLE IF NOT EXISTS vhosts (
  host STRING PRIMARY KEY CHECK (length(host) > 0),
  tenant UUID NOT NULL REFERENCES tenants (tenant) ON DELETE CASCADE
)
`,
}
