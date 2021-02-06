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

package principal

import (
	"context"
	"net/url"
	"time"

	"github.com/Mandala/go-log"
	"github.com/bobvawter/cacheroach/api/principal"
	"github.com/bobvawter/cacheroach/pkg/store/config"
	"github.com/bobvawter/cacheroach/pkg/store/util"
	"github.com/google/wire"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Set is used by wire.
var Set = wire.NewSet(
	wire.Struct(new(Server), "*"),
	wire.Bind(new(principal.PrincipalsServer), new(*Server)),
)

// Server implements the principal.PrincipalsServer API.
type Server struct {
	Config                           *config.Config
	DB                               *pgxpool.Pool
	Logger                           *log.Logger
	principal.UnsafePrincipalsServer `wire:"-"`
}

var _ principal.PrincipalsServer = (*Server)(nil)

// Ensure will store the given Principal in the database,
// updating Principal.Version on successful update.
func (s *Server) Ensure(
	ctx context.Context, req *principal.EnsureRequest,
) (*principal.EnsureResponse, error) {
	p := req.Principal

	if req.Delete {
		err := util.Retry(ctx, func(ctx context.Context) error {
			tag, err := s.DB.Exec(ctx,
				"DELETE FROM principals WHERE principal = $1 AND version = $2",
				p.ID, p.Version)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				return util.ErrVersionSkew
			}
			return nil
		})
		return &principal.EnsureResponse{}, err
	}

	if p.ID == nil {
		p.ID = principal.NewID()
	}
	if p.PasswordSet != "" {
		if err := p.SetPassword(p.PasswordSet); err != nil {
			return nil, err
		}
	}
	if p.Version == 0 && p.PasswordHash == "" {
		p.PasswordHash = " " // Not valid bcrypt.
	}
	err := util.Retry(ctx, func(ctx context.Context) error {
		tx, err := s.DB.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)

		row := tx.QueryRow(ctx,
			"INSERT INTO principals (principal, label, pw_hash, version) "+
				"VALUES ($1, $2, $3, 1) "+
				"ON CONFLICT (principal) "+
				"DO UPDATE SET (label, pw_hash, version) = "+
				"("+
				" IF (length(excluded.label)> 0, excluded.label, principals.label),"+
				" IF (length(excluded.pw_hash)> 0, excluded.pw_hash, principals.pw_hash),"+
				" principals.version + 1"+
				") RETURNING label, pw_hash, version", p.ID, p.Label, p.PasswordHash)

		var pendingVersion int64
		if err := row.Scan(&p.Label, &p.PasswordHash, &pendingVersion); err != nil {
			return err
		}
		if pendingVersion != p.Version+1 {
			return util.ErrVersionSkew
		}

		if _, err := tx.Exec(ctx,
			"DELETE FROM principal_handles WHERE principal = $1", p.ID); err != nil {
			return err
		}

		for i := range p.Handles {
			// Normalize the handles before inserting
			h, err := url.Parse(p.Handles[i])
			if err != nil {
				return errors.Wrapf(err, "could not parse handle %q", p.Handles[i])
			}
			if _, err := tx.Exec(ctx,
				"INSERT INTO principal_handles (urn, principal) VALUES ($1, $2)",
				h.String(), p.ID); err != nil {
				return err
			}
		}

		if err := tx.Commit(ctx); err != nil {
			return err
		}
		p.Version = pendingVersion
		return nil
	})
	return &principal.EnsureResponse{Principal: p}, err
}

// List implements principal.PrincipalsServer.
func (s *Server) List(_ *emptypb.Empty, out principal.Principals_ListServer) error {
	return util.RetryLoop(out.Context(), func(ctx context.Context, sideEffect *util.Marker) error {
		tx, err := s.DB.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)

		rows, err := tx.Query(ctx,
			"WITH "+
				"h AS (SELECT principal, array_agg(urn) AS urns FROM principal_handles GROUP BY principal), "+
				"p AS (SELECT principal, label, version FROM principals) "+
				"SELECT p.*, h.urns FROM p JOIN h ON p.principal = h.principal")
		if err != nil {
			return err
		}
		defer rows.Close()

		sideEffect.Mark()
		for rows.Next() {
			p := &principal.Principal{ID: &principal.ID{}}

			if err := rows.Scan(p.ID, &p.Label, &p.Version, &p.Handles); err != nil {
				return err
			}

			if err := out.Send(p); err != nil {
				return err
			}
		}
		return nil
	})
}

// Load implements principal.PrincipalsServer.
func (s *Server) Load(ctx context.Context, id *principal.ID) (*principal.Principal, error) {
	ret := &principal.Principal{ID: id}
	err := util.Retry(ctx, func(ctx context.Context) error {
		var eg errgroup.Group
		eg.Go(func() error {
			row := s.DB.QueryRow(ctx,
				"SELECT label, pw_hash, version FROM principals WHERE principal = $1", id)
			return row.Scan(&ret.Label, &ret.PasswordHash, &ret.Version)
		})
		eg.Go(func() error {
			rows, err := s.DB.Query(ctx,
				"SELECT urn FROM principal_handles WHERE principal = $1", id)
			if err != nil {
				return err
			}
			defer rows.Close()

			var handles []string
			for rows.Next() {
				s := ""
				if err := rows.Scan(&s); err != nil {
					return err
				}
				u, err := url.Parse(s)
				if err != nil {
					return err
				}
				handles = append(handles, u.String())
			}
			ret.Handles = handles
			return nil
		})
		return eg.Wait()
	})
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return ret, err
}

// Watch implements principal.PrincipalsServer.
func (s *Server) Watch(req *principal.WatchRequest, out principal.Principals_WatchServer) error {
	return s.watch(out.Context(), req.Principal, req.Duration.AsDuration(), out.Send)
}

func (s *Server) watch(
	ctx context.Context,
	id *principal.ID,
	duration time.Duration,
	out func(principal *principal.Principal) error,
) error {
	ticker := time.NewTicker(duration)
	defer ticker.Stop()

	lastVersion := int64(0)
	for {
		toSend, err := s.Load(ctx, id)
		if err != nil {
			return err
		}
		if toSend.Version > lastVersion {
			if err := out(toSend); err != nil {
				return err
			}
			lastVersion = toSend.Version
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
