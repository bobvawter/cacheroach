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
	"strings"
	"time"

	"github.com/Mandala/go-log"
	"github.com/bobvawter/cacheroach/api/principal"
	"github.com/bobvawter/cacheroach/pkg/store/config"
	"github.com/bobvawter/cacheroach/pkg/store/util"
	"github.com/google/wire"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
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

	err := util.Retry(ctx, func(ctx context.Context) error {
		tx, err := s.DB.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)

		row := tx.QueryRow(ctx,
			"INSERT INTO principals ( "+
				"principal, email_domain, refresh_after, refresh_status, refresh_token, "+
				"claims, version"+
				") VALUES ($1, $2, $3, $4, $5, $6, 1) "+
				"ON CONFLICT (principal) "+
				"DO UPDATE SET (refresh_after, refresh_status, refresh_token, claims, version) = "+
				"("+
				" IF (excluded.refresh_after > 0::TIMESTAMPTZ, excluded.refresh_after, principals.refresh_after),"+
				" IF (excluded.refresh_status > 0, excluded.refresh_status, principals.refresh_status),"+
				" IF (length(excluded.refresh_token) > 0, excluded.refresh_token, principals.refresh_token),"+
				" IFNULL (excluded.claims, principals.claims),"+
				" principals.version + 1"+
				") RETURNING name, refresh_after, refresh_status, refresh_token, claims, version",
			p.ID, strings.ToLower(p.EmailDomain), p.RefreshAfter.AsTime(),
			p.RefreshStatus, p.RefreshToken, p.Claims)

		var pendingVersion int64
		var refreshAfter time.Time
		if err := row.Scan(
			&p.Label, &refreshAfter, &p.RefreshStatus, &p.RefreshToken,
			&p.Claims, &pendingVersion); err != nil {
			return err
		}
		p.RefreshAfter = timestamppb.New(refreshAfter)
		if pendingVersion != p.Version+1 {
			return util.ErrVersionSkew
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
			"SELECT principal, email_domain, name, claims, version "+
				"FROM principals")
		if err != nil {
			return err
		}
		defer rows.Close()

		sideEffect.Mark()
		for rows.Next() {
			p := &principal.Principal{ID: &principal.ID{}}

			if err := rows.Scan(p.ID, &p.EmailDomain, &p.Label, &p.Claims, &p.Version); err != nil {
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
func (s *Server) Load(ctx context.Context, req *principal.LoadRequest) (*principal.Principal, error) {
	var col string
	var val interface{}

	switch t := req.Kind.(type) {
	case *principal.LoadRequest_Email:
		col = "email"
		val = strings.ToLower(t.Email)
	case *principal.LoadRequest_ID:
		col = "principal"
		val = t.ID
	case *principal.LoadRequest_EmailDomain:
		col = "email_domain"
		val = strings.ToLower(t.EmailDomain)
	default:
		return nil, status.Error(codes.Unimplemented, "unknown kind")
	}
	ret := &principal.Principal{ID: &principal.ID{}}
	err := util.Retry(ctx, func(ctx context.Context) error {
		var refreshAfter time.Time
		row := s.DB.QueryRow(ctx,
			"SELECT principal, name, email_domain, refresh_after, refresh_status, refresh_token, "+
				"claims, version "+
				"FROM principals WHERE "+col+" = $1", val)
		err := row.Scan(ret.ID, &ret.Label, &ret.EmailDomain, &refreshAfter, &ret.RefreshStatus,
			&ret.RefreshToken, &ret.Claims, &ret.Version)
		ret.RefreshAfter = timestamppb.New(refreshAfter)
		return err
	})
	if err == pgx.ErrNoRows {
		return nil, status.Error(codes.NotFound, req.String())
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
		toSend, err := s.Load(ctx, &principal.LoadRequest{Kind: &principal.LoadRequest_ID{ID: id}})
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
