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

// Package tenant provides access to tenants.
package tenant

//go:generate protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative ./tenant.proto

import (
	"context"

	"github.com/Mandala/go-log"
	"github.com/bobvawter/cacheroach/api/tenant"
	"github.com/bobvawter/cacheroach/pkg/store/util"
	"github.com/google/wire"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Set is used by wire.
var Set = wire.NewSet(
	wire.Struct(new(Server), "*"),
	wire.Bind(new(tenant.TenantsServer), new(*Server)),
)

// Server implements the tenant.TenantsServer API.
type Server struct {
	tenant.UnsafeTenantsServer `wire:"-"`
	DB                         *pgxpool.Pool
	Logger                     *log.Logger
}

var _ tenant.TenantsServer = (*Server)(nil)

// Ensure implements TenantsServer.
func (s *Server) Ensure(ctx context.Context, req *tenant.EnsureRequest) (*tenant.EnsureResponse, error) {
	var err error
	if req.Delete {
		err = util.Retry(ctx, func(ctx context.Context) error {
			tag, err := s.DB.Exec(ctx,
				"DELETE FROM tenants WHERE tenant = $1 AND version = $2",
				req.Tenant.ID, req.Tenant.Version)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				return util.ErrVersionSkew
			}
			return nil
		})
	} else {
		err = util.Retry(ctx, func(ctx context.Context) error {
			tx, err := s.DB.Begin(ctx)
			if err != nil {
				return err
			}
			defer tx.Rollback(ctx)

			row := tx.QueryRow(ctx,
				"INSERT INTO tenants (tenant, label, version) "+
					"VALUES ($1, $2, 1) "+
					"ON CONFLICT (tenant) "+
					"DO UPDATE SET (label, version) = ("+
					" IF (length(excluded.label) > 0, excluded.label, tenants.label),"+
					" tenants.version + 1"+
					") RETURNING label, version", req.Tenant.ID, req.Tenant.Label)

			var pendingVersion int64
			if err := row.Scan(&req.Tenant.Label, &pendingVersion); err != nil {
				return err
			}
			if pendingVersion != req.Tenant.Version+1 {
				return util.ErrVersionSkew
			}

			if err := tx.Commit(ctx); err != nil {
				return err
			}
			req.Tenant.Version = pendingVersion
			s.Logger.Debugf("updated tenant %q to version %d", req.Tenant.ID, pendingVersion)
			return nil
		})
	}
	if err != nil {
		return nil, err
	}
	return &tenant.EnsureResponse{Tenant: req.Tenant}, nil
}

// Get implements TenantsServer.
func (s *Server) Get(ctx context.Context, req *tenant.GetRequest) (*tenant.GetResponse, error) {
	ret := &tenant.Tenant{ID: req.ID}
	err := util.Retry(ctx, func(ctx context.Context) error {
		row := s.DB.QueryRow(ctx, "SELECT label, version FROM tenants WHERE tenant = $1", req.ID)
		err := row.Scan(&ret.Label, &ret.Version)
		if errors.Is(err, pgx.ErrNoRows) {
			return status.Error(codes.NotFound, "")
		}
		return err
	})
	return &tenant.GetResponse{Tenant: ret}, err
}

// List implements TenantsServer.
func (s *Server) List(_ *emptypb.Empty, out tenant.Tenants_ListServer) error {
	return util.RetryLoop(out.Context(), func(ctx context.Context, sideEffect *util.Marker) error {
		rows, err := s.DB.Query(ctx, "SELECT tenant, label, version FROM tenants")
		if err != nil {
			return err
		}
		defer rows.Close()

		sideEffect.Mark()
		for rows.Next() {
			t := &tenant.Tenant{ID: &tenant.ID{}}
			if err := rows.Scan(t.ID, &t.Label, &t.Version); err != nil {
				return err
			}
			if err := out.Send(t); err != nil {
				return err
			}
		}
		return nil
	})
}
