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

// Package vhost allows virtual-host mappings to be managed.
package vhost

import (
	"context"

	"github.com/Mandala/go-log"
	"github.com/bobvawter/cacheroach/api/tenant"
	"github.com/bobvawter/cacheroach/api/vhost"
	"github.com/bobvawter/cacheroach/pkg/store/util"
	"github.com/google/wire"
	"github.com/jackc/pgx/v4/pgxpool"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Set is used by wire.
var Set = wire.NewSet(
	wire.Struct(new(Server), "*"),
	wire.Bind(new(vhost.VHostsServer), new(*Server)),
)

// Server allows virtual host mappings to be configured.
type Server struct {
	DB                       *pgxpool.Pool
	Logger                   *log.Logger
	vhost.UnsafeVHostsServer `wire:"-"`
}

var _ vhost.UnsafeVHostsServer = (*Server)(nil)

// Ensure implements vhost.VHostsServer.
func (s *Server) Ensure(ctx context.Context, req *vhost.EnsureRequest) (*emptypb.Empty, error) {
	var err error
	if req.Delete {
		err = util.Retry(ctx, func(ctx context.Context) error {
			_, err := s.DB.Exec(ctx, "DELETE FROM vhosts WHERE host = $1 AND tenant = $2", req.Vhost.Vhost, req.Vhost.TenantId)
			return err
		})
	} else {
		err = util.Retry(ctx, func(ctx context.Context) error {
			_, err := s.DB.Exec(ctx, "UPSERT INTO vhosts (host, tenant) VALUES ($1, $2)", req.Vhost.Vhost, req.Vhost.TenantId)
			return err
		})
	}
	return &emptypb.Empty{}, err
}

// List implements vhost.VHostsServer.
func (s *Server) List(_ *emptypb.Empty, out vhost.VHosts_ListServer) error {
	return util.RetryLoop(out.Context(), func(ctx context.Context, sideEffect *util.Marker) error {
		rows, err := s.DB.Query(ctx, "SELECT host, tenant FROM vhosts")
		if err != nil {
			return err
		}
		defer rows.Close()
		sideEffect.Mark()
		for rows.Next() {
			h := &vhost.VHost{
				TenantId: &tenant.ID{},
			}
			if err := rows.Scan(&h.Vhost, h.TenantId); err != nil {
				return err
			}
			if err := out.Send(h); err != nil {
				return err
			}
		}
		return nil
	})
}
