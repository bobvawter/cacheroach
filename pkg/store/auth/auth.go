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

package auth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/bobvawter/cacheroach/api/auth"
	"github.com/bobvawter/cacheroach/api/capabilities"
	"github.com/bobvawter/cacheroach/api/principal"
	"github.com/bobvawter/cacheroach/api/session"
	"github.com/bobvawter/cacheroach/api/token"
	"github.com/bobvawter/cacheroach/pkg/store/util"
	"github.com/google/wire"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	// Set is used by wire.
	Set = wire.NewSet(
		wire.Struct(new(Server), "*"),
		wire.Bind(new(auth.AuthServer), new(*Server)),
	)
)

// Server implements the auth.AuthServer API.
type Server struct {
	DB                    *pgxpool.Pool
	Principals            principal.PrincipalsServer
	Tokens                token.TokensServer
	auth.UnsafeAuthServer `wire:"-"`
}

var _ auth.AuthServer = (*Server)(nil)

// Login implements AuthServer.
func (s *Server) Login(ctx context.Context, req *auth.LoginRequest) (*auth.LoginResponse, error) {
	var id *principal.ID
	err := util.Retry(ctx, func(ctx context.Context) error {
		// Normalize handle
		u, err := url.Parse(req.Handle)
		if err != nil {
			return err
		}
		row := s.DB.QueryRow(ctx,
			"SELECT principals.principal, principals.pw_hash "+
				"FROM principals "+
				"INNER JOIN principal_handles "+
				"ON principals.principal = principal_handles.principal "+
				"WHERE principal_handles.urn = $1", u.String())

		id = &principal.ID{}
		var hash string
		if err := row.Scan(id, &hash); errors.Is(err, pgx.ErrNoRows) {
			id = nil
			return nil
		} else if err != nil {
			return err
		}

		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil {
			id = nil
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if id == nil {
		return nil, status.Error(codes.Unauthenticated, "")
	}

	template := &session.Session{
		Capabilities: capabilities.All(),
		ExpiresAt:    timestamppb.New(time.Now().AddDate(0, 1, 0).Round(time.Second)),
		PrincipalId:  id,
		Scope: &session.Scope{
			Kind: &session.Scope_OnPrincipal{OnPrincipal: id},
		},
	}
	if p, ok := peer.FromContext(ctx); ok {
		template.Note = fmt.Sprintf("login from %s", p.Addr)
	}
	resp, err := s.Tokens.Issue(ctx, &token.IssueRequest{Template: template})
	if err != nil {
		return nil, err
	}

	return &auth.LoginResponse{
		Session: resp.Issued,
		Token:   resp.Token,
	}, nil
}
