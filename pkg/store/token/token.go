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

package token

import (
	"context"
	"time"

	"github.com/Mandala/go-log"
	"github.com/bobvawter/cacheroach/api/capabilities"
	"github.com/bobvawter/cacheroach/api/principal"
	"github.com/bobvawter/cacheroach/api/session"
	"github.com/bobvawter/cacheroach/api/tenant"
	"github.com/bobvawter/cacheroach/api/token"
	"github.com/bobvawter/cacheroach/pkg/claims"
	"github.com/bobvawter/cacheroach/pkg/store/config"
	"github.com/bobvawter/cacheroach/pkg/store/util"
	"github.com/dgrijalva/jwt-go/v4"
	"github.com/google/wire"
	lru "github.com/hashicorp/golang-lru"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Set is used by wire.
var Set = wire.NewSet(
	ProvideServer,
	wire.Bind(new(token.TokensServer), new(*Server)),
)

type cached struct {
	expires  time.Time
	sessions []*session.Session
}

// Server allows session tokens to be managed.
type Server struct {
	config                   *config.Config
	db                       *pgxpool.Pool
	logger                   *log.Logger
	token.UnsafeTokensServer `wire:"-"`

	// A map<uuid.UUID>*cached The keys are session or principal IDs.
	cache *lru.TwoQueueCache
}

var _ token.TokensServer = (*Server)(nil)

// ProvideServer is called by wire.
func ProvideServer(
	cfg *config.Config,
	db *pgxpool.Pool,
	logger *log.Logger,
) (*Server, error) {
	if len(cfg.SigningKeys) == 0 {
		return nil, errors.New("HMAC signing keys must be specified")
	}
	validations, err := lru.New2Q(1024 * 1024)
	if err != nil {
		return nil, err
	}
	s := &Server{config: cfg, db: db, logger: logger, cache: validations}
	return s, nil
}

// Current implements TokensServer.
func (s *Server) Current(ctx context.Context, _ *emptypb.Empty) (*session.Session, error) {
	sn := session.FromContext(ctx)
	if sn == nil {
		sn = &session.Session{}
	}
	return sn, nil
}

// Find implements TokensServer.
func (s *Server) Find(scope *session.Scope, server token.Tokens_FindServer) error {
	ctx := server.Context()
	sn := session.FromContext(ctx)
	cacheKey := sn.PrincipalId.AsUUID()
	if found, ok := s.cache.Get(cacheKey); ok {
		cached := found.(*cached)
		if cached.expires.After(time.Now()) {
			for i := range cached.sessions {
				server.Send(cached.sessions[i])
			}
			return nil
		}
		s.cache.Remove(cacheKey)
	}
	return util.RetryLoop(ctx, func(ctx context.Context, sideEffect *util.Marker) error {
		rows, err := s.db.Query(ctx, `
WITH 
  dom AS (SELECT substring(email, '@(.*)$') as email_domain FROM principals WHERE principal = $1 AND email != ''),
  prns AS (SELECT principal FROM principals JOIN dom USING (email_domain) UNION SELECT $1::UUID)
SELECT session, tenant, path, capabilities, expires_at, note, name, super
FROM sessions
JOIN prns USING (principal)
WHERE expires_at > now()
`, sn.PrincipalId)
		if err != nil {
			return err
		}
		defer rows.Close()

		const maxCachedSession = 16
		cacheOK := true
		var cache []*session.Session

		sideEffect.Mark()
		for rows.Next() {
			var caps capabilities.Capabilities
			var expires time.Time
			var note, path, name string
			var id session.ID
			var tnt tenant.ID
			var super bool
			if err := rows.Scan(&id, &tnt, &path, &caps, &expires, &note, &name, &super); err != nil {
				return err
			}
			s := &session.Session{
				Capabilities: &caps,
				ExpiresAt:    timestamppb.New(expires),
				ID:           &id,
				Name:         name,
				Note:         note,
				Scope:        &session.Scope{},
				PrincipalId:  sn.PrincipalId,
			}
			if super {
				s.Scope.Kind = &session.Scope_SuperToken{SuperToken: true}
			} else if tnt.Zero() {
				s.Scope.Kind = &session.Scope_OnPrincipal{OnPrincipal: sn.PrincipalId}
			} else {
				s.Scope.Kind = &session.Scope_OnLocation{OnLocation: &session.Location{
					TenantId: &tnt,
					Path:     path,
				}}
			}

			if !scope.IsSubsetOf(s.Scope) {
				continue
			}

			if err := server.Send(s); err != nil {
				return err
			}

			if cacheOK {
				if len(cache) < maxCachedSession {
					cache = append(cache, s)
				} else {
					cacheOK = false
					cache = nil
				}
			}
		}

		if cacheOK {
			s.cache.Add(cacheKey, &cached{
				expires:  time.Now().Add(time.Minute),
				sessions: cache,
			})
		}

		return nil
	})
}

// Invalidate implements TokensServer.
func (s *Server) Invalidate(ctx context.Context, req *token.InvalidateRequest) (*emptypb.Empty, error) {

	var pID *principal.ID
	var sID *session.ID
	switch t := req.Kind.(type) {
	case *token.InvalidateRequest_Current:
		sn := session.FromContext(ctx)
		pID = sn.GetPrincipalId()
		sID = sn.GetID()

	case *token.InvalidateRequest_ID:
		var prn principal.ID
		var tnt tenant.ID

		// Look up the target to determine if we have delegate powers.
		row := s.db.QueryRow(ctx, "SELECT principal, tenant FROM sessions WHERE session = $1", t.ID)

		if err := row.Scan(&prn, &tnt); err == pgx.ErrNoRows {
			return &emptypb.Empty{}, nil
		}
		pID = &prn
		sn := session.FromContext(ctx)
		ok := false
		if !prn.Zero() {
			ok = (&session.Session{
				Scope: &session.Scope{Kind: &session.Scope_OnPrincipal{
					OnPrincipal: &prn}},
				Capabilities: &capabilities.Capabilities{Delegate: true},
			}).IsSubsetOf(sn)
		}
		if !ok && !tnt.Zero() {
			ok = (&session.Session{
				Scope: &session.Scope{Kind: &session.Scope_OnLocation{
					OnLocation: &session.Location{
						TenantId: &tnt,
						Path:     "/*",
					}}},
				Capabilities: &capabilities.Capabilities{Delegate: true},
			}).IsSubsetOf(sn)
		}

		if !ok {
			return nil, status.Error(codes.PermissionDenied, "")
		}
		sID = t.ID

	default:
		return nil, status.Error(codes.InvalidArgument, "")
	}

	if sID == nil {
		return nil, status.Error(codes.InvalidArgument, "")
	}

	s.cache.Remove(pID.AsUUID())
	s.cache.Remove(sID.AsUUID())

	return &emptypb.Empty{}, util.Retry(ctx, func(ctx context.Context) error {
		_, err := s.db.Exec(ctx,
			"UPDATE sessions SET expires_at = now() WHERE session = $1",
			sID)
		return err
	})
}

// Issue implements TokensServer.
func (s *Server) Issue(ctx context.Context, req *token.IssueRequest) (*token.IssueResponse, error) {
	sn := req.Template
	sn.ID = session.NewID()
	now := time.Now()
	cl, tkn, err := claims.Sign(now, sn, s.config.SigningKeys[0])
	if err != nil {
		return nil, err
	}
	ret := &token.IssueResponse{
		Issued: sn,
		Token:  tkn,
	}

	return ret, util.Retry(ctx, func(ctx context.Context) error {
		_, err := s.db.Exec(ctx,
			"INSERT INTO sessions (session, principal, tenant, path, "+
				"capabilities, expires_at, issued_at, jwt_claims, note, name, super) "+
				"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
			sn.ID, sn.PrincipalId,
			sn.GetScope().GetOnLocation().GetTenantId(), // Possibly null.
			sn.GetScope().GetOnLocation().GetPath(),     // Possibly null.
			sn.Capabilities, sn.ExpiresAt.AsTime(), now, cl, sn.Note, sn.Name,
			sn.GetScope().GetSuperToken())
		return err
	})
}

// Load implements TokensServer.
func (s *Server) Load(ctx context.Context, req *token.LoadRequest) (*session.Session, error) {
	var row pgx.Row
	switch t := req.Kind.(type) {
	case *token.LoadRequest_ID:
		row = s.db.QueryRow(ctx,
			"SELECT session, principal, tenant, path, capabilities, expires_at, note, name, super "+
				"FROM sessions "+
				"WHERE session = $1", t.ID)
	case *token.LoadRequest_Name:
		sn := session.FromContext(ctx)
		row = s.db.QueryRow(ctx,
			"SELECT session, principal, tenant, path, capabilities, expires_at, note, name, super "+
				"FROM sessions "+
				"WHERE principal = $1 AND name = $2", sn.GetPrincipalId(), t.Name)
	default:
		return nil, status.Error(codes.InvalidArgument, "kind")
	}

	var caps capabilities.Capabilities
	var expires time.Time
	var id session.ID
	var note, path, name string
	var prn principal.ID
	var tnt tenant.ID
	var super bool
	if err := row.Scan(
		&id, &prn, &tnt, &path, &caps, &expires, &note, &name, &super,
	); errors.Is(err, pgx.ErrNoRows) {
		return nil, status.Error(codes.NotFound, "")
	} else if err != nil {
		return nil, err
	}
	sn := &session.Session{
		Capabilities: &caps,
		ExpiresAt:    timestamppb.New(expires),
		ID:           &id,
		Name:         name,
		Note:         note,
		PrincipalId:  &prn,
		Scope:        &session.Scope{},
	}
	if super {
		sn.Scope.Kind = &session.Scope_SuperToken{SuperToken: true}
	} else if tnt.Zero() {
		sn.Scope.Kind = &session.Scope_OnPrincipal{OnPrincipal: sn.PrincipalId}
	} else {
		sn.Scope.Kind = &session.Scope_OnLocation{OnLocation: &session.Location{
			TenantId: &tnt,
			Path:     path,
		}}
	}
	return sn, nil
}

// Refresh implements TokensServer.
func (s *Server) Refresh(ctx context.Context, _ *emptypb.Empty) (*token.IssueResponse, error) {
	sn := session.FromContext(ctx)
	originalID := sn.ID
	sn.ID = session.NewID()
	now := time.Now()
	sn.ExpiresAt = timestamppb.New(now.AddDate(0, 0, 1))
	cl, tkn, err := claims.Sign(now, sn, s.config.SigningKeys[0])
	if err != nil {
		return nil, err
	}

	resp := &token.IssueResponse{
		Issued: sn,
		Token:  tkn,
	}

	return resp, util.Retry(ctx, func(ctx context.Context) error {
		tx, err := s.db.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)

		tag, err := tx.Exec(ctx,
			"UPDATE sessions "+
				"SET expires_at = now(), "+
				"note = concat(note, $2) "+
				"WHERE (session = $1)",
			originalID, " replaced by "+sn.ID.AsUUID().String())
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return status.Error(codes.Unauthenticated, "")
		}

		if err := insert(ctx, tx.Exec, now, cl, sn); err != nil {
			return err
		}

		return tx.Commit(ctx)
	})
}

// Validate implements TokensServer.
func (s *Server) Validate(ctx context.Context, t *token.Token) (*session.Session, error) {
	var err error
	var ret *session.Session

	for i := range s.config.SigningKeys {
		_, ret, err = claims.Validate(t.Jwt, s.config.SigningKeys[i])
		if err == nil {
			break
		}
		if errors.Is(err, jwt.ErrSignatureInvalid) {
			continue
		}
		return nil, err
	}
	if ret == nil {
		return nil, nil
	}

	// Ephemeral session; we'll see this with signed-requests.
	if ret.ID.Zero() {
		return ret, nil
	}

	if found, ok := s.cache.Get(ret.ID.AsUUID()); ok {
		v := found.(*cached)
		if v.expires.After(time.Now()) {
			return proto.Clone(v.sessions[0]).(*session.Session), nil
		}
		s.cache.Remove(ret.ID.AsUUID())
	}

	if err := util.Retry(ctx, func(ctx context.Context) error {
		var count int
		err := s.db.QueryRow(ctx,
			"SELECT count(*) "+
				"FROM sessions "+
				"WHERE session = $1 AND expires_at > now()",
			ret.ID.AsUUID().String(),
		).Scan(&count)
		if count == 0 {
			ret = nil
		}
		return err
	}); err != nil {
		return nil, err
	}

	if ret != nil {
		s.cache.Add(ret.ID.AsUUID(), &cached{
			expires:  time.Now().Add(time.Minute),
			sessions: []*session.Session{ret},
		})
	}

	return ret, nil
}

func insert(ctx context.Context,
	exec func(context.Context, string, ...interface{}) (pgconn.CommandTag, error),
	now time.Time, cl *claims.Claims, sn *session.Session) error {
	return util.Retry(ctx, func(ctx context.Context) error {
		_, err := exec(ctx,
			"INSERT INTO sessions (session, principal, tenant, path, "+
				"capabilities, expires_at, issued_at, jwt_claims, note) "+
				"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
			sn.ID, sn.PrincipalId,
			sn.GetScope().GetOnLocation().GetTenantId(), // Possibly null.
			sn.GetScope().GetOnLocation().GetPath(),     // Possibly null.
			sn.Capabilities, sn.ExpiresAt.AsTime(), now, cl, sn.Note)
		return err
	})
}
