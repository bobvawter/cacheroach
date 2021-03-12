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
	"testing"
	"time"

	"fmt"

	"github.com/bobvawter/cacheroach/api/capabilities"
	"github.com/bobvawter/cacheroach/api/principal"
	"github.com/bobvawter/cacheroach/api/session"
	"github.com/bobvawter/cacheroach/api/tenant"
	. "github.com/bobvawter/cacheroach/api/token"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Check that a domain-level principal implicitly delegates to
// other principals with the name email domain.
func TestDomainInheritance(t *testing.T) {
	a := assert.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	rig, cleanup, err := testRig(ctx)
	if !a.NoError(err) {
		return
	}
	defer cleanup()

	tID := tenant.NewID()
	_, err = rig.tenants.Ensure(ctx, &tenant.EnsureRequest{Tenant: &tenant.Tenant{
		Label: "Some Tenant",
		ID:    tID,
	}})
	if !a.NoError(err) {
		return
	}

	pID := principal.NewID()
	_, err = rig.principals.Ensure(ctx, &principal.EnsureRequest{
		Principal: &principal.Principal{
			ID:     pID,
			Claims: []byte(`{"email":"user@example.com"}`),
		}})
	if !a.NoError(err) {
		return
	}

	principalSession, err := rig.tokens.Issue(ctx, &IssueRequest{Template: &session.Session{
		PrincipalId:  pID,
		ExpiresAt:    timestamppb.New(time.Now().Add(time.Hour)),
		Capabilities: capabilities.All(),
		Scope:        &session.Scope{Kind: &session.Scope_OnPrincipal{OnPrincipal: pID}},
	}})
	if !a.NoError(err) {
		return
	}

	domainID := principal.NewID()
	_, err = rig.principals.Ensure(ctx, &principal.EnsureRequest{
		Principal: &principal.Principal{
			Label:       "Domain Principal",
			ID:          domainID,
			EmailDomain: "example.com",
		}})
	if !a.NoError(err) {
		return
	}

	domainSession, err := rig.tokens.Issue(ctx, &IssueRequest{Template: &session.Session{
		PrincipalId:  domainID,
		ExpiresAt:    timestamppb.New(time.Now().Add(time.Hour)),
		Capabilities: capabilities.All(),
		Scope: &session.Scope{
			Kind: &session.Scope_OnLocation{
				OnLocation: &session.Location{
					TenantId: tID,
					Path:     "/*",
				}}}}})
	if !a.NoError(err) {
		return
	}

	{
		sink := &sink{ctx: session.WithSession(ctx, principalSession.Issued)}
		err = rig.tokens.Find(&session.Scope{}, sink)
		if !a.NoError(err) {
			return
		}
		a.Len(sink.ret, 2)
	}

	// Ensure that the domain-level session can will be invalidated.
	_, err = rig.tokens.Invalidate(session.WithSession(ctx, domainSession.Issued),
		&InvalidateRequest{Kind: &InvalidateRequest_ID{ID: domainSession.Issued.ID}})
	if !a.NoError(err) {
		return
	}

	rig.tokens.cache.Purge()

	{
		sink := &sink{ctx: session.WithSession(ctx, principalSession.Issued)}
		err = rig.tokens.Find(&session.Scope{}, sink)
		if !a.NoError(err) {
			return
		}
		a.Len(sink.ret, 1)
	}
}

func TestTokenFlow(t *testing.T) {
	a := assert.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	rig, cleanup, err := testRig(ctx)
	if !a.NoError(err) {
		return
	}
	defer cleanup()

	tID := tenant.NewID()
	_, err = rig.tenants.Ensure(ctx, &tenant.EnsureRequest{Tenant: &tenant.Tenant{
		Label: "Some Tenant",
		ID:    tID,
	}})
	if !a.NoError(err) {
		return
	}

	pID := principal.NewID()
	p := &principal.Principal{
		Label: "Some User",
		ID:    pID,
	}
	_, err = rig.principals.Ensure(ctx, &principal.EnsureRequest{Principal: p})
	if !a.NoError(err) {
		return
	}

	tcs := []*session.Session{
		{
			Capabilities: &capabilities.Capabilities{Delegate: true},
			ExpiresAt:    timestamppb.New(time.Now().AddDate(0, 0, 1).Round(time.Second)),
			Name:         "foo",
			PrincipalId:  pID,
			Scope: &session.Scope{
				Kind: &session.Scope_OnLocation{
					OnLocation: &session.Location{
						TenantId: tID,
						Path:     "/*",
					},
				},
			},
		},
		{
			Capabilities: &capabilities.Capabilities{Delegate: true},
			ExpiresAt:    timestamppb.New(time.Now().AddDate(0, 0, 1).Round(time.Second)),
			Name:         "bar",
			PrincipalId:  pID,
			Scope: &session.Scope{
				Kind: &session.Scope_OnPrincipal{
					OnPrincipal: pID},
			},
		},
	}

	for i, tc := range tcs {
		t.Run(fmt.Sprintf("tc%d", i), func(t *testing.T) {
			a := assert.New(t)

			ret, err := rig.tokens.Issue(ctx, &IssueRequest{Template: tc})
			if !a.NoError(err) {
				return
			}
			t.Log(ret.Token.Jwt)
			a.NotEmpty(ret.Token.Jwt)

			sn, err := rig.tokens.Validate(ctx, ret.Token)
			if !a.NoError(err) {
				return
			}
			if !a.NotNil(sn) {
				return
			}
			a.False(sn.ID.Zero())

			// Load by ID.
			{
				loaded, err := rig.tokens.Load(ctx, &LoadRequest{Kind: &LoadRequest_ID{ID: sn.ID}})
				if a.NoError(err) {
					a.Equal(sn.String(), loaded.String())
				}
			}

			// Load by principal-scoped name.
			{
				loaded, err := rig.tokens.Load(session.WithSession(ctx, sn),
					&LoadRequest{Kind: &LoadRequest_Name{Name: sn.Name}})
				if a.NoError(err) {
					a.Equal(sn.String(), loaded.String())
				}
			}

			// Should show up in find.
			{
				sink := &sink{ctx: session.WithSession(ctx, sn)}
				err := rig.tokens.Find(&session.Scope{}, sink)
				if a.NoError(err) && a.Len(sink.ret, 1) {
					a.Equal(sn.String(), sink.ret[0].String())
				}
			}

			// Nullify the session ID for comparison
			{
				tc := proto.Clone(tc).(*session.Session)
				sn := proto.Clone(sn).(*session.Session)
				tc.ID = nil
				sn.ID = nil
				a.Equal(tc.String(), sn.String())
			}

			req := &InvalidateRequest{
				Kind: &InvalidateRequest_ID{
					ID: ret.Issued.ID},
			}

			_, err = rig.tokens.Invalidate(session.WithSession(ctx, sn), req)
			if !a.NoError(err) {
				return
			}

			// Shouldn't find expired sessions.
			{
				sink := &sink{ctx: session.WithSession(ctx, sn)}
				err := rig.tokens.Find(&session.Scope{}, sink)
				a.NoError(err)
				a.Empty(sink.ret)
			}

			_, err = rig.tokens.Invalidate(session.WithSession(ctx, sn), req)
			if !a.NoError(err) {
				return
			}

			sn, err = rig.tokens.Validate(ctx, ret.Token)
			a.Nilf(sn, "%s", sn)
			a.NoError(err)

		})
	}
}

// Issue a token, refresh it, and ensure invalidation of other token.
func TestRefreshFlow(t *testing.T) {
	a := assert.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	rig, cleanup, err := testRig(ctx)
	if !a.NoError(err) {
		return
	}
	defer cleanup()

	pID := principal.NewID()
	p := &principal.Principal{
		Label: "Some User",
		ID:    pID,
	}
	_, err = rig.principals.Ensure(ctx, &principal.EnsureRequest{Principal: p})
	a.NoError(err)

	resp, err := rig.tokens.Issue(ctx, &IssueRequest{Template: &session.Session{
		Capabilities: &capabilities.Capabilities{Delegate: true},
		ExpiresAt:    timestamppb.New(time.Now().AddDate(0, 0, 1).Round(time.Second)),
		PrincipalId:  pID,
		Scope: &session.Scope{
			Kind: &session.Scope_OnPrincipal{
				OnPrincipal: pID,
			},
		},
	}})
	if !a.NoError(err) {
		return
	}

	// Clone the session since this method mutates its input.
	sn := proto.Clone(resp.Issued).(*session.Session)
	resp2, err := rig.tokens.Refresh(session.WithSession(ctx, sn), nil)
	if !a.NoError(err) {
		return
	}

	a.NotEqual(resp.Token.Jwt, resp2.Token.Jwt)

	a.NotEqual(resp.Issued.ID.String(), resp2.Issued.ID.String())
	a.NotEqual(resp.Issued.ExpiresAt.String(), resp2.Issued.ExpiresAt.String())
	a.Equal(resp.Issued.Scope.String(), resp2.Issued.Scope.String())

	sn, err = rig.tokens.Validate(ctx, resp.Token)
	a.Nilf(sn, "%s", sn)
	a.NoError(err)

	sn, err = rig.tokens.Validate(ctx, resp2.Token)
	a.NotNil(sn)
	a.NoError(err)
}

type sink struct {
	grpc.ServerStream
	ctx context.Context
	ret []*session.Session
}

func (x *sink) Context() context.Context {
	return x.ctx
}

func (x *sink) Send(m *session.Session) error {
	x.ret = append(x.ret, m)
	return nil
}
