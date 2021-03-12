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

package enforcer

import (
	"context"
	"testing"

	"fmt"

	"time"

	"github.com/bobvawter/cacheroach/api/capabilities"
	"github.com/bobvawter/cacheroach/api/principal"
	"github.com/bobvawter/cacheroach/api/session"
	"github.com/bobvawter/cacheroach/api/tenant"
	"github.com/bobvawter/cacheroach/api/token"
	"github.com/bobvawter/cacheroach/api/upload"
	"github.com/bobvawter/cacheroach/api/vhost"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func Test(t *testing.T) {
	a := assert.New(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rig, cleanup, err := testRig(ctx)
	if !a.NoError(err) {
		return
	}
	defer cleanup()

	pID := principal.NewID()
	tcs := []struct {
		ctx context.Context
		dir capabilities.Direction
		src interface {
			proto.Message
			String() string
		}
		expected interface {
			proto.Message
			String() string
		}
	}{
		{
			ctx: ctx,
			src: &principal.Principal{
				ID:      pID,
				Version: 1,
			},
			expected: &principal.Principal{
				ID:      pID,
				Version: 1,
			},
		},
		{
			ctx: session.WithSession(ctx, &session.Session{
				Capabilities: &capabilities.Capabilities{Write: true, Pii: true},
				PrincipalId:  pID,
				Scope:        &session.Scope{Kind: &session.Scope_OnPrincipal{OnPrincipal: pID}},
			}),
			src: &principal.Principal{
				ID:      pID,
				Version: 1,
			},
			expected: &principal.Principal{
				ID:      pID,
				Version: 1,
			},
		},
		{
			ctx: session.WithSession(ctx, &session.Session{
				Capabilities: &capabilities.Capabilities{Read: true, Write: true, Pii: true},
				PrincipalId:  pID,
				Scope:        &session.Scope{Kind: &session.Scope_OnPrincipal{OnPrincipal: pID}},
			}),
			dir: capabilities.Direction_REQUEST,
			src: &principal.Principal{
				ID:      pID,
				Version: 1,
			},
			expected: &principal.Principal{
				ID:      pID,
				Version: 1,
			},
		},
	}

	for idx, tc := range tcs {
		t.Run(fmt.Sprintf("%d", idx), func(t *testing.T) {
			a := assert.New(t)

			if tc.dir == 0 {
				tc.dir = capabilities.Direction_RESPONSE
			}
			eq := proto.Equal(tc.src, tc.expected)
			ok, err := rig.Enforce(tc.ctx, tc.dir, protoreflect.ValueOf(tc.src.ProtoReflect()))
			if a.NoError(err) {
				if eq {
					a.True(ok)
				} else {
					a.False(ok)
				}
				a.Equal(tc.expected.String(), tc.src.String())
			}
		})
	}
}

func TestEval(t *testing.T) {
	a := assert.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rig, cleanup, err := testRig(ctx)
	if !assert.NoError(t, err) {
		return
	}
	defer cleanup()

	pID := principal.NewID()
	if _, err := rig.principals.Ensure(ctx, &principal.EnsureRequest{Principal: &principal.Principal{
		ID: pID,
	}}); !a.NoError(err) {
		return
	}

	tID := tenant.NewID()
	if _, err := rig.tenants.Ensure(ctx, &tenant.EnsureRequest{Tenant: &tenant.Tenant{
		ID:    tID,
		Label: "delegated access",
	}}); !a.NoError(err) {
		return
	}
	if _, err := rig.tokens.Issue(ctx, &token.IssueRequest{Template: &session.Session{
		Capabilities: &capabilities.Capabilities{Write: true},
		ExpiresAt:    timestamppb.New(time.Now().Add(time.Hour)),
		PrincipalId:  pID,
		Scope: &session.Scope{Kind: &session.Scope_OnLocation{
			OnLocation: &session.Location{
				TenantId: tID,
				Path:     "/foo/bar/*",
			}}},
		Note: "testing automatic delegation lookup",
	}}); !a.NoError(err) {
		return
	}

	tcs := []struct {
		dir      capabilities.Direction
		expected bool
		err      string
		push     []proto.Message
		rule     *capabilities.Rule
		sn       *session.Session
		vhost    *vhost.VHost
	}{
		{
			rule:     &capabilities.Rule{Kind: &capabilities.Rule_Never{Never: true}},
			expected: false,
		},
		{
			rule:     &capabilities.Rule{Kind: &capabilities.Rule_Never{Never: false}},
			expected: false,
		},
		{
			rule: &capabilities.Rule{Kind: &capabilities.Rule_Not{
				Not: &capabilities.Rule{Kind: &capabilities.Rule_Never{Never: true}}}},
			expected: true,
		},
		{
			rule: &capabilities.Rule{Kind: &capabilities.Rule_Direction{
				Direction: capabilities.Direction_REQUEST}},
			dir:      capabilities.Direction_REQUEST,
			expected: true,
		},
		{
			rule: &capabilities.Rule{Kind: &capabilities.Rule_Direction{
				Direction: capabilities.Direction_REQUEST}},
			dir:      capabilities.Direction_RESPONSE,
			expected: false,
		},
		{
			rule: &capabilities.Rule{Kind: &capabilities.Rule_AuthStatus_{
				AuthStatus: capabilities.Rule_LOGGED_IN}},
			sn:       &session.Session{},
			expected: true,
		},
		{
			rule: &capabilities.Rule{Kind: &capabilities.Rule_AuthStatus_{
				AuthStatus: capabilities.Rule_LOGGED_IN}},
			expected: false,
		},
		{
			rule: &capabilities.Rule{Kind: &capabilities.Rule_AuthStatus_{
				AuthStatus: capabilities.Rule_PUBLIC}},
			sn:       &session.Session{},
			expected: true,
		},
		{
			rule: &capabilities.Rule{Kind: &capabilities.Rule_AuthStatus_{
				AuthStatus: capabilities.Rule_PUBLIC}},
			expected: true,
		},
		{
			rule: &capabilities.Rule{Kind: &capabilities.Rule_AuthStatus_{
				AuthStatus: capabilities.Rule_SUPER}},
			sn: &session.Session{Scope: &session.Scope{Kind: &session.Scope_SuperToken{
				SuperToken: true}}},
			expected: true,
		},
		{
			rule: &capabilities.Rule{Kind: &capabilities.Rule_AuthStatus_{
				AuthStatus: capabilities.Rule_SUPER}},
			sn:       &session.Session{},
			expected: false,
		},
		{
			rule: &capabilities.Rule{Kind: &capabilities.Rule_Eq_{
				Eq: &capabilities.Rule_Eq{
					A: &capabilities.Reference{Kind: &capabilities.Reference_Context{
						Context: capabilities.ContextReference_SESSION_PRINCIPAL}},
					B: &capabilities.Reference{Kind: &capabilities.Reference_Field{
						Field: 1}},
				}}},
			sn:       &session.Session{PrincipalId: pID},
			push:     []proto.Message{&principal.Principal{ID: pID}},
			expected: true,
		},
		{
			rule: &capabilities.Rule{Kind: &capabilities.Rule_Eq_{
				Eq: &capabilities.Rule_Eq{
					A: &capabilities.Reference{Kind: &capabilities.Reference_Context{
						Context: capabilities.ContextReference_INVALID_CONTEXT}},
					B: &capabilities.Reference{Kind: &capabilities.Reference_Field{
						Field: 1}},
				}}},
			sn:   &session.Session{PrincipalId: pID},
			push: []proto.Message{&principal.Principal{ID: pID}},
			err:  "invalid context",
		},
		{
			rule: &capabilities.Rule{Kind: &capabilities.Rule_Eq_{
				Eq: &capabilities.Rule_Eq{
					A: &capabilities.Reference{Kind: &capabilities.Reference_Context{
						Context: capabilities.ContextReference_SESSION_PRINCIPAL}},
					B: &capabilities.Reference{Kind: &capabilities.Reference_Field{
						Field: 3}},
				}}},
			sn:  &session.Session{PrincipalId: pID},
			err: "empty stack",
		},
		{
			rule: &capabilities.Rule{Kind: &capabilities.Rule_Eq_{
				Eq: &capabilities.Rule_Eq{
					A: &capabilities.Reference{Kind: &capabilities.Reference_Context{
						Context: capabilities.ContextReference_SESSION_PRINCIPAL}},
					B: &capabilities.Reference{Kind: &capabilities.Reference_Field{
						Field: 1}},
				}}},
			sn:       &session.Session{PrincipalId: principal.NewID()},
			push:     []proto.Message{&principal.Principal{ID: pID}},
			expected: false,
		},
		{
			rule: &capabilities.Rule{Kind: &capabilities.Rule_Eq_{
				Eq: &capabilities.Rule_Eq{
					A: &capabilities.Reference{Kind: &capabilities.Reference_Context{
						Context: capabilities.ContextReference_SESSION_PRINCIPAL}},
					B: &capabilities.Reference{Kind: &capabilities.Reference_Context{
						Context: capabilities.ContextReference_SESSION_PRINCIPAL}},
				}}},
			sn:       &session.Session{PrincipalId: principal.Unauthenticated},
			expected: true,
		},
		{
			rule: &capabilities.Rule{Kind: &capabilities.Rule_Eq_{
				Eq: &capabilities.Rule_Eq{
					A: &capabilities.Reference{Kind: &capabilities.Reference_Context{
						Context: capabilities.ContextReference_UNAUTHENTICATED_PRINCIPAL}},
					B: &capabilities.Reference{Kind: &capabilities.Reference_Context{
						Context: capabilities.ContextReference_SESSION_PRINCIPAL}},
				}}},
			expected: false,
		},
		{
			rule: &capabilities.Rule{Kind: &capabilities.Rule_Eq_{
				Eq: &capabilities.Rule_Eq{
					A: &capabilities.Reference{Kind: &capabilities.Reference_Context{
						Context: capabilities.ContextReference_SCOPE_TENANT}},
					B: &capabilities.Reference{Kind: &capabilities.Reference_Field{
						Field: 1}},
				}}},
			sn: &session.Session{
				PrincipalId: pID,
				Scope: &session.Scope{Kind: &session.Scope_OnLocation{
					OnLocation: &session.Location{
						TenantId: tID,
						Path:     "/*",
					}}},
			},
			push:     []proto.Message{&tenant.Tenant{ID: tID}},
			expected: true,
		},
		{
			rule: &capabilities.Rule{Kind: &capabilities.Rule_Eq_{
				Eq: &capabilities.Rule_Eq{
					A: &capabilities.Reference{Kind: &capabilities.Reference_Context{
						Context: capabilities.ContextReference_SCOPE_TENANT}},
					B: &capabilities.Reference{Kind: &capabilities.Reference_Field{
						Field: 1}},
				}}},
			sn: &session.Session{
				PrincipalId: pID,
				Scope: &session.Scope{Kind: &session.Scope_OnLocation{
					OnLocation: &session.Location{
						TenantId: tID,
						Path:     "/foo/bar/baz",
					}}},
			},
			push:     []proto.Message{&tenant.Tenant{ID: tID}},
			expected: true,
		},
		{
			rule: &capabilities.Rule{Kind: &capabilities.Rule_Eq_{
				Eq: &capabilities.Rule_Eq{
					A: &capabilities.Reference{Kind: &capabilities.Reference_Context{
						Context: capabilities.ContextReference_SCOPE_TENANT}},
					B: &capabilities.Reference{Kind: &capabilities.Reference_Field{
						Field: 1}},
				}}},
			sn: &session.Session{
				PrincipalId: pID,
				Scope: &session.Scope{Kind: &session.Scope_OnLocation{
					OnLocation: &session.Location{
						TenantId: tID,
						Path:     "/foo/bar/baz",
					}}},
			},
			push:     []proto.Message{&tenant.Tenant{ID: tID}},
			expected: true,
		},
		{
			rule: &capabilities.Rule{Kind: &capabilities.Rule_May{
				May: &capabilities.SessionReference{
					Capabilities: &capabilities.Capabilities{Write: true},
					Scope: &capabilities.ScopeReference{Kind: &capabilities.ScopeReference_OnLocation{
						OnLocation: &capabilities.LocationReference{
							TenantId: &capabilities.Reference{Kind: &capabilities.Reference_Context{
								Context: capabilities.ContextReference_SCOPE_TENANT,
							}},
							Path: &capabilities.Reference{Kind: &capabilities.Reference_Field{
								Field: 2,
							}},
						},
					}},
				}}},
			sn: &session.Session{
				PrincipalId:  pID,
				Capabilities: &capabilities.Capabilities{Write: true},
				Scope: &session.Scope{Kind: &session.Scope_OnLocation{
					OnLocation: &session.Location{
						TenantId: tID,
						Path:     "/*",
					}}},
			},
			push: []proto.Message{&upload.BeginRequest{
				Tenant: tID,
				Path:   "/foo/bar",
			}},
			expected: true,
		},
		{
			rule: &capabilities.Rule{Kind: &capabilities.Rule_May{
				May: &capabilities.SessionReference{
					Capabilities: &capabilities.Capabilities{Write: true},
					Scope: &capabilities.ScopeReference{Kind: &capabilities.ScopeReference_OnLocation{
						OnLocation: &capabilities.LocationReference{
							TenantId: &capabilities.Reference{Kind: &capabilities.Reference_Context{
								Context: capabilities.ContextReference_SCOPE_TENANT,
							}},
							Path: &capabilities.Reference{Kind: &capabilities.Reference_Field{
								Field: 2,
							}},
						},
					}},
				}}},
			sn: &session.Session{
				PrincipalId:  pID,
				Capabilities: &capabilities.Capabilities{Write: true},
				Scope: &session.Scope{Kind: &session.Scope_OnLocation{
					OnLocation: &session.Location{
						TenantId: tID,
						Path:     "/no/way",
					}}},
			},
			push: []proto.Message{&upload.BeginRequest{
				Tenant: tID,
				Path:   "/foo/bar",
			}},
			expected: false,
		},
		{
			rule: &capabilities.Rule{Kind: &capabilities.Rule_And_{
				And: &capabilities.Rule_And{
					Rule: []*capabilities.Rule{
						{Kind: &capabilities.Rule_Not{Not: &capabilities.Rule{Kind: &capabilities.Rule_Never{}}}},
						{Kind: &capabilities.Rule_Not{Not: &capabilities.Rule{Kind: &capabilities.Rule_Never{}}}},
					},
				}}},
			expected: true,
		},
		{
			rule: &capabilities.Rule{Kind: &capabilities.Rule_And_{
				And: &capabilities.Rule_And{
					Rule: []*capabilities.Rule{
						{Kind: &capabilities.Rule_Not{Not: &capabilities.Rule{Kind: &capabilities.Rule_Never{}}}},
						{Kind: &capabilities.Rule_Never{}},
					},
				}}},
			expected: false,
		},
		{
			// Testing access via delegated session above
			rule: &capabilities.Rule{Kind: &capabilities.Rule_May{
				May: &capabilities.SessionReference{
					Capabilities: &capabilities.Capabilities{Write: true},
					Scope: &capabilities.ScopeReference{Kind: &capabilities.ScopeReference_OnLocation{
						OnLocation: &capabilities.LocationReference{
							TenantId: &capabilities.Reference{Kind: &capabilities.Reference_Context{
								Context: capabilities.ContextReference_VHOST_TENANT,
							}},
							Path: &capabilities.Reference{Kind: &capabilities.Reference_Field{
								Field: 2,
							}},
						}}}}}},
			push: []proto.Message{&upload.BeginRequest{
				Tenant: tID,
				Path:   "/foo/bar/ok",
			}},
			sn: &session.Session{
				PrincipalId:  principal.NewID(), // Not pID to test delegation behavior.
				Capabilities: &capabilities.Capabilities{Delegate: true},
				Scope: &session.Scope{Kind: &session.Scope_OnPrincipal{
					OnPrincipal: pID,
				}},
			},
			vhost: &vhost.VHost{
				Vhost:    "example.com",
				TenantId: tID,
			},
			expected: true,
		},
	}

	for idx, tc := range tcs {
		t.Run(fmt.Sprintf("%d", idx), func(t *testing.T) {
			a := assert.New(t)
			ctx := ctx
			if tc.sn != nil {
				ctx = session.WithSession(ctx, tc.sn)
			}
			if tc.vhost != nil {
				ctx = vhost.WithVHost(ctx, tc.vhost)
			}
			ev := &eval{
				Context:   ctx,
				Enforcer:  rig.Enforcer,
				direction: tc.dir,
				seen:      make(map[proto.Message]bool),
				sn:        tc.sn,
			}
			for i := range tc.push {
				ev.Push(tc.push[i])
			}
			ok, err := ev.Eval(tc.rule)
			if tc.err != "" {
				a.EqualError(err, tc.err)
			} else if a.NoError(err) {
				a.Equal(tc.expected, ok)
			}
		})
	}
}
