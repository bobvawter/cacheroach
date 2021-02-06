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

package session

import (
	"fmt"
	"testing"

	"github.com/bobvawter/cacheroach/api/principal"
	"github.com/bobvawter/cacheroach/api/tenant"
	"github.com/stretchr/testify/assert"
)

func TestSubsetOf(t *testing.T) {
	p1 := principal.NewID()
	p2 := principal.NewID()
	t1 := tenant.NewID()
	t2 := tenant.NewID()

	tcs := []struct {
		Has   *Scope
		Wants *Scope
		Eq    bool
		Fail  bool
	}{
		{
			Has:   nil,
			Wants: nil,
			Eq:    true,
		},
		{
			Has:   &Scope{},
			Wants: &Scope{},
			Eq:    true,
		},
		{
			Has:   nil,
			Wants: &Scope{},
			Eq:    true,
		},
		{
			Has:   &Scope{},
			Wants: nil,
			Eq:    true,
		},
		{
			Has:   &Scope{},
			Wants: &Scope{Kind: &Scope_OnPrincipal{p1}},
			Fail:  true,
		},
		{
			Has:   &Scope{Kind: &Scope_OnPrincipal{p1}},
			Wants: &Scope{Kind: &Scope_OnPrincipal{p1}},
			Eq:    true,
		},
		{
			Has:   &Scope{Kind: &Scope_OnPrincipal{p1}},
			Wants: &Scope{Kind: &Scope_OnPrincipal{p2}},
			Fail:  true,
		},
		{
			Has:   &Scope{Kind: &Scope_OnPrincipal{p1}},
			Wants: &Scope{Kind: &Scope_OnPrincipal{p1}},
			Eq:    true,
		},
		{
			Has:   &Scope{Kind: &Scope_SuperToken{true}},
			Wants: &Scope{Kind: &Scope_OnPrincipal{p1}},
			Fail:  true,
		},
		{
			Has:   &Scope{Kind: &Scope_OnPrincipal{p1}},
			Wants: &Scope{Kind: &Scope_SuperToken{true}},
			Fail:  true,
		},
		{
			Has: &Scope{Kind: &Scope_OnLocation{&Location{
				TenantId: t1,
				Path:     "/*",
			}}},
			Wants: &Scope{Kind: &Scope_OnLocation{&Location{
				TenantId: t1,
				Path:     "/foo/bar",
			}}},
		},
		{
			Has: &Scope{Kind: &Scope_OnLocation{&Location{
				TenantId: t1,
				Path:     "/foo/*",
			}}},
			Wants: &Scope{Kind: &Scope_OnLocation{&Location{
				TenantId: t1,
				Path:     "/foo/bar",
			}}},
		},
		{
			Has: &Scope{Kind: &Scope_OnLocation{&Location{
				TenantId: t1,
				Path:     "/foo/*",
			}}},
			Wants: &Scope{Kind: &Scope_OnLocation{&Location{
				TenantId: t2,
				Path:     "/foo/bar",
			}}},
			Fail: true,
		},
		{
			Has: &Scope{Kind: &Scope_OnLocation{&Location{
				TenantId: t1,
				Path:     "/foo/*",
			}}},
			Wants: &Scope{Kind: &Scope_OnLocation{&Location{
				TenantId: t1,
				Path:     "foo/bar",
			}}},
			Fail: true,
		},
		{
			Has: &Scope{Kind: &Scope_OnLocation{&Location{
				TenantId: t1,
				Path:     "/foo/bar",
			}}},
			Wants: &Scope{Kind: &Scope_OnLocation{&Location{
				TenantId: t1,
				Path:     "/foo/bar",
			}}},
			Eq: true,
		},
		{
			Has: &Scope{Kind: &Scope_OnLocation{&Location{
				TenantId: t1,
				Path:     "/foo/bar/baz",
			}}},
			Wants: &Scope{Kind: &Scope_OnLocation{&Location{
				TenantId: t1,
				Path:     "/foo/bar",
			}}},
			Fail: true,
		},
		{
			Has: &Scope{Kind: &Scope_OnLocation{&Location{
				TenantId: t1,
				Path:     "",
			}}},
			Wants: &Scope{Kind: &Scope_OnLocation{&Location{
				TenantId: t1,
				Path:     "/foo/bar",
			}}},
			Fail: true,
		},
		{
			Has: &Scope{Kind: &Scope_OnLocation{&Location{
				TenantId: t1,
				Path:     "/*",
			}}},
			Wants: &Scope{Kind: &Scope_OnLocation{&Location{
				TenantId: t1,
				Path:     "",
			}}},
			Fail: true,
		},
	}

	for i, tc := range tcs {
		t.Run(fmt.Sprintf("tc:%d", i), func(t *testing.T) {
			a := assert.New(t)
			a.True(tc.Wants.IsSubsetOf(tc.Wants))
			a.True(tc.Has.IsSubsetOf(tc.Has))
			if tc.Fail {
				a.False(tc.Wants.IsSubsetOf(tc.Has))
				return
			}
			a.True(tc.Wants.IsSubsetOf(tc.Has))

			if tc.Eq {
				a.True(tc.Has.IsSubsetOf(tc.Wants))
			} else {
				a.False(tc.Has.IsSubsetOf(tc.Wants))
			}
		})
	}
}
