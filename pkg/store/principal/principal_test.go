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
	"encoding/json"
	"testing"
	"time"

	. "github.com/bobvawter/cacheroach/api/principal"
	"github.com/bobvawter/cacheroach/api/tenant"
	"github.com/bobvawter/cacheroach/pkg/store/util"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestPrincipal(t *testing.T) {
	a := assert.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	rig, cleanup, err := testRig(ctx)
	if !a.NoError(err) {
		return
	}
	defer cleanup()

	if !a.NoError(err) {
		return
	}

	tID := tenant.NewID()
	if _, err := rig.t.Ensure(ctx, &tenant.EnsureRequest{
		Tenant: &tenant.Tenant{Label: "Tenant", ID: tID}}); !a.NoError(err) {
		return
	}
	a.NoError(err)

	const email = "you@example.com"
	claimBytes, err := json.Marshal(map[string]string{
		"email": email,
		"name":  "Some User",
	})
	if !a.NoError(err) {
		return
	}
	p := &Principal{
		Claims:  claimBytes,
		ID:      NewID(),
		Version: 0,
	}

	if _, err := rig.p.Ensure(ctx, &EnsureRequest{Principal: p}); !a.NoError(err) {
		return
	}
	a.Equal(int64(1), p.Version)

	t.Run("watch", func(t *testing.T) {
		a := assert.New(t)
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		ch := make(chan *Principal)

		go rig.p.watch(ctx, p.ID, 10*time.Millisecond, func(x *Principal) error {
			ch <- x
			return nil
		})
		x := <-ch
		a.True(proto.Equal(x, p))

		if _, err := rig.p.Ensure(ctx, &EnsureRequest{Principal: p}); !a.NoError(err) {
			return
		}
		a.Equal(int64(2), p.Version)
		x = <-ch
		a.True(proto.Equal(x, p))
	})

	t.Run("loadID", func(t *testing.T) {
		a := assert.New(t)
		p2, err := rig.p.Load(ctx, &LoadRequest{Kind: &LoadRequest_ID{ID: p.ID}})
		a.NoError(err)
		a.NotNil(p2)
		a.Truef(proto.Equal(p, p2), "%v vs. %v", p, p2)
		a.Equal(p.String(), p2.String())
	})

	t.Run("loadID404", func(t *testing.T) {
		a := assert.New(t)
		_, err := rig.p.Load(ctx, &LoadRequest{Kind: &LoadRequest_ID{ID: NewID()}})
		s, ok := status.FromError(err)
		a.True(ok)
		a.Equal(codes.NotFound, s.Code())
	})

	t.Run("loadHandle", func(t *testing.T) {
		a := assert.New(t)
		p2, err := rig.p.Load(ctx, &LoadRequest{Kind: &LoadRequest_Email{Email: email}})
		a.NoError(err)
		a.NotNil(p2)
		a.Truef(proto.Equal(p, p2), "%v vs. %v", p, p2)
		a.Equal(p.String(), p2.String())
	})

	t.Run("loadHandle404", func(t *testing.T) {
		a := assert.New(t)
		_, err := rig.p.Load(ctx, &LoadRequest{Kind: &LoadRequest_Email{Email: "not_found@example.com"}})
		s, ok := status.FromError(err)
		a.True(ok)
		a.Equal(codes.NotFound, s.Code())
	})

	t.Run("partial-update", func(t *testing.T) {
		a := assert.New(t)
		resp, err := rig.p.Ensure(ctx, &EnsureRequest{
			Principal: &Principal{ID: p.ID, RefreshAfter: timestamppb.Now(), RefreshToken: "Updated Token", Version: 2}})
		a.NoError(err)
		a.Equal("Updated Token", resp.Principal.RefreshToken)
		a.Equal(p.Label, resp.Principal.Label)
		a.Equal(int64(3), resp.Principal.Version)
	})

	t.Run("skew", func(t *testing.T) {
		a := assert.New(t)
		p.Version = 88
		_, err := rig.p.Ensure(ctx, &EnsureRequest{Principal: p})
		a.True(errors.Is(err, util.ErrVersionSkew))
	})

	t.Run("domain", func(t *testing.T) {
		a := assert.New(t)
		resp, err := rig.p.Ensure(ctx, &EnsureRequest{
			Principal: &Principal{EmailDomain: "Example.COM"}})
		if !a.NoError(err) {
			return
		}
		a.Equal(int64(1), resp.Principal.Version)

		found, err := rig.p.Load(ctx, &LoadRequest{
			Kind: &LoadRequest_EmailDomain{EmailDomain: "example.com"}})
		if !a.NoError(err) {
			return
		}
		a.Equal(resp.Principal.ID.String(), found.ID.String())
		a.Equal("example.com", found.EmailDomain)

		_, err = rig.p.Ensure(ctx, &EnsureRequest{
			Principal: &Principal{EmailDomain: "example.com"}})
		if a.NotNil(err) {
			a.Contains(err.Error(), "duplicate key value")
		}
	})
}
