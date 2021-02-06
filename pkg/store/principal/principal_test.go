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
	"testing"
	"time"

	. "github.com/bobvawter/cacheroach/api/principal"
	"github.com/bobvawter/cacheroach/api/tenant"
	"github.com/bobvawter/cacheroach/pkg/store/util"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
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

	const email = "email:you@example.com"
	const pw = "Str0ngPassword!"

	p := &Principal{
		Handles: []string{email},
		Label:   "Some User",
		ID:      NewID(),
		Version: 0,
	}
	a.NoError(p.SetPassword(pw))

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

	t.Run("load", func(t *testing.T) {
		a := assert.New(t)
		p2, err := rig.p.Load(ctx, p.ID)
		a.NoError(err)
		a.NotNil(p2)
		a.Truef(proto.Equal(p, p2), "%v vs. %v", p, p2)
		a.Equal(p.String(), p2.String())
	})

	t.Run("partial-update", func(t *testing.T) {
		a := assert.New(t)
		resp, err := rig.p.Ensure(ctx, &EnsureRequest{
			Principal: &Principal{ID: p.ID, Label: "More Label", Version: 2}})
		a.NoError(err)
		a.Equal("More Label", resp.Principal.Label)
		a.Equal(p.PasswordHash, resp.Principal.PasswordHash)
		a.NotEmpty(resp.Principal.PasswordHash)
	})

	t.Run("skew", func(t *testing.T) {
		a := assert.New(t)
		p.Version = 88
		_, err := rig.p.Ensure(ctx, &EnsureRequest{Principal: p})
		a.True(errors.Is(err, util.ErrVersionSkew))
	})

}
