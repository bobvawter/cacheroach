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
	"testing"
	"time"

	. "github.com/bobvawter/cacheroach/api/auth"
	"github.com/bobvawter/cacheroach/api/principal"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestAuth(t *testing.T) {
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

	const email = "email:you@example.com"
	const pw = "Str0ngPassword!"

	p := &principal.Principal{
		Handles: []string{email},
		Label:   "Some User",
		ID:      principal.NewID(),
		Version: 0,
	}
	a.NoError(p.SetPassword(pw))

	if _, err = rig.principals.Ensure(ctx, &principal.EnsureRequest{Principal: p}); !a.NoError(err) {
		return
	}
	a.Equal(int64(1), p.Version)

	resp, err := rig.auth.Login(ctx, &LoginRequest{Handle: email, Password: pw})
	a.NoError(err)
	a.NotEmpty(resp.GetToken().GetJwt())

	_, err = rig.auth.Login(ctx, &LoginRequest{Handle: email, Password: ""})
	if a.Error(err) {
		s, ok := status.FromError(err)
		if a.True(ok) {
			a.Equal(codes.Unauthenticated, s.Code())
		}
	}

	_, err = rig.auth.Login(ctx, &LoginRequest{Handle: "email:nobody@example.com", Password: ""})
	if a.Error(err) {
		s, ok := status.FromError(err)
		if a.True(ok) {
			a.Equal(codes.Unauthenticated, s.Code())
		}
	}
}
