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

package tenant

import (
	"context"
	"testing"
	"time"

	. "github.com/bobvawter/cacheroach/api/tenant"
	"github.com/bobvawter/cacheroach/pkg/store/util"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

func TestTenants(t *testing.T) {
	a := assert.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	s, cleanup, err := newForTesting(ctx)
	if !a.NoError(err) {
		return
	}
	defer cleanup()

	tnt := &Tenant{
		Label: "Some Tenant",
		ID:    NewID(),
	}

	_, err = s.Ensure(ctx, &EnsureRequest{Tenant: tnt})
	a.NoError(err)
	a.Equal(int64(1), tnt.Version)

	_, err = s.Ensure(ctx, &EnsureRequest{Tenant: tnt})
	a.NoError(err)
	a.Equal(int64(2), tnt.Version)

	str := &fakeStream{ctx: ctx}
	err = s.List(nil, str)
	a.NoError(err)
	a.Len(str.ret, 1)
	a.Equal(tnt.String(), str.ret[0].String())

	tnt.Version = 100
	_, err = s.Ensure(ctx, &EnsureRequest{Tenant: tnt})
	a.True(errors.Is(err, util.ErrVersionSkew))

	tnt.Version = 2
	_, err = s.Ensure(ctx, &EnsureRequest{Tenant: tnt, Delete: true})
	a.NoError(err)

	str.ret = nil
	err = s.List(nil, str)
	a.NoError(err)
	a.Len(str.ret, 0)
}

type fakeStream struct {
	grpc.ServerStream
	ctx context.Context
	ret []*Tenant
}

func (f *fakeStream) Context() context.Context {
	return f.ctx
}

func (f *fakeStream) Send(tnt *Tenant) error {
	f.ret = append(f.ret, tnt)
	return nil
}
