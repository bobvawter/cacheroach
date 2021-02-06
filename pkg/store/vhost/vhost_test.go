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

package vhost

import (
	"context"
	"testing"
	"time"

	"github.com/bobvawter/cacheroach/api/tenant"
	"github.com/bobvawter/cacheroach/api/vhost"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestVHost(t *testing.T) {
	a := assert.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	rig, cleanup, err := testRig(ctx)
	if !a.NoError(err) {
		return
	}
	defer cleanup()

	tID := tenant.NewID()
	if _, err := rig.tenants.Ensure(ctx, &tenant.EnsureRequest{
		Tenant: &tenant.Tenant{Label: "T", ID: tID}}); !a.NoError(err) {
		return
	}
	if _, err := rig.vhosts.Ensure(ctx, &vhost.EnsureRequest{
		Vhost: &vhost.VHost{Vhost: "example.com", TenantId: tID}}); !a.NoError(err) {
		return
	}
	if _, err := rig.vhosts.Ensure(ctx, &vhost.EnsureRequest{
		Vhost: &vhost.VHost{Vhost: "example.org", TenantId: tID}}); !a.NoError(err) {
		return
	}

	sink := &sink{ctx: ctx}
	a.NoError(rig.vhosts.List(&emptypb.Empty{}, sink))
	a.Len(sink.ret, 2)

	if _, err := rig.vhosts.Ensure(ctx, &vhost.EnsureRequest{
		Delete: true,
		Vhost:  &vhost.VHost{Vhost: "example.org", TenantId: tID}}); !a.NoError(err) {
		return
	}
	if _, err := rig.vhosts.Ensure(ctx, &vhost.EnsureRequest{
		Delete: true,
		Vhost:  &vhost.VHost{Vhost: "example.org", TenantId: tID}}); !a.NoError(err) {
		return
	}

	sink.ret = nil
	a.NoError(rig.vhosts.List(&emptypb.Empty{}, sink))
	a.Len(sink.ret, 1)
}

type sink struct {
	grpc.ServerStream
	ctx context.Context
	ret []*vhost.VHost
}

func (x *sink) Context() context.Context {
	return x.ctx
}

func (x *sink) Send(v *vhost.VHost) error {
	x.ret = append(x.ret, v)
	return nil
}
