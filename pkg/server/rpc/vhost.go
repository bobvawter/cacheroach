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

package rpc

import (
	"context"

	"github.com/Mandala/go-log"
	"github.com/bobvawter/cacheroach/api/session"
	"github.com/bobvawter/cacheroach/api/vhost"
	"github.com/bobvawter/cacheroach/pkg/server/common"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// VHostInterceptor ensures that a vhost.VHost is present in RPC calls.
type VHostInterceptor struct {
	Logger *log.Logger
	Mapper *common.VHostMap
}

// Stream wraps a streaming gRPC call.
func (i *VHostInterceptor) Stream(
	srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler,
) error {
	ctx := i.resolve(ss.Context())
	ss = &streamWrapper{ss, ctx}
	return handler(srv, ss)
}

// Unary wraps a unary gRPC call.
func (i *VHostInterceptor) Unary(
	ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
) (ret interface{}, err error) {
	ctx = i.resolve(ctx)
	return handler(ctx, req)
}

func (i *VHostInterceptor) resolve(ctx context.Context) context.Context {
	var host *vhost.VHost

	// Defer to a session if it already defines a tenant.
	if tnt := session.FromContext(ctx).GetScope().GetOnLocation().GetTenantId(); tnt != nil {
		host = &vhost.VHost{TenantId: tnt}
	} else {
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			names := md.Get(":authority")
			if len(names) > 0 {
				hostname := names[len(names)-1]
				host = i.Mapper.Resolve(hostname)
			}
		}
	}

	if host != nil {
		i.Logger.Tracef("vhost %s", host)
		ctx = vhost.WithVHost(ctx, host)
	}
	return ctx
}
