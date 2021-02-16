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

	"github.com/bobvawter/cacheroach/pkg/server/common"
	"google.golang.org/grpc"
)

// BusyInterceptor ensures that a vhost.VHost is present in RPC calls.
type BusyInterceptor struct {
	common.BusyLatch
}

// Stream wraps a streaming gRPC call.
func (i BusyInterceptor) Stream(
	srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler,
) error {
	i.Hold()
	defer i.Release()
	return handler(srv, ss)
}

// Unary wraps a unary gRPC call.
func (i BusyInterceptor) Unary(
	ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
) (ret interface{}, err error) {
	i.Hold()
	defer i.Release()
	return handler(ctx, req)
}
