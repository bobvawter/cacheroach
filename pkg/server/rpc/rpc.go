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

// Package rpc contains the gRPC endpoints and support code.
package rpc

import (
	"context"
	"runtime/pprof"

	"github.com/Mandala/go-log"
	"github.com/bobvawter/cacheroach/api/auth"
	"github.com/bobvawter/cacheroach/api/diag"
	"github.com/bobvawter/cacheroach/api/file"
	"github.com/bobvawter/cacheroach/api/principal"
	"github.com/bobvawter/cacheroach/api/tenant"
	"github.com/bobvawter/cacheroach/api/token"
	"github.com/bobvawter/cacheroach/api/upload"
	"github.com/bobvawter/cacheroach/api/vhost"
	"github.com/bobvawter/cacheroach/pkg/metrics"
	"github.com/google/wire"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// Set is used by wire.
var Set = wire.NewSet(
	ProvideAuthInterceptor,
	ProvideRPC,
	wire.Struct(new(BusyInterceptor), "*"),
	wire.Struct(new(ElideInterceptor), "*"),
	wire.Struct(new(VHostInterceptor), "*"),
)

// ProvideRPC attaches all of the service implementations to a
// *grpc.Server and returns it.
func ProvideRPC(
	log *log.Logger,
	security *AuthInterceptor,
	busy *BusyInterceptor,
	elide *ElideInterceptor,
	met *metrics.Interceptor,
	vh *VHostInterceptor,
	ath auth.AuthServer,
	dia diag.DiagsServer,
	fls file.FilesServer,
	prn principal.PrincipalsServer,
	tnt tenant.TenantsServer,
	tkn token.TokensServer,
	upl upload.UploadsServer,
	vht vhost.VHostsServer,
) (*grpc.Server, error) {
	rpc := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (ret interface{}, err error) {
				labels := pprof.Labels("rpc", info.FullMethod)
				pprof.Do(ctx, labels, func(ctx context.Context) {
					log.Tracef("RPC %s starting", info.FullMethod)
					ret, err = handler(ctx, req)
					log.Tracef("RPC %s complete: %v, %v", info.FullMethod, ret, err)
				})
				return
			},
			busy.Unary,
			met.Unary,
			security.Unary,
			vh.Unary,
			elide.Unary,
		),
		grpc.ChainStreamInterceptor(
			func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
				labels := pprof.Labels("rpc", info.FullMethod)
				pprof.Do(ss.Context(), labels, func(ctx context.Context) {
					log.Tracef("RPC %s starting", info.FullMethod)
					err = handler(srv, ss)
					log.Tracef("RPC %s complete: %v", info.FullMethod, err)
				})
				return
			},
			busy.Stream,
			met.Stream,
			security.Stream,
			vh.Stream,
			elide.Stream,
		),
	)
	reflection.Register(rpc)

	auth.RegisterAuthServer(rpc, ath)
	diag.RegisterDiagsServer(rpc, dia)
	file.RegisterFilesServer(rpc, fls)
	principal.RegisterPrincipalsServer(rpc, prn)
	tenant.RegisterTenantsServer(rpc, tnt)
	token.RegisterTokensServer(rpc, tkn)
	upload.RegisterUploadsServer(rpc, upl)
	vhost.RegisterVHostsServer(rpc, vht)

	// Per https://github.com/grpc/grpc-go/issues/1384, the right way to
	// drain when using ServeHTTP is to shut down the HTTP server and
	// not the GRPC Server.
	return rpc, nil
}

// streamWrapper is a ServerStream with an overridable context.
type streamWrapper struct {
	grpc.ServerStream
	ctx context.Context
}

func (a *streamWrapper) Context() context.Context {
	return a.ctx
}
