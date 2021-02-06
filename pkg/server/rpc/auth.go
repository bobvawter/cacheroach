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
	"fmt"
	"strings"

	"github.com/Mandala/go-log"
	"github.com/bobvawter/cacheroach/api/capabilities"
	"github.com/bobvawter/cacheroach/api/session"
	"github.com/bobvawter/cacheroach/api/token"
	"github.com/bobvawter/cacheroach/pkg/enforcer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// If no rule is defined, require a super-token.
var defaultRule = &capabilities.Rule{Kind: &capabilities.Rule_AuthStatus_{
	AuthStatus: capabilities.Rule_SUPER}}

// AuthInterceptor will examine an incoming RPC request for
// authorization data and decorate the context with a token.Session.
//
// Unauthorized requests will be rejected unless the service
// implementation implements DefaultSession.
type AuthInterceptor struct {
	Enforcer *enforcer.Enforcer
	Logger   *log.Logger
	Tokens   token.TokensServer

	methodRules map[string]*capabilities.Rule
}

// ProvideAuthInterceptor is called by wire.
func ProvideAuthInterceptor(
	logger *log.Logger,
	tokens token.TokensServer,
) (*AuthInterceptor, error) {
	reqs := make(map[string]*capabilities.Rule)

	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		for svcs, i := fd.Services(), 0; i < svcs.Len(); i++ {
			svc := svcs.Get(i)
			for ms, j := svc.Methods(), 0; j < ms.Len(); j++ {
				m := ms.Get(j)
				req := proto.GetExtension(m.Options(), capabilities.E_MethodRule).(*capabilities.Rule)
				if req.ProtoReflect().IsValid() {
					key := fmt.Sprintf("/%s/%s", svc.FullName(), m.Name())
					logger.Tracef("found requirement %s: %s", key, req)
					reqs[key] = req
				}
			}
		}
		return true
	})
	// Make the reflection service public.
	reqs["/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"] =
		&capabilities.Rule{Kind: &capabilities.Rule_AuthStatus_{AuthStatus: capabilities.Rule_PUBLIC}}

	return &AuthInterceptor{
		Logger:      logger,
		Tokens:      tokens,
		methodRules: reqs,
	}, nil
}

// Stream wraps a streaming gRPC call.
func (i *AuthInterceptor) Stream(
	srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler,
) error {
	sn, err := i.get(ss.Context())
	if err != nil {
		return err
	}
	ctx := session.WithSession(ss.Context(), sn)

	rule := i.methodRules[info.FullMethod]
	if rule == nil {
		rule = defaultRule
	}
	ok, err := i.Enforcer.Check(ctx, rule)
	if err != nil {
		return err
	}
	if !ok {
		return status.Error(codes.PermissionDenied, "insufficient scope")
	}
	return handler(srv, &streamWrapper{
		ServerStream: ss,
		ctx:          ctx,
	})
}

// Unary wraps a unary gRPC call.
func (i *AuthInterceptor) Unary(
	ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
) (ret interface{}, err error) {
	sn, err := i.get(ctx)
	if err != nil {
		return nil, err
	}
	ctx = session.WithSession(ctx, sn)
	rule := i.methodRules[info.FullMethod]
	if rule == nil {
		rule = defaultRule
	}
	ok, err := i.Enforcer.Check(ctx, rule)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "insufficient scope")
	}
	return handler(ctx, req)
}

func (i *AuthInterceptor) get(ctx context.Context) (*session.Session, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, nil
	}
	data := md.Get("authorization")
	if len(data) != 1 {
		return nil, nil
	}
	if strings.ToLower(data[0][:7]) != "bearer " {
		return nil, nil
	}
	return i.Tokens.Validate(ctx, &token.Token{Jwt: data[0][7:]})
}
