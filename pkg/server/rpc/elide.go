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

	"github.com/bobvawter/cacheroach/api/capabilities"
	"github.com/bobvawter/cacheroach/pkg/enforcer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type streamElider struct {
	grpc.ServerStream
	Enforcer *enforcer.Enforcer
}

func (e *streamElider) RecvMsg(m interface{}) error {
	if err := e.ServerStream.RecvMsg(m); err != nil {
		return err
	}
	if msg, ok := m.(proto.Message); ok {
		ok, err := e.Enforcer.Enforce(e.Context(), capabilities.Direction_REQUEST,
			protoreflect.ValueOf(msg.ProtoReflect()))
		if err != nil {
			return err
		}
		if !ok {
			return status.Error(codes.PermissionDenied, "inappropriate fields in request")
		}
	}
	return nil
}

func (e *streamElider) SendMsg(x interface{}) error {
	// We expect this to always be the case.
	msg, ok := x.(proto.Message)
	if !ok {
		return e.ServerStream.SendMsg(msg)
	}
	allow, err := e.Enforcer.Enforce(
		e.Context(),
		capabilities.Direction_RESPONSE,
		protoreflect.ValueOf(msg.ProtoReflect()))
	if err != nil {
		return err
	}
	if !allow {
		return nil
	}
	return e.ServerStream.SendMsg(x)
}

// ElideInterceptor provides services for eliding marked message fields.
type ElideInterceptor struct {
	Enforcer *enforcer.Enforcer
}

// Stream wraps a streaming gRPC call.
func (i *ElideInterceptor) Stream(
	srv interface{}, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler,
) error {
	ss = &streamElider{ss, i.Enforcer}
	return handler(srv, ss)
}

// Unary wraps a unary gRPC call.
func (i *ElideInterceptor) Unary(
	ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
) (interface{}, error) {
	if msg, ok := req.(proto.Message); ok {
		ok, err := i.Enforcer.Enforce(ctx, capabilities.Direction_REQUEST,
			protoreflect.ValueOf(msg.ProtoReflect()))
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, status.Error(codes.PermissionDenied, "inappropriate fields in request")
		}
	}

	ret, err := handler(ctx, req)
	if err != nil {
		return nil, err
	}
	if msg, ok := ret.(proto.Message); ok {
		i.Enforcer.Enforce(ctx, capabilities.Direction_RESPONSE, protoreflect.ValueOf(msg.ProtoReflect()))
	}
	return ret, nil
}
