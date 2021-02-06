// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package token

import (
	context "context"
	session "github.com/bobvawter/cacheroach/api/session"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion7

// TokensClient is the client API for Tokens service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type TokensClient interface {
	// Current returns the Session associated with the current request.
	// This can be used to determine the current principal and scope
	// of access.
	Current(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*session.Session, error)
	// Issue creates an encoded token described by the session template.
	Issue(ctx context.Context, in *IssueRequest, opts ...grpc.CallOption) (*IssueResponse, error)
	// Find returns all valid sessions that are accessible by the
	// principal associated with the current request, using the provided
	// Scope as a filter.
	Find(ctx context.Context, in *session.Scope, opts ...grpc.CallOption) (Tokens_FindClient, error)
	// Load retrieves the given session.
	Load(ctx context.Context, in *LoadRequest, opts ...grpc.CallOption) (*session.Session, error)
	// Invalidate destroys an active token.
	Invalidate(ctx context.Context, in *InvalidateRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	// Refresh invalidates the access token associated with the current
	// request and returns a refreshed token and session.
	Refresh(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*IssueResponse, error)
	// Validate returns the currently-valid session associated with the token.
	Validate(ctx context.Context, in *Token, opts ...grpc.CallOption) (*session.Session, error)
}

type tokensClient struct {
	cc grpc.ClientConnInterface
}

func NewTokensClient(cc grpc.ClientConnInterface) TokensClient {
	return &tokensClient{cc}
}

func (c *tokensClient) Current(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*session.Session, error) {
	out := new(session.Session)
	err := c.cc.Invoke(ctx, "/cacheroach.token.Tokens/Current", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tokensClient) Issue(ctx context.Context, in *IssueRequest, opts ...grpc.CallOption) (*IssueResponse, error) {
	out := new(IssueResponse)
	err := c.cc.Invoke(ctx, "/cacheroach.token.Tokens/Issue", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tokensClient) Find(ctx context.Context, in *session.Scope, opts ...grpc.CallOption) (Tokens_FindClient, error) {
	stream, err := c.cc.NewStream(ctx, &_Tokens_serviceDesc.Streams[0], "/cacheroach.token.Tokens/Find", opts...)
	if err != nil {
		return nil, err
	}
	x := &tokensFindClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type Tokens_FindClient interface {
	Recv() (*session.Session, error)
	grpc.ClientStream
}

type tokensFindClient struct {
	grpc.ClientStream
}

func (x *tokensFindClient) Recv() (*session.Session, error) {
	m := new(session.Session)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *tokensClient) Load(ctx context.Context, in *LoadRequest, opts ...grpc.CallOption) (*session.Session, error) {
	out := new(session.Session)
	err := c.cc.Invoke(ctx, "/cacheroach.token.Tokens/Load", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tokensClient) Invalidate(ctx context.Context, in *InvalidateRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, "/cacheroach.token.Tokens/Invalidate", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tokensClient) Refresh(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*IssueResponse, error) {
	out := new(IssueResponse)
	err := c.cc.Invoke(ctx, "/cacheroach.token.Tokens/Refresh", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tokensClient) Validate(ctx context.Context, in *Token, opts ...grpc.CallOption) (*session.Session, error) {
	out := new(session.Session)
	err := c.cc.Invoke(ctx, "/cacheroach.token.Tokens/Validate", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TokensServer is the server API for Tokens service.
// All implementations must embed UnimplementedTokensServer
// for forward compatibility
type TokensServer interface {
	// Current returns the Session associated with the current request.
	// This can be used to determine the current principal and scope
	// of access.
	Current(context.Context, *emptypb.Empty) (*session.Session, error)
	// Issue creates an encoded token described by the session template.
	Issue(context.Context, *IssueRequest) (*IssueResponse, error)
	// Find returns all valid sessions that are accessible by the
	// principal associated with the current request, using the provided
	// Scope as a filter.
	Find(*session.Scope, Tokens_FindServer) error
	// Load retrieves the given session.
	Load(context.Context, *LoadRequest) (*session.Session, error)
	// Invalidate destroys an active token.
	Invalidate(context.Context, *InvalidateRequest) (*emptypb.Empty, error)
	// Refresh invalidates the access token associated with the current
	// request and returns a refreshed token and session.
	Refresh(context.Context, *emptypb.Empty) (*IssueResponse, error)
	// Validate returns the currently-valid session associated with the token.
	Validate(context.Context, *Token) (*session.Session, error)
	mustEmbedUnimplementedTokensServer()
}

// UnimplementedTokensServer must be embedded to have forward compatible implementations.
type UnimplementedTokensServer struct {
}

func (UnimplementedTokensServer) Current(context.Context, *emptypb.Empty) (*session.Session, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Current not implemented")
}
func (UnimplementedTokensServer) Issue(context.Context, *IssueRequest) (*IssueResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Issue not implemented")
}
func (UnimplementedTokensServer) Find(*session.Scope, Tokens_FindServer) error {
	return status.Errorf(codes.Unimplemented, "method Find not implemented")
}
func (UnimplementedTokensServer) Load(context.Context, *LoadRequest) (*session.Session, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Load not implemented")
}
func (UnimplementedTokensServer) Invalidate(context.Context, *InvalidateRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Invalidate not implemented")
}
func (UnimplementedTokensServer) Refresh(context.Context, *emptypb.Empty) (*IssueResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Refresh not implemented")
}
func (UnimplementedTokensServer) Validate(context.Context, *Token) (*session.Session, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Validate not implemented")
}
func (UnimplementedTokensServer) mustEmbedUnimplementedTokensServer() {}

// UnsafeTokensServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to TokensServer will
// result in compilation errors.
type UnsafeTokensServer interface {
	mustEmbedUnimplementedTokensServer()
}

func RegisterTokensServer(s grpc.ServiceRegistrar, srv TokensServer) {
	s.RegisterService(&_Tokens_serviceDesc, srv)
}

func _Tokens_Current_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(emptypb.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TokensServer).Current(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/cacheroach.token.Tokens/Current",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TokensServer).Current(ctx, req.(*emptypb.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _Tokens_Issue_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(IssueRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TokensServer).Issue(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/cacheroach.token.Tokens/Issue",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TokensServer).Issue(ctx, req.(*IssueRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Tokens_Find_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(session.Scope)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(TokensServer).Find(m, &tokensFindServer{stream})
}

type Tokens_FindServer interface {
	Send(*session.Session) error
	grpc.ServerStream
}

type tokensFindServer struct {
	grpc.ServerStream
}

func (x *tokensFindServer) Send(m *session.Session) error {
	return x.ServerStream.SendMsg(m)
}

func _Tokens_Load_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LoadRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TokensServer).Load(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/cacheroach.token.Tokens/Load",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TokensServer).Load(ctx, req.(*LoadRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Tokens_Invalidate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(InvalidateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TokensServer).Invalidate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/cacheroach.token.Tokens/Invalidate",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TokensServer).Invalidate(ctx, req.(*InvalidateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Tokens_Refresh_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(emptypb.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TokensServer).Refresh(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/cacheroach.token.Tokens/Refresh",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TokensServer).Refresh(ctx, req.(*emptypb.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _Tokens_Validate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Token)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TokensServer).Validate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/cacheroach.token.Tokens/Validate",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TokensServer).Validate(ctx, req.(*Token))
	}
	return interceptor(ctx, in, info, handler)
}

var _Tokens_serviceDesc = grpc.ServiceDesc{
	ServiceName: "cacheroach.token.Tokens",
	HandlerType: (*TokensServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Current",
			Handler:    _Tokens_Current_Handler,
		},
		{
			MethodName: "Issue",
			Handler:    _Tokens_Issue_Handler,
		},
		{
			MethodName: "Load",
			Handler:    _Tokens_Load_Handler,
		},
		{
			MethodName: "Invalidate",
			Handler:    _Tokens_Invalidate_Handler,
		},
		{
			MethodName: "Refresh",
			Handler:    _Tokens_Refresh_Handler,
		},
		{
			MethodName: "Validate",
			Handler:    _Tokens_Validate_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Find",
			Handler:       _Tokens_Find_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "token.proto",
}
