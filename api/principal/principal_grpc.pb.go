// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package principal

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion7

// PrincipalsClient is the client API for Principals service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type PrincipalsClient interface {
	Ensure(ctx context.Context, in *EnsureRequest, opts ...grpc.CallOption) (*EnsureResponse, error)
	List(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (Principals_ListClient, error)
	Load(ctx context.Context, in *ID, opts ...grpc.CallOption) (*Principal, error)
	Watch(ctx context.Context, in *WatchRequest, opts ...grpc.CallOption) (Principals_WatchClient, error)
}

type principalsClient struct {
	cc grpc.ClientConnInterface
}

func NewPrincipalsClient(cc grpc.ClientConnInterface) PrincipalsClient {
	return &principalsClient{cc}
}

func (c *principalsClient) Ensure(ctx context.Context, in *EnsureRequest, opts ...grpc.CallOption) (*EnsureResponse, error) {
	out := new(EnsureResponse)
	err := c.cc.Invoke(ctx, "/cacheroach.principal.Principals/Ensure", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *principalsClient) List(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (Principals_ListClient, error) {
	stream, err := c.cc.NewStream(ctx, &_Principals_serviceDesc.Streams[0], "/cacheroach.principal.Principals/List", opts...)
	if err != nil {
		return nil, err
	}
	x := &principalsListClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type Principals_ListClient interface {
	Recv() (*Principal, error)
	grpc.ClientStream
}

type principalsListClient struct {
	grpc.ClientStream
}

func (x *principalsListClient) Recv() (*Principal, error) {
	m := new(Principal)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *principalsClient) Load(ctx context.Context, in *ID, opts ...grpc.CallOption) (*Principal, error) {
	out := new(Principal)
	err := c.cc.Invoke(ctx, "/cacheroach.principal.Principals/Load", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *principalsClient) Watch(ctx context.Context, in *WatchRequest, opts ...grpc.CallOption) (Principals_WatchClient, error) {
	stream, err := c.cc.NewStream(ctx, &_Principals_serviceDesc.Streams[1], "/cacheroach.principal.Principals/Watch", opts...)
	if err != nil {
		return nil, err
	}
	x := &principalsWatchClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type Principals_WatchClient interface {
	Recv() (*Principal, error)
	grpc.ClientStream
}

type principalsWatchClient struct {
	grpc.ClientStream
}

func (x *principalsWatchClient) Recv() (*Principal, error) {
	m := new(Principal)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// PrincipalsServer is the server API for Principals service.
// All implementations must embed UnimplementedPrincipalsServer
// for forward compatibility
type PrincipalsServer interface {
	Ensure(context.Context, *EnsureRequest) (*EnsureResponse, error)
	List(*emptypb.Empty, Principals_ListServer) error
	Load(context.Context, *ID) (*Principal, error)
	Watch(*WatchRequest, Principals_WatchServer) error
	mustEmbedUnimplementedPrincipalsServer()
}

// UnimplementedPrincipalsServer must be embedded to have forward compatible implementations.
type UnimplementedPrincipalsServer struct {
}

func (UnimplementedPrincipalsServer) Ensure(context.Context, *EnsureRequest) (*EnsureResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Ensure not implemented")
}
func (UnimplementedPrincipalsServer) List(*emptypb.Empty, Principals_ListServer) error {
	return status.Errorf(codes.Unimplemented, "method List not implemented")
}
func (UnimplementedPrincipalsServer) Load(context.Context, *ID) (*Principal, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Load not implemented")
}
func (UnimplementedPrincipalsServer) Watch(*WatchRequest, Principals_WatchServer) error {
	return status.Errorf(codes.Unimplemented, "method Watch not implemented")
}
func (UnimplementedPrincipalsServer) mustEmbedUnimplementedPrincipalsServer() {}

// UnsafePrincipalsServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to PrincipalsServer will
// result in compilation errors.
type UnsafePrincipalsServer interface {
	mustEmbedUnimplementedPrincipalsServer()
}

func RegisterPrincipalsServer(s grpc.ServiceRegistrar, srv PrincipalsServer) {
	s.RegisterService(&_Principals_serviceDesc, srv)
}

func _Principals_Ensure_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(EnsureRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PrincipalsServer).Ensure(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/cacheroach.principal.Principals/Ensure",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PrincipalsServer).Ensure(ctx, req.(*EnsureRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Principals_List_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(emptypb.Empty)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(PrincipalsServer).List(m, &principalsListServer{stream})
}

type Principals_ListServer interface {
	Send(*Principal) error
	grpc.ServerStream
}

type principalsListServer struct {
	grpc.ServerStream
}

func (x *principalsListServer) Send(m *Principal) error {
	return x.ServerStream.SendMsg(m)
}

func _Principals_Load_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ID)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PrincipalsServer).Load(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/cacheroach.principal.Principals/Load",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PrincipalsServer).Load(ctx, req.(*ID))
	}
	return interceptor(ctx, in, info, handler)
}

func _Principals_Watch_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(WatchRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(PrincipalsServer).Watch(m, &principalsWatchServer{stream})
}

type Principals_WatchServer interface {
	Send(*Principal) error
	grpc.ServerStream
}

type principalsWatchServer struct {
	grpc.ServerStream
}

func (x *principalsWatchServer) Send(m *Principal) error {
	return x.ServerStream.SendMsg(m)
}

var _Principals_serviceDesc = grpc.ServiceDesc{
	ServiceName: "cacheroach.principal.Principals",
	HandlerType: (*PrincipalsServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Ensure",
			Handler:    _Principals_Ensure_Handler,
		},
		{
			MethodName: "Load",
			Handler:    _Principals_Load_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "List",
			Handler:       _Principals_List_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "Watch",
			Handler:       _Principals_Watch_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "principal.proto",
}
