// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package vhost

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

// VHostsClient is the client API for VHosts service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type VHostsClient interface {
	Ensure(ctx context.Context, in *EnsureRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	List(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (VHosts_ListClient, error)
}

type vHostsClient struct {
	cc grpc.ClientConnInterface
}

func NewVHostsClient(cc grpc.ClientConnInterface) VHostsClient {
	return &vHostsClient{cc}
}

func (c *vHostsClient) Ensure(ctx context.Context, in *EnsureRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, "/cacheroach.vhost.VHosts/Ensure", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *vHostsClient) List(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (VHosts_ListClient, error) {
	stream, err := c.cc.NewStream(ctx, &_VHosts_serviceDesc.Streams[0], "/cacheroach.vhost.VHosts/List", opts...)
	if err != nil {
		return nil, err
	}
	x := &vHostsListClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type VHosts_ListClient interface {
	Recv() (*VHost, error)
	grpc.ClientStream
}

type vHostsListClient struct {
	grpc.ClientStream
}

func (x *vHostsListClient) Recv() (*VHost, error) {
	m := new(VHost)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// VHostsServer is the server API for VHosts service.
// All implementations must embed UnimplementedVHostsServer
// for forward compatibility
type VHostsServer interface {
	Ensure(context.Context, *EnsureRequest) (*emptypb.Empty, error)
	List(*emptypb.Empty, VHosts_ListServer) error
	mustEmbedUnimplementedVHostsServer()
}

// UnimplementedVHostsServer must be embedded to have forward compatible implementations.
type UnimplementedVHostsServer struct {
}

func (UnimplementedVHostsServer) Ensure(context.Context, *EnsureRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Ensure not implemented")
}
func (UnimplementedVHostsServer) List(*emptypb.Empty, VHosts_ListServer) error {
	return status.Errorf(codes.Unimplemented, "method List not implemented")
}
func (UnimplementedVHostsServer) mustEmbedUnimplementedVHostsServer() {}

// UnsafeVHostsServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to VHostsServer will
// result in compilation errors.
type UnsafeVHostsServer interface {
	mustEmbedUnimplementedVHostsServer()
}

func RegisterVHostsServer(s grpc.ServiceRegistrar, srv VHostsServer) {
	s.RegisterService(&_VHosts_serviceDesc, srv)
}

func _VHosts_Ensure_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(EnsureRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(VHostsServer).Ensure(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/cacheroach.vhost.VHosts/Ensure",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(VHostsServer).Ensure(ctx, req.(*EnsureRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _VHosts_List_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(emptypb.Empty)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(VHostsServer).List(m, &vHostsListServer{stream})
}

type VHosts_ListServer interface {
	Send(*VHost) error
	grpc.ServerStream
}

type vHostsListServer struct {
	grpc.ServerStream
}

func (x *vHostsListServer) Send(m *VHost) error {
	return x.ServerStream.SendMsg(m)
}

var _VHosts_serviceDesc = grpc.ServiceDesc{
	ServiceName: "cacheroach.vhost.VHosts",
	HandlerType: (*VHostsServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Ensure",
			Handler:    _VHosts_Ensure_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "List",
			Handler:       _VHosts_List_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "vhost.proto",
}
