// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.14.0
// source: vhost.proto

package vhost

import (
	tenant "github.com/bobvawter/cacheroach/api/tenant"
	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type VHost struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Vhost    string     `protobuf:"bytes,1,opt,name=vhost,proto3" json:"vhost,omitempty"`
	TenantId *tenant.ID `protobuf:"bytes,2,opt,name=tenant_id,json=tenantId,proto3" json:"tenant_id,omitempty"`
}

func (x *VHost) Reset() {
	*x = VHost{}
	if protoimpl.UnsafeEnabled {
		mi := &file_vhost_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *VHost) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VHost) ProtoMessage() {}

func (x *VHost) ProtoReflect() protoreflect.Message {
	mi := &file_vhost_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VHost.ProtoReflect.Descriptor instead.
func (*VHost) Descriptor() ([]byte, []int) {
	return file_vhost_proto_rawDescGZIP(), []int{0}
}

func (x *VHost) GetVhost() string {
	if x != nil {
		return x.Vhost
	}
	return ""
}

func (x *VHost) GetTenantId() *tenant.ID {
	if x != nil {
		return x.TenantId
	}
	return nil
}

type EnsureRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Vhost  *VHost `protobuf:"bytes,1,opt,name=vhost,proto3" json:"vhost,omitempty"`
	Delete bool   `protobuf:"varint,2,opt,name=delete,proto3" json:"delete,omitempty"`
}

func (x *EnsureRequest) Reset() {
	*x = EnsureRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_vhost_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EnsureRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EnsureRequest) ProtoMessage() {}

func (x *EnsureRequest) ProtoReflect() protoreflect.Message {
	mi := &file_vhost_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EnsureRequest.ProtoReflect.Descriptor instead.
func (*EnsureRequest) Descriptor() ([]byte, []int) {
	return file_vhost_proto_rawDescGZIP(), []int{1}
}

func (x *EnsureRequest) GetVhost() *VHost {
	if x != nil {
		return x.Vhost
	}
	return nil
}

func (x *EnsureRequest) GetDelete() bool {
	if x != nil {
		return x.Delete
	}
	return false
}

var File_vhost_proto protoreflect.FileDescriptor

var file_vhost_proto_rawDesc = []byte{
	0x0a, 0x0b, 0x76, 0x68, 0x6f, 0x73, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x10, 0x63,
	0x61, 0x63, 0x68, 0x65, 0x72, 0x6f, 0x61, 0x63, 0x68, 0x2e, 0x76, 0x68, 0x6f, 0x73, 0x74, 0x1a,
	0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2f, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0c, 0x74, 0x65,
	0x6e, 0x61, 0x6e, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x51, 0x0a, 0x05, 0x56, 0x48,
	0x6f, 0x73, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x68, 0x6f, 0x73, 0x74, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x05, 0x76, 0x68, 0x6f, 0x73, 0x74, 0x12, 0x32, 0x0a, 0x09, 0x74, 0x65, 0x6e,
	0x61, 0x6e, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x15, 0x2e, 0x63,
	0x61, 0x63, 0x68, 0x65, 0x72, 0x6f, 0x61, 0x63, 0x68, 0x2e, 0x74, 0x65, 0x6e, 0x61, 0x6e, 0x74,
	0x2e, 0x49, 0x44, 0x52, 0x08, 0x74, 0x65, 0x6e, 0x61, 0x6e, 0x74, 0x49, 0x64, 0x22, 0x56, 0x0a,
	0x0d, 0x45, 0x6e, 0x73, 0x75, 0x72, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x2d,
	0x0a, 0x05, 0x76, 0x68, 0x6f, 0x73, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e,
	0x63, 0x61, 0x63, 0x68, 0x65, 0x72, 0x6f, 0x61, 0x63, 0x68, 0x2e, 0x76, 0x68, 0x6f, 0x73, 0x74,
	0x2e, 0x56, 0x48, 0x6f, 0x73, 0x74, 0x52, 0x05, 0x76, 0x68, 0x6f, 0x73, 0x74, 0x12, 0x16, 0x0a,
	0x06, 0x64, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x06, 0x64,
	0x65, 0x6c, 0x65, 0x74, 0x65, 0x32, 0x90, 0x01, 0x0a, 0x06, 0x56, 0x48, 0x6f, 0x73, 0x74, 0x73,
	0x12, 0x46, 0x0a, 0x06, 0x45, 0x6e, 0x73, 0x75, 0x72, 0x65, 0x12, 0x1f, 0x2e, 0x63, 0x61, 0x63,
	0x68, 0x65, 0x72, 0x6f, 0x61, 0x63, 0x68, 0x2e, 0x76, 0x68, 0x6f, 0x73, 0x74, 0x2e, 0x45, 0x6e,
	0x73, 0x75, 0x72, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x16, 0x2e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d,
	0x70, 0x74, 0x79, 0x22, 0x03, 0x90, 0x02, 0x02, 0x12, 0x3e, 0x0a, 0x04, 0x4c, 0x69, 0x73, 0x74,
	0x12, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x17, 0x2e, 0x63, 0x61, 0x63, 0x68, 0x65,
	0x72, 0x6f, 0x61, 0x63, 0x68, 0x2e, 0x76, 0x68, 0x6f, 0x73, 0x74, 0x2e, 0x56, 0x48, 0x6f, 0x73,
	0x74, 0x22, 0x03, 0x90, 0x02, 0x01, 0x30, 0x01, 0x42, 0x2b, 0x5a, 0x29, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x62, 0x6f, 0x62, 0x76, 0x61, 0x77, 0x74, 0x65, 0x72,
	0x2f, 0x63, 0x61, 0x63, 0x68, 0x65, 0x72, 0x6f, 0x61, 0x63, 0x68, 0x2f, 0x61, 0x70, 0x69, 0x2f,
	0x76, 0x68, 0x6f, 0x73, 0x74, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_vhost_proto_rawDescOnce sync.Once
	file_vhost_proto_rawDescData = file_vhost_proto_rawDesc
)

func file_vhost_proto_rawDescGZIP() []byte {
	file_vhost_proto_rawDescOnce.Do(func() {
		file_vhost_proto_rawDescData = protoimpl.X.CompressGZIP(file_vhost_proto_rawDescData)
	})
	return file_vhost_proto_rawDescData
}

var file_vhost_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_vhost_proto_goTypes = []interface{}{
	(*VHost)(nil),         // 0: cacheroach.vhost.VHost
	(*EnsureRequest)(nil), // 1: cacheroach.vhost.EnsureRequest
	(*tenant.ID)(nil),     // 2: cacheroach.tenant.ID
	(*emptypb.Empty)(nil), // 3: google.protobuf.Empty
}
var file_vhost_proto_depIdxs = []int32{
	2, // 0: cacheroach.vhost.VHost.tenant_id:type_name -> cacheroach.tenant.ID
	0, // 1: cacheroach.vhost.EnsureRequest.vhost:type_name -> cacheroach.vhost.VHost
	1, // 2: cacheroach.vhost.VHosts.Ensure:input_type -> cacheroach.vhost.EnsureRequest
	3, // 3: cacheroach.vhost.VHosts.List:input_type -> google.protobuf.Empty
	3, // 4: cacheroach.vhost.VHosts.Ensure:output_type -> google.protobuf.Empty
	0, // 5: cacheroach.vhost.VHosts.List:output_type -> cacheroach.vhost.VHost
	4, // [4:6] is the sub-list for method output_type
	2, // [2:4] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_vhost_proto_init() }
func file_vhost_proto_init() {
	if File_vhost_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_vhost_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*VHost); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_vhost_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EnsureRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_vhost_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_vhost_proto_goTypes,
		DependencyIndexes: file_vhost_proto_depIdxs,
		MessageInfos:      file_vhost_proto_msgTypes,
	}.Build()
	File_vhost_proto = out.File
	file_vhost_proto_rawDesc = nil
	file_vhost_proto_goTypes = nil
	file_vhost_proto_depIdxs = nil
}
