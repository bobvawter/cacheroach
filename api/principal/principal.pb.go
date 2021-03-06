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

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.14.0
// source: principal.proto

package principal

import (
	_ "github.com/bobvawter/cacheroach/api/capabilities"
	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	durationpb "google.golang.org/protobuf/types/known/durationpb"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
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

type TokenStatus int32

const (
	// The token has not (yet) been validated.
	TokenStatus_UNKNOWN TokenStatus = 0
	// The token should be considered valid until the refresh_after time.
	TokenStatus_VALID TokenStatus = 1
	// The token is being refreshed by another instance.  It should be
	// considered valid until the listed refresh time, at which point it
	// should be refreshed again.
	TokenStatus_REFRESHING TokenStatus = 2
	// The token could not be revalidated and no further attempts should
	// be made.
	TokenStatus_PERMANENT_FAILURE TokenStatus = 3
)

// Enum value maps for TokenStatus.
var (
	TokenStatus_name = map[int32]string{
		0: "UNKNOWN",
		1: "VALID",
		2: "REFRESHING",
		3: "PERMANENT_FAILURE",
	}
	TokenStatus_value = map[string]int32{
		"UNKNOWN":           0,
		"VALID":             1,
		"REFRESHING":        2,
		"PERMANENT_FAILURE": 3,
	}
)

func (x TokenStatus) Enum() *TokenStatus {
	p := new(TokenStatus)
	*p = x
	return p
}

func (x TokenStatus) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (TokenStatus) Descriptor() protoreflect.EnumDescriptor {
	return file_principal_proto_enumTypes[0].Descriptor()
}

func (TokenStatus) Type() protoreflect.EnumType {
	return &file_principal_proto_enumTypes[0]
}

func (x TokenStatus) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use TokenStatus.Descriptor instead.
func (TokenStatus) EnumDescriptor() ([]byte, []int) {
	return file_principal_proto_rawDescGZIP(), []int{0}
}

type ID struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Data []byte `protobuf:"bytes,1,opt,name=data,proto3" json:"data,omitempty"`
}

func (x *ID) Reset() {
	*x = ID{}
	if protoimpl.UnsafeEnabled {
		mi := &file_principal_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ID) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ID) ProtoMessage() {}

func (x *ID) ProtoReflect() protoreflect.Message {
	mi := &file_principal_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ID.ProtoReflect.Descriptor instead.
func (*ID) Descriptor() ([]byte, []int) {
	return file_principal_proto_rawDescGZIP(), []int{0}
}

func (x *ID) GetData() []byte {
	if x != nil {
		return x.Data
	}
	return nil
}

type Principal struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ID      *ID    `protobuf:"bytes,1,opt,name=ID,proto3" json:"ID,omitempty"`
	Label   string `protobuf:"bytes,2,opt,name=label,proto3" json:"label,omitempty"`
	Version int64  `protobuf:"varint,3,opt,name=version,proto3" json:"version,omitempty"`
	// OIDC claims as provided by an authentication server.
	Claims []byte `protobuf:"bytes,4,opt,name=claims,proto3" json:"claims,omitempty"`
	// If present, indicates that the principal represents all users whose
	// email address are in the given domain.
	EmailDomain   string                 `protobuf:"bytes,5,opt,name=email_domain,json=emailDomain,proto3" json:"email_domain,omitempty"`
	RefreshToken  string                 `protobuf:"bytes,66,opt,name=refresh_token,json=refreshToken,proto3" json:"refresh_token,omitempty"`
	RefreshAfter  *timestamppb.Timestamp `protobuf:"bytes,67,opt,name=refresh_after,json=refreshAfter,proto3" json:"refresh_after,omitempty"`
	RefreshStatus TokenStatus            `protobuf:"varint,68,opt,name=refresh_status,json=refreshStatus,proto3,enum=cacheroach.principal.TokenStatus" json:"refresh_status,omitempty"`
}

func (x *Principal) Reset() {
	*x = Principal{}
	if protoimpl.UnsafeEnabled {
		mi := &file_principal_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Principal) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Principal) ProtoMessage() {}

func (x *Principal) ProtoReflect() protoreflect.Message {
	mi := &file_principal_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Principal.ProtoReflect.Descriptor instead.
func (*Principal) Descriptor() ([]byte, []int) {
	return file_principal_proto_rawDescGZIP(), []int{1}
}

func (x *Principal) GetID() *ID {
	if x != nil {
		return x.ID
	}
	return nil
}

func (x *Principal) GetLabel() string {
	if x != nil {
		return x.Label
	}
	return ""
}

func (x *Principal) GetVersion() int64 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *Principal) GetClaims() []byte {
	if x != nil {
		return x.Claims
	}
	return nil
}

func (x *Principal) GetEmailDomain() string {
	if x != nil {
		return x.EmailDomain
	}
	return ""
}

func (x *Principal) GetRefreshToken() string {
	if x != nil {
		return x.RefreshToken
	}
	return ""
}

func (x *Principal) GetRefreshAfter() *timestamppb.Timestamp {
	if x != nil {
		return x.RefreshAfter
	}
	return nil
}

func (x *Principal) GetRefreshStatus() TokenStatus {
	if x != nil {
		return x.RefreshStatus
	}
	return TokenStatus_UNKNOWN
}

type LoadRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Kind:
	//	*LoadRequest_ID
	//	*LoadRequest_Email
	//	*LoadRequest_EmailDomain
	Kind isLoadRequest_Kind `protobuf_oneof:"Kind"`
}

func (x *LoadRequest) Reset() {
	*x = LoadRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_principal_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LoadRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LoadRequest) ProtoMessage() {}

func (x *LoadRequest) ProtoReflect() protoreflect.Message {
	mi := &file_principal_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LoadRequest.ProtoReflect.Descriptor instead.
func (*LoadRequest) Descriptor() ([]byte, []int) {
	return file_principal_proto_rawDescGZIP(), []int{2}
}

func (m *LoadRequest) GetKind() isLoadRequest_Kind {
	if m != nil {
		return m.Kind
	}
	return nil
}

func (x *LoadRequest) GetID() *ID {
	if x, ok := x.GetKind().(*LoadRequest_ID); ok {
		return x.ID
	}
	return nil
}

func (x *LoadRequest) GetEmail() string {
	if x, ok := x.GetKind().(*LoadRequest_Email); ok {
		return x.Email
	}
	return ""
}

func (x *LoadRequest) GetEmailDomain() string {
	if x, ok := x.GetKind().(*LoadRequest_EmailDomain); ok {
		return x.EmailDomain
	}
	return ""
}

type isLoadRequest_Kind interface {
	isLoadRequest_Kind()
}

type LoadRequest_ID struct {
	// Load a Principal based on ID.
	ID *ID `protobuf:"bytes,1,opt,name=ID,proto3,oneof"`
}

type LoadRequest_Email struct {
	// Load a Principal by email address.
	Email string `protobuf:"bytes,2,opt,name=email,proto3,oneof"`
}

type LoadRequest_EmailDomain struct {
	// Load a domain-level Principal.
	EmailDomain string `protobuf:"bytes,3,opt,name=email_domain,json=emailDomain,proto3,oneof"`
}

func (*LoadRequest_ID) isLoadRequest_Kind() {}

func (*LoadRequest_Email) isLoadRequest_Kind() {}

func (*LoadRequest_EmailDomain) isLoadRequest_Kind() {}

type WatchRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Principal *ID                  `protobuf:"bytes,1,opt,name=principal,proto3" json:"principal,omitempty"`
	Duration  *durationpb.Duration `protobuf:"bytes,2,opt,name=duration,proto3" json:"duration,omitempty"`
}

func (x *WatchRequest) Reset() {
	*x = WatchRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_principal_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *WatchRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*WatchRequest) ProtoMessage() {}

func (x *WatchRequest) ProtoReflect() protoreflect.Message {
	mi := &file_principal_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use WatchRequest.ProtoReflect.Descriptor instead.
func (*WatchRequest) Descriptor() ([]byte, []int) {
	return file_principal_proto_rawDescGZIP(), []int{3}
}

func (x *WatchRequest) GetPrincipal() *ID {
	if x != nil {
		return x.Principal
	}
	return nil
}

func (x *WatchRequest) GetDuration() *durationpb.Duration {
	if x != nil {
		return x.Duration
	}
	return nil
}

type EnsureRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Principal *Principal `protobuf:"bytes,1,opt,name=principal,proto3" json:"principal,omitempty"`
	Delete    bool       `protobuf:"varint,2,opt,name=delete,proto3" json:"delete,omitempty"`
}

func (x *EnsureRequest) Reset() {
	*x = EnsureRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_principal_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EnsureRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EnsureRequest) ProtoMessage() {}

func (x *EnsureRequest) ProtoReflect() protoreflect.Message {
	mi := &file_principal_proto_msgTypes[4]
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
	return file_principal_proto_rawDescGZIP(), []int{4}
}

func (x *EnsureRequest) GetPrincipal() *Principal {
	if x != nil {
		return x.Principal
	}
	return nil
}

func (x *EnsureRequest) GetDelete() bool {
	if x != nil {
		return x.Delete
	}
	return false
}

type EnsureResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Principal *Principal `protobuf:"bytes,1,opt,name=principal,proto3" json:"principal,omitempty"`
}

func (x *EnsureResponse) Reset() {
	*x = EnsureResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_principal_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EnsureResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EnsureResponse) ProtoMessage() {}

func (x *EnsureResponse) ProtoReflect() protoreflect.Message {
	mi := &file_principal_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EnsureResponse.ProtoReflect.Descriptor instead.
func (*EnsureResponse) Descriptor() ([]byte, []int) {
	return file_principal_proto_rawDescGZIP(), []int{5}
}

func (x *EnsureResponse) GetPrincipal() *Principal {
	if x != nil {
		return x.Principal
	}
	return nil
}

var File_principal_proto protoreflect.FileDescriptor

var file_principal_proto_rawDesc = []byte{
	0x0a, 0x0f, 0x70, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x14, 0x63, 0x61, 0x63, 0x68, 0x65, 0x72, 0x6f, 0x61, 0x63, 0x68, 0x2e, 0x70, 0x72,
	0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x1a, 0x12, 0x63, 0x61, 0x70, 0x61, 0x62, 0x69, 0x6c,
	0x69, 0x74, 0x69, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x64, 0x75, 0x72,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1b, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d, 0x70,
	0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74,
	0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x18, 0x0a, 0x02, 0x49, 0x44, 0x12,
	0x12, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x64,
	0x61, 0x74, 0x61, 0x22, 0xe6, 0x03, 0x0a, 0x09, 0x50, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61,
	0x6c, 0x12, 0x28, 0x0a, 0x02, 0x49, 0x44, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e,
	0x63, 0x61, 0x63, 0x68, 0x65, 0x72, 0x6f, 0x61, 0x63, 0x68, 0x2e, 0x70, 0x72, 0x69, 0x6e, 0x63,
	0x69, 0x70, 0x61, 0x6c, 0x2e, 0x49, 0x44, 0x52, 0x02, 0x49, 0x44, 0x12, 0x14, 0x0a, 0x05, 0x6c,
	0x61, 0x62, 0x65, 0x6c, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6c, 0x61, 0x62, 0x65,
	0x6c, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x03, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x56, 0x0a, 0x06, 0x63,
	0x6c, 0x61, 0x69, 0x6d, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x42, 0x3e, 0x9a, 0xf5, 0x1a,
	0x3a, 0x2a, 0x22, 0x0a, 0x0a, 0x22, 0x08, 0x0a, 0x02, 0x40, 0x01, 0x0a, 0x02, 0x30, 0x02, 0x0a,
	0x14, 0x22, 0x12, 0x0a, 0x02, 0x40, 0x02, 0x0a, 0x0c, 0x3a, 0x0a, 0x12, 0x02, 0x20, 0x01, 0x22,
	0x04, 0x12, 0x02, 0x10, 0x01, 0x7a, 0x14, 0x6d, 0x75, 0x73, 0x74, 0x20, 0x68, 0x61, 0x76, 0x65,
	0x20, 0x70, 0x69, 0x69, 0x20, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x52, 0x06, 0x63, 0x6c, 0x61,
	0x69, 0x6d, 0x73, 0x12, 0x21, 0x0a, 0x0c, 0x65, 0x6d, 0x61, 0x69, 0x6c, 0x5f, 0x64, 0x6f, 0x6d,
	0x61, 0x69, 0x6e, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x65, 0x6d, 0x61, 0x69, 0x6c,
	0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x12, 0x2b, 0x0a, 0x0d, 0x72, 0x65, 0x66, 0x72, 0x65, 0x73,
	0x68, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x42, 0x20, 0x01, 0x28, 0x09, 0x42, 0x06, 0x9a,
	0xf5, 0x1a, 0x02, 0x18, 0x01, 0x52, 0x0c, 0x72, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x54, 0x6f,
	0x6b, 0x65, 0x6e, 0x12, 0x47, 0x0a, 0x0d, 0x72, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x5f, 0x61,
	0x66, 0x74, 0x65, 0x72, 0x18, 0x43, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x42, 0x06, 0x9a, 0xf5, 0x1a, 0x02, 0x18, 0x01, 0x52, 0x0c,
	0x72, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x41, 0x66, 0x74, 0x65, 0x72, 0x12, 0x50, 0x0a, 0x0e,
	0x72, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x44,
	0x20, 0x01, 0x28, 0x0e, 0x32, 0x21, 0x2e, 0x63, 0x61, 0x63, 0x68, 0x65, 0x72, 0x6f, 0x61, 0x63,
	0x68, 0x2e, 0x70, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x2e, 0x54, 0x6f, 0x6b, 0x65,
	0x6e, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x42, 0x06, 0x9a, 0xf5, 0x1a, 0x02, 0x18, 0x01, 0x52,
	0x0d, 0x72, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x3a, 0x3c,
	0x9a, 0xf5, 0x1a, 0x38, 0x2a, 0x36, 0x0a, 0x02, 0x40, 0x02, 0x0a, 0x30, 0x3a, 0x0a, 0x12, 0x02,
	0x08, 0x01, 0x22, 0x04, 0x12, 0x02, 0x10, 0x01, 0x7a, 0x22, 0x6d, 0x75, 0x73, 0x74, 0x20, 0x62,
	0x65, 0x20, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x72, 0x65, 0x61, 0x64, 0x20, 0x74,
	0x68, 0x65, 0x20, 0x70, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x22, 0x7e, 0x0a, 0x0b,
	0x4c, 0x6f, 0x61, 0x64, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x2a, 0x0a, 0x02, 0x49,
	0x44, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x63, 0x61, 0x63, 0x68, 0x65, 0x72,
	0x6f, 0x61, 0x63, 0x68, 0x2e, 0x70, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x2e, 0x49,
	0x44, 0x48, 0x00, 0x52, 0x02, 0x49, 0x44, 0x12, 0x16, 0x0a, 0x05, 0x65, 0x6d, 0x61, 0x69, 0x6c,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x05, 0x65, 0x6d, 0x61, 0x69, 0x6c, 0x12,
	0x23, 0x0a, 0x0c, 0x65, 0x6d, 0x61, 0x69, 0x6c, 0x5f, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x0b, 0x65, 0x6d, 0x61, 0x69, 0x6c, 0x44, 0x6f,
	0x6d, 0x61, 0x69, 0x6e, 0x42, 0x06, 0x0a, 0x04, 0x4b, 0x69, 0x6e, 0x64, 0x22, 0x7d, 0x0a, 0x0c,
	0x57, 0x61, 0x74, 0x63, 0x68, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x36, 0x0a, 0x09,
	0x70, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x18, 0x2e, 0x63, 0x61, 0x63, 0x68, 0x65, 0x72, 0x6f, 0x61, 0x63, 0x68, 0x2e, 0x70, 0x72, 0x69,
	0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x2e, 0x49, 0x44, 0x52, 0x09, 0x70, 0x72, 0x69, 0x6e, 0x63,
	0x69, 0x70, 0x61, 0x6c, 0x12, 0x35, 0x0a, 0x08, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x44, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x52, 0x08, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x66, 0x0a, 0x0d, 0x45,
	0x6e, 0x73, 0x75, 0x72, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x3d, 0x0a, 0x09,
	0x70, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1f, 0x2e, 0x63, 0x61, 0x63, 0x68, 0x65, 0x72, 0x6f, 0x61, 0x63, 0x68, 0x2e, 0x70, 0x72, 0x69,
	0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x2e, 0x50, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c,
	0x52, 0x09, 0x70, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x12, 0x16, 0x0a, 0x06, 0x64,
	0x65, 0x6c, 0x65, 0x74, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x06, 0x64, 0x65, 0x6c,
	0x65, 0x74, 0x65, 0x22, 0x4f, 0x0a, 0x0e, 0x45, 0x6e, 0x73, 0x75, 0x72, 0x65, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x3d, 0x0a, 0x09, 0x70, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70,
	0x61, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x63, 0x61, 0x63, 0x68, 0x65,
	0x72, 0x6f, 0x61, 0x63, 0x68, 0x2e, 0x70, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x2e,
	0x50, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x52, 0x09, 0x70, 0x72, 0x69, 0x6e, 0x63,
	0x69, 0x70, 0x61, 0x6c, 0x2a, 0x4c, 0x0a, 0x0b, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x53, 0x74, 0x61,
	0x74, 0x75, 0x73, 0x12, 0x0b, 0x0a, 0x07, 0x55, 0x4e, 0x4b, 0x4e, 0x4f, 0x57, 0x4e, 0x10, 0x00,
	0x12, 0x09, 0x0a, 0x05, 0x56, 0x41, 0x4c, 0x49, 0x44, 0x10, 0x01, 0x12, 0x0e, 0x0a, 0x0a, 0x52,
	0x45, 0x46, 0x52, 0x45, 0x53, 0x48, 0x49, 0x4e, 0x47, 0x10, 0x02, 0x12, 0x15, 0x0a, 0x11, 0x50,
	0x45, 0x52, 0x4d, 0x41, 0x4e, 0x45, 0x4e, 0x54, 0x5f, 0x46, 0x41, 0x49, 0x4c, 0x55, 0x52, 0x45,
	0x10, 0x03, 0x32, 0xda, 0x02, 0x0a, 0x0a, 0x50, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c,
	0x73, 0x12, 0x58, 0x0a, 0x06, 0x45, 0x6e, 0x73, 0x75, 0x72, 0x65, 0x12, 0x23, 0x2e, 0x63, 0x61,
	0x63, 0x68, 0x65, 0x72, 0x6f, 0x61, 0x63, 0x68, 0x2e, 0x70, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70,
	0x61, 0x6c, 0x2e, 0x45, 0x6e, 0x73, 0x75, 0x72, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x1a, 0x24, 0x2e, 0x63, 0x61, 0x63, 0x68, 0x65, 0x72, 0x6f, 0x61, 0x63, 0x68, 0x2e, 0x70, 0x72,
	0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x2e, 0x45, 0x6e, 0x73, 0x75, 0x72, 0x65, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x03, 0x90, 0x02, 0x02, 0x12, 0x46, 0x0a, 0x04, 0x4c,
	0x69, 0x73, 0x74, 0x12, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x1f, 0x2e, 0x63, 0x61,
	0x63, 0x68, 0x65, 0x72, 0x6f, 0x61, 0x63, 0x68, 0x2e, 0x70, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70,
	0x61, 0x6c, 0x2e, 0x50, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x22, 0x03, 0x90, 0x02,
	0x01, 0x30, 0x01, 0x12, 0x55, 0x0a, 0x04, 0x4c, 0x6f, 0x61, 0x64, 0x12, 0x21, 0x2e, 0x63, 0x61,
	0x63, 0x68, 0x65, 0x72, 0x6f, 0x61, 0x63, 0x68, 0x2e, 0x70, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70,
	0x61, 0x6c, 0x2e, 0x4c, 0x6f, 0x61, 0x64, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1f,
	0x2e, 0x63, 0x61, 0x63, 0x68, 0x65, 0x72, 0x6f, 0x61, 0x63, 0x68, 0x2e, 0x70, 0x72, 0x69, 0x6e,
	0x63, 0x69, 0x70, 0x61, 0x6c, 0x2e, 0x50, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x22,
	0x09, 0x90, 0x02, 0x01, 0x9a, 0xf5, 0x1a, 0x02, 0x30, 0x00, 0x12, 0x53, 0x0a, 0x05, 0x57, 0x61,
	0x74, 0x63, 0x68, 0x12, 0x22, 0x2e, 0x63, 0x61, 0x63, 0x68, 0x65, 0x72, 0x6f, 0x61, 0x63, 0x68,
	0x2e, 0x70, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x2e, 0x57, 0x61, 0x74, 0x63, 0x68,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1f, 0x2e, 0x63, 0x61, 0x63, 0x68, 0x65, 0x72,
	0x6f, 0x61, 0x63, 0x68, 0x2e, 0x70, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x2e, 0x50,
	0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c, 0x22, 0x03, 0x90, 0x02, 0x01, 0x30, 0x01, 0x42,
	0x2f, 0x5a, 0x2d, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x62, 0x6f,
	0x62, 0x76, 0x61, 0x77, 0x74, 0x65, 0x72, 0x2f, 0x63, 0x61, 0x63, 0x68, 0x65, 0x72, 0x6f, 0x61,
	0x63, 0x68, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x70, 0x72, 0x69, 0x6e, 0x63, 0x69, 0x70, 0x61, 0x6c,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_principal_proto_rawDescOnce sync.Once
	file_principal_proto_rawDescData = file_principal_proto_rawDesc
)

func file_principal_proto_rawDescGZIP() []byte {
	file_principal_proto_rawDescOnce.Do(func() {
		file_principal_proto_rawDescData = protoimpl.X.CompressGZIP(file_principal_proto_rawDescData)
	})
	return file_principal_proto_rawDescData
}

var file_principal_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_principal_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_principal_proto_goTypes = []interface{}{
	(TokenStatus)(0),              // 0: cacheroach.principal.TokenStatus
	(*ID)(nil),                    // 1: cacheroach.principal.ID
	(*Principal)(nil),             // 2: cacheroach.principal.Principal
	(*LoadRequest)(nil),           // 3: cacheroach.principal.LoadRequest
	(*WatchRequest)(nil),          // 4: cacheroach.principal.WatchRequest
	(*EnsureRequest)(nil),         // 5: cacheroach.principal.EnsureRequest
	(*EnsureResponse)(nil),        // 6: cacheroach.principal.EnsureResponse
	(*timestamppb.Timestamp)(nil), // 7: google.protobuf.Timestamp
	(*durationpb.Duration)(nil),   // 8: google.protobuf.Duration
	(*emptypb.Empty)(nil),         // 9: google.protobuf.Empty
}
var file_principal_proto_depIdxs = []int32{
	1,  // 0: cacheroach.principal.Principal.ID:type_name -> cacheroach.principal.ID
	7,  // 1: cacheroach.principal.Principal.refresh_after:type_name -> google.protobuf.Timestamp
	0,  // 2: cacheroach.principal.Principal.refresh_status:type_name -> cacheroach.principal.TokenStatus
	1,  // 3: cacheroach.principal.LoadRequest.ID:type_name -> cacheroach.principal.ID
	1,  // 4: cacheroach.principal.WatchRequest.principal:type_name -> cacheroach.principal.ID
	8,  // 5: cacheroach.principal.WatchRequest.duration:type_name -> google.protobuf.Duration
	2,  // 6: cacheroach.principal.EnsureRequest.principal:type_name -> cacheroach.principal.Principal
	2,  // 7: cacheroach.principal.EnsureResponse.principal:type_name -> cacheroach.principal.Principal
	5,  // 8: cacheroach.principal.Principals.Ensure:input_type -> cacheroach.principal.EnsureRequest
	9,  // 9: cacheroach.principal.Principals.List:input_type -> google.protobuf.Empty
	3,  // 10: cacheroach.principal.Principals.Load:input_type -> cacheroach.principal.LoadRequest
	4,  // 11: cacheroach.principal.Principals.Watch:input_type -> cacheroach.principal.WatchRequest
	6,  // 12: cacheroach.principal.Principals.Ensure:output_type -> cacheroach.principal.EnsureResponse
	2,  // 13: cacheroach.principal.Principals.List:output_type -> cacheroach.principal.Principal
	2,  // 14: cacheroach.principal.Principals.Load:output_type -> cacheroach.principal.Principal
	2,  // 15: cacheroach.principal.Principals.Watch:output_type -> cacheroach.principal.Principal
	12, // [12:16] is the sub-list for method output_type
	8,  // [8:12] is the sub-list for method input_type
	8,  // [8:8] is the sub-list for extension type_name
	8,  // [8:8] is the sub-list for extension extendee
	0,  // [0:8] is the sub-list for field type_name
}

func init() { file_principal_proto_init() }
func file_principal_proto_init() {
	if File_principal_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_principal_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ID); i {
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
		file_principal_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Principal); i {
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
		file_principal_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LoadRequest); i {
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
		file_principal_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*WatchRequest); i {
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
		file_principal_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
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
		file_principal_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EnsureResponse); i {
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
	file_principal_proto_msgTypes[2].OneofWrappers = []interface{}{
		(*LoadRequest_ID)(nil),
		(*LoadRequest_Email)(nil),
		(*LoadRequest_EmailDomain)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_principal_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_principal_proto_goTypes,
		DependencyIndexes: file_principal_proto_depIdxs,
		EnumInfos:         file_principal_proto_enumTypes,
		MessageInfos:      file_principal_proto_msgTypes,
	}.Build()
	File_principal_proto = out.File
	file_principal_proto_rawDesc = nil
	file_principal_proto_goTypes = nil
	file_principal_proto_depIdxs = nil
}
