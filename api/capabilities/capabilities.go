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

package capabilities

import (
	"database/sql/driver"
	"sort"
	"strings"

	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

var all = &Capabilities{}

func init() {
	file_capabilities_proto_init()
	ref := all.ProtoReflect()
	fields := all.ProtoReflect().Descriptor().Fields()

	for i, j := 0, fields.Len(); i < j; i++ {
		if fd := fields.Get(i); fd.Kind() == protoreflect.BoolKind {
			ref.Set(fd, protoreflect.ValueOfBool(true))
		}
	}
}

// Parse will return a capabilities with the request field names set.
// The value "all" will return All().
func Parse(x []string) (*Capabilities, error) {
	ret := &Capabilities{}
	ref := ret.ProtoReflect()

	for i := range x {
		l := strings.ToLower(x[i])
		if l == "all" {
			ret = All()
		} else if fd := ref.Descriptor().Fields().ByName(protoreflect.Name(l)); fd != nil {
			ref.Set(fd, protoreflect.ValueOfBool(true))
		} else {
			return nil, errors.Errorf("unknown capability %q", x[i])
		}
	}

	return ret, nil
}

// All returns a Capabilities wil all bits set.
func All() *Capabilities {
	return proto.Clone(all).(*Capabilities)
}

// AsBits expresses the bool fields of the message as a bit-field, using
// the message field numbers as the bit.
func (x *Capabilities) AsBits() int64 {
	ret := int64(0)
	x.ProtoReflect().Range(func(d protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if d.Kind() == protoreflect.BoolKind && v.Bool() {
			ret |= 1 << (d.Number() - 1)
		}
		return true
	})
	return ret
}

// IsSubsetOf returns true if the target Capabilities are a subset of or
// equal to another Capabilities.
func (x *Capabilities) IsSubsetOf(other *Capabilities) bool {
	xBits := x.AsBits()
	return xBits&other.AsBits() == xBits
}

// Scan implements sql.Scanner.
func (x *Capabilities) Scan(v interface{}) error {
	i, ok := v.(int64)
	if !ok {
		return errors.Errorf("cannot convert from %T", v)
	}
	x.set(i)
	return nil
}

// Pretty returns a pretty-printable value that Parse will understand.
func (x *Capabilities) Pretty() string {
	if proto.Equal(all, x) {
		return "all"
	}
	var ret []string
	x.ProtoReflect().Range(func(fd protoreflect.FieldDescriptor, val protoreflect.Value) bool {
		if fd.Kind() == protoreflect.BoolKind && val.Bool() {
			ret = append(ret, string(fd.Name()))
		}
		return true
	})
	sort.Strings(ret)
	return strings.Join(ret, ",")
}

// Value implements driver.Valuer.
func (x *Capabilities) Value() (driver.Value, error) {
	if x == nil {
		return 0, nil
	}
	return x.AsBits(), nil
}

// Zero returns true if no capabilities are set.
func (x *Capabilities) Zero() bool {
	if x == nil {
		return true
	}
	ret := true
	x.ProtoReflect().Range(func(d protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if d.Kind() == protoreflect.BoolKind && v.Bool() {
			ret = false
		}
		return ret
	})
	return ret
}

// set the capabilities as a bit-field.
func (x *Capabilities) set(val int64) {
	t := protoreflect.ValueOfBool(true)
	msg := x.ProtoReflect()
	for idx, f := 0, msg.Descriptor().Fields(); idx < f.Len(); idx++ {
		d := f.Get(idx)
		if d.Kind() == protoreflect.BoolKind && val&(1<<(d.Number()-1)) != 0 {
			msg.Set(d, t)
		}
	}
}
