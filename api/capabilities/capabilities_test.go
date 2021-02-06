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
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestCapabilities_IsSubsetOf(t *testing.T) {
	a := assert.New(t)

	all := &Capabilities{}
	for fields, i := all.ProtoReflect().Descriptor().Fields(), 0; i < fields.Len(); i++ {
		d := fields.Get(i)
		if d.Kind() == protoreflect.BoolKind {
			all.ProtoReflect().Set(d, protoreflect.ValueOfBool(true))
		}
	}
	a.Equal(int64(0b1111), all.AsBits())
	a.False(all.Zero())

	none := &Capabilities{}
	a.Equal(int64(0), none.AsBits())
	a.True(none.Zero())

	a.True(all.IsSubsetOf(all))
	a.True(none.IsSubsetOf(none))

	a.True(none.IsSubsetOf(all))
	a.False(all.IsSubsetOf(none))
}
