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

package session

import (
	"fmt"
	"path"
	"strings"

	"google.golang.org/protobuf/proto"
)

// IsSubsetOf returns true if the target scope is a subset of or equal
// to another Scope.
func (x *Scope) IsSubsetOf(other *Scope) bool {
	if x == nil || x.Kind == nil {
		return true
	}
	if other == nil {
		return false
	}

	switch t := x.Kind.(type) {
	case *Scope_OnPrincipal:
		if !proto.Equal(t.OnPrincipal, other.GetOnPrincipal()) {
			return false
		}
		return true

	case *Scope_OnLocation:
		if !proto.Equal(t.OnLocation.TenantId, other.GetOnLocation().GetTenantId()) {
			return false
		}

		oParts := strings.Split(path.Clean(other.GetOnLocation().GetPath()), "/")
		xParts := strings.Split(path.Clean(t.OnLocation.Path), "/")

		if len(oParts) > len(xParts) {
			return false
		}

		for i := range oParts {
			if oParts[i] == "*" {
				continue
			}
			if oParts[i] != xParts[i] {
				return false
			}
		}

		return true

	case *Scope_SuperToken:
		return other.GetSuperToken()

	default:
		panic(fmt.Sprintf("unimplemented: %T", t))
	}
}
