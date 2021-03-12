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

package store

import (
	"github.com/bobvawter/cacheroach/pkg/store/blob"
	"github.com/bobvawter/cacheroach/pkg/store/fs"
	"github.com/bobvawter/cacheroach/pkg/store/principal"
	"github.com/bobvawter/cacheroach/pkg/store/tenant"
	"github.com/bobvawter/cacheroach/pkg/store/token"
	"github.com/bobvawter/cacheroach/pkg/store/upload"
	"github.com/bobvawter/cacheroach/pkg/store/vhost"
	"github.com/google/wire"
)

// Set is used by wire and rolls up all of the sub-packages.
//
// Combine with storetesting.Set for a ready-to-run stack.
var Set = wire.NewSet(
	blob.Set,
	fs.Set,
	principal.Set,
	tenant.Set,
	token.Set,
	upload.Set,
	vhost.Set,
)
