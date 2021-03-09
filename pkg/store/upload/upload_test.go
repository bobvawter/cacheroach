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

package upload

import (
	"context"
	"math/rand"
	"testing"

	"github.com/bobvawter/cacheroach/api/capabilities"
	"github.com/bobvawter/cacheroach/api/principal"
	"github.com/bobvawter/cacheroach/api/session"
	"github.com/bobvawter/cacheroach/api/tenant"
	"github.com/bobvawter/cacheroach/api/token"
	"github.com/bobvawter/cacheroach/api/upload"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func TestUploadFlow(t *testing.T) {
	a := assert.New(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rig, cleanup, err := testRig(ctx)
	if !a.NoError(err) {
		return
	}
	defer cleanup()

	pID := principal.NewID()
	if _, err := rig.principals.Ensure(ctx, &principal.EnsureRequest{
		Principal: &principal.Principal{
			ID:           pID,
			Label:        "User",
			PasswordHash: " ",
		}}); !a.NoError(err) {
		return
	}

	tID := tenant.NewID()
	if _, err := rig.tenants.Ensure(ctx, &tenant.EnsureRequest{
		Tenant: &tenant.Tenant{
			ID:    tID,
			Label: "Tenant",
		}}); !a.NoError(err) {
		return
	}

	{
		resp, err := rig.tokens.Issue(ctx, &token.IssueRequest{
			Template: &session.Session{
				ID:           session.NewID(),
				Capabilities: &capabilities.Capabilities{Write: true},
				PrincipalId:  pID,
				Scope: &session.Scope{Kind: &session.Scope_OnLocation{
					OnLocation: &session.Location{
						TenantId: tID,
						Path:     "/*",
					},
				}}}})
		if !a.NoError(err) {
			return
		}
		ctx = session.WithSession(ctx, resp.Issued)
	}

	resp, err := rig.uploads.Begin(ctx, &upload.BeginRequest{
		Tenant: tID,
		Path:   "/index.html",
	})
	if !a.NoError(err) {
		return
	}
	a.NotZero(resp.MaxChunkSize)
	a.NotEmpty(resp.State.Signature)

	// Using a odd number.
	const chunkLen = 1024*1024 + 1
	const chunkCount = 15
	data := make([]byte, chunkLen)
	state := resp.State
	for i := 0; i < chunkCount; i++ {
		if _, err := rand.Read(data); !a.NoError(err) {
			return
		}

		resp, err := rig.uploads.Transfer(ctx, &upload.TransferRequest{
			State: proto.Clone(state).(*upload.TransferState),
			Data:  data,
		})
		if !a.NoError(err) {
			return
		}
		// Test retrying a chunk, should arrive at the same state.
		if i == 10 {
			resp2, err := rig.uploads.Transfer(ctx, &upload.TransferRequest{
				State: proto.Clone(state).(*upload.TransferState),
				Data:  data,
			})
			if !a.NoError(err) {
				return
			}
			a.Equal(resp.State.String(), resp2.State.String())
		}

		state = resp.State

		// Shift the data to keep generating new chunks.
		data = append(data[1:], data[0])
	}
	a.Equal(int64(chunkLen*chunkCount), state.Offset)

	if _, err := rig.uploads.Commit(ctx, &upload.CommitRequest{
		State: state,
		Meta: map[string]string{
			"foo": "bar",
		},
	}); !a.NoError(err) {
		return
	}

	{
		f, err := rig.fs.FileSystem(tID).OpenVersion(ctx, "/index.html", 0)
		if !a.NoError(err) {
			return
		}
		a.Equal("bar", f.Meta["foo"])
		a.Equal(int64(chunkLen*chunkCount), f.Length())
		a.Equal(int64(1), f.Version)
	}

	// Verify that a double-commit is OK, too:
	if _, err := rig.uploads.Commit(ctx, &upload.CommitRequest{
		State: state,
		Meta: map[string]string{
			"foo": "bar2",
		},
	}); !a.NoError(err) {
		return
	}

	{
		f, err := rig.fs.FileSystem(tID).OpenVersion(ctx, "/index.html", 0)
		if !a.NoError(err) {
			return
		}
		a.Equal("bar2", f.Meta["foo"])
		a.Equal(int64(chunkLen*chunkCount), f.Length())
		a.Equal(int64(2), f.Version)
	}

	// Now append another chunk to the rope.
	{
		resp, err := rig.uploads.Transfer(ctx, &upload.TransferRequest{
			State: proto.Clone(state).(*upload.TransferState),
			Data:  data,
		})
		if !a.NoError(err) {
			return
		}
		state = resp.State
	}

	// Verify that a double-commit is OK, too:
	rig.uploads.cache.Purge()
	if _, err := rig.uploads.Commit(ctx, &upload.CommitRequest{
		State: state,
		Meta: map[string]string{
			"foo": "bar3",
		},
	}); !a.NoError(err) {
		return
	}

	{
		f, err := rig.fs.FileSystem(tID).OpenVersion(ctx, "/index.html", 0)
		if !a.NoError(err) {
			return
		}
		a.Equal("bar3", f.Meta["foo"])
		a.Equal(int64(chunkLen*(chunkCount+1)), f.Length())
		a.Equal(int64(3), f.Version)
	}

	// Test retriving old version.
	{
		f, err := rig.fs.FileSystem(tID).OpenVersion(ctx, "/index.html", 1)
		if !a.NoError(err) {
			return
		}
		a.Equal("bar", f.Meta["foo"])
		a.Equal(int64(chunkLen*chunkCount), f.Length())
		a.Equal(int64(1), f.Version)
	}

	// Test a one-shot transfer
	{
		data := []byte("One-shot upload")
		resp, err := rig.uploads.Begin(ctx, &upload.BeginRequest{
			Tenant: tID,
			Path:   "/one-shot",
			Committed: &upload.BeginRequest_Contents{
				Contents: data,
			},
		})
		if !a.NoError(err) {
			return
		}
		a.True(resp.Committed)

		f, err := rig.fs.FileSystem(tID).Open("/one-shot")
		if !a.NoError(err) {
			return
		}
		stat, err := f.Stat()
		if !a.NoError(err) {
			return
		}
		a.Equal(int64(len(data)), stat.Size())
	}

	// Test an empty upload
	{
		resp, err := rig.uploads.Begin(ctx, &upload.BeginRequest{
			Tenant: tID,
			Path:   "/is-empty",
			Committed: &upload.BeginRequest_Empty{
				Empty: true,
			},
		})
		if !a.NoError(err) {
			return
		}
		a.True(resp.Committed)

		f, err := rig.fs.FileSystem(tID).Open("/is-empty")
		if !a.NoError(err) {
			return
		}
		stat, err := f.Stat()
		if !a.NoError(err) {
			return
		}
		a.Equal(int64(0), stat.Size())
	}
}
