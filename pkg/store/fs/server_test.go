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

package fs

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bobvawter/cacheroach/api/file"
	"github.com/bobvawter/cacheroach/api/tenant"
	"github.com/stretchr/testify/assert"
)

func TestServer_List(t *testing.T) {
	const fileCount = 16
	a := assert.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()

	rig, cleanup, err := testRig(ctx)
	if !a.NoError(err) {
		return
	}
	defer cleanup()

	tID := tenant.NewID()
	_, err = rig.t.Ensure(ctx, &tenant.EnsureRequest{Tenant: &tenant.Tenant{
		Label: "Some Tenant",
		ID:    tID,
	}})
	if !a.NoError(err) {
		return
	}

	var allPaths []string
	fs := rig.fs.FileSystem(tID)
	// 1-based
	for i := 1; i <= fileCount; i++ {
		data := ""
		for j := 0; j < i; j++ {
			data += "*"
		}
		h, err := rig.b.EnsureBlob(ctx, tID, strings.NewReader(data))
		if !a.NoError(err) {
			return
		}

		p := fmt.Sprintf("/%d/%[1]d.txt", i)
		allPaths = append(allPaths, p)

		meta := &FileMeta{
			Path: p,
			Meta: map[string]string{
				fmt.Sprintf("meta-%d", i): "OK",
			},
		}
		err = fs.Put(ctx, meta, h)
		if !a.NoError(err) {
			return
		}
	}

	tcs := []struct {
		path     string
		expected []string
	}{
		{"", allPaths},
		{"/", allPaths},
		{"//", allPaths},
		{"/1", []string{"/1/1.txt"}},
		{"/1/", []string{"/1/1.txt"}},
		{"/1/1.txt", []string{"/1/1.txt"}},
		{"1", nil},
		{"/foo", nil},
	}

	for _, tc := range tcs {
		t.Run(tc.path, func(t *testing.T) {
			a := assert.New(t)
			resp, err := rig.svr.List(ctx, &file.ListRequest{
				Tenant: tID,
				Path:   tc.path,
			})
			if !a.NoError(err) {
				return
			}
			a.Len(resp.Files, len(tc.expected))
			for _, meta := range resp.Files {
				a.Contains(tc.expected, meta.Path)
				a.Equal(fmt.Sprintf("/%d/%[1]d.txt", meta.Size), meta.Path)
				a.Equal("OK", meta.Meta[fmt.Sprintf("meta-%d", meta.Size)])
			}
		})
	}

	t.Run("pagination", func(t *testing.T) {
		// Override pagination limit.
		rig.svr.limitOverride = 3
		defer func() { rig.svr.limitOverride = 0 }()

		a := assert.New(t)
		var cursor *file.Cursor
		seen := make(map[string]bool)

		for {
			resp, err := rig.svr.List(ctx, &file.ListRequest{
				Tenant: tID,
				Cursor: cursor,
			})
			if !a.NoError(err) {
				return
			}
			for _, meta := range resp.Files {
				seen[meta.Path] = true
			}
			cursor = resp.Cursor
			if cursor == nil {
				break
			}
		}
		a.Len(seen, fileCount)
	})
}
