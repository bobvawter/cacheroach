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
	"fmt"
	"io"
	"io/fs"
	"time"

	"github.com/bobvawter/cacheroach/api/tenant"
	"github.com/bobvawter/cacheroach/pkg/store/blob"
)

// FileMeta describes file-like data other than the file's size.
type FileMeta struct {
	CTime, MTime time.Time
	Meta         map[string]string
	Path         string
	Tenant       *tenant.ID
	Version      int64
}

// A File associates an open Blob with additional metadata.
type File struct {
	*FileMeta
	*blob.Blob
}

var (
	_ fs.File           = (*File)(nil)
	_ fs.FileInfo       = (*File)(nil)
	_ io.ReadSeekCloser = (*File)(nil)
)

// IsDir implements fs.FileInfo.
func (f *File) IsDir() bool {
	return false
}

// Name implements fs.FileInfo and returns the file's path.
func (f *File) Name() string { return f.Path }

// Mode implements fs.FileInfo.
func (f *File) Mode() fs.FileMode {
	return 0444
}

// ModTime implements fs.FileInfo.
func (f *File) ModTime() time.Time { return f.MTime }

// Size implements fs.FileInfo.
func (f *File) Size() int64 {
	return f.Blob.Length()
}

// Stat implements fs.FileInfo.
func (f *File) Stat() (fs.FileInfo, error) { return f, nil }

func (f *File) String() string {
	return fmt.Sprintf("%s:%s -> %s", f.Tenant, f.Path, f.Hash())
}

// Sys implements fs.FileInfo.
func (f *File) Sys() interface{} { return nil }
