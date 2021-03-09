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
	"io/fs"
	"time"
)

// listing is a trivial implementation of fs.DirEntry and fs.FileInfo.
type listing struct {
	dir  bool
	name string
}

var (
	_ fs.DirEntry = (*listing)(nil)
	_ fs.FileInfo = (*listing)(nil)
)

func (l *listing) Info() (fs.FileInfo, error) { return l, nil }
func (l *listing) IsDir() bool                { return l.dir }
func (l *listing) Mode() fs.FileMode {
	if l.dir {
		return fs.ModeDir | 0555
	}
	return 0444
}
func (l *listing) ModTime() time.Time { return time.Time{} }
func (l *listing) Name() string       { return l.name }
func (l *listing) Size() int64        { return 0 }
func (l *listing) Sys() interface{}   { return nil }
func (l *listing) Type() fs.FileMode  { return l.Mode().Type() }
