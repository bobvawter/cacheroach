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
	"errors"
	"io/fs"
	"strings"
	"time"
)

// dir implements fs.File, fs.FileInfo, and fs.ReadDirFile interfaces
// to create a directory listing.
type dir struct {
	path string // The path, including a trailing /
	fs   *FileSystem
}

var (
	_ fs.File        = (*dir)(nil)
	_ fs.FileInfo    = (*dir)(nil)
	_ fs.ReadDirFile = (*dir)(nil)
)

func (d *dir) Close() error                   { return nil }
func (d *dir) IsDir() bool                    { return true }
func (d *dir) Name() string                   { return d.path }
func (d *dir) Mode() fs.FileMode              { return fs.ModeDir | 0555 }
func (d *dir) ModTime() time.Time             { return time.Time{} }
func (d *dir) Seek(int64, int) (int64, error) { return 0, fs.ErrInvalid }
func (d *dir) Read([]byte) (int, error)       { return 0, fs.ErrInvalid }
func (d *dir) Size() int64                    { return 0 }
func (d *dir) Stat() (fs.FileInfo, error)     { return d, nil }
func (d *dir) Sys() interface{}               { return nil }

func (d *dir) ReadDir(count int) ([]fs.DirEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if count >= 0 {
		return nil, errors.New("partial listing not implemented")
	}
	parts := strings.Split(d.path, "/")

	rows, err := d.fs.store.db.Query(ctx,
		"SELECT DISTINCT x[$1], array_length(x, 1) > $1 "+
			"FROM (SELECT string_to_array(path, '/') AS x "+
			"FROM files WHERE tenant = $2 AND path LIKE $3)",
		len(parts), d.fs.tenant, d.path+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ret []fs.DirEntry
	for rows.Next() {
		var nextSegment string
		var isDir bool
		if err := rows.Scan(&nextSegment, &isDir); err != nil {
			return nil, err
		}

		var nextPath = d.path + nextSegment
		if isDir {
			nextPath += "/"
		}
		ret = append(ret, &listing{isDir, nextPath})
	}

	return ret, nil
}
