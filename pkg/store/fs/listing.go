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
	"os"
	"time"
)

// listing implements enough of os.FileInfo to be able to use the
// http package's directory viewer useful.
type listing struct {
	dir  bool
	name string
}

var _ os.FileInfo = &listing{}

func (l *listing) Name() string {
	return l.name
}

func (l *listing) Size() int64 {
	return 0
}

func (l *listing) Mode() os.FileMode {
	return 0666
}

func (l *listing) ModTime() time.Time {
	return time.Time{}
}

func (l *listing) IsDir() bool {
	return l.dir
}

func (l *listing) Sys() interface{} {
	return nil
}
