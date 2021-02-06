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

package cli

import (
	"fmt"
	"os"
	"text/tabwriter"
)

type tabs struct {
	w *tabwriter.Writer
}

func newTabs() *tabs {
	return &tabs{tabwriter.NewWriter(os.Stdout, 4, 4, 2, ' ', 0)}
}

func (o *tabs) Printf(format string, args ...interface{}) {
	_, _ = fmt.Fprintf(o.w, format, args...)
}

func (o *tabs) Close() {
	_ = o.w.Flush()
}
