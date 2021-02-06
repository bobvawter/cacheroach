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

package main

import (
	"os"

	"github.com/Mandala/go-log"
	"github.com/bobvawter/cacheroach/pkg/cmd/root"
	"github.com/spf13/cobra/doc"
)

// Auto-generate Cobra documentation.
func main() {
	logger := log.New(os.Stderr)
	x := root.Command(logger)
	x.DisableAutoGenTag = true
	err := doc.GenMarkdownTree(x, "./doc/")
	if err != nil {
		logger.Errorf("could not generate: %v", err)
	}
}
