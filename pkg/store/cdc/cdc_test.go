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

package cdc

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test(t *testing.T) {
	a := assert.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	rig, cleanup, err := testRig(ctx)
	if !a.NoError(err) {
		return
	}
	defer cleanup()

	ch := rig.notifier.Notify(ctx, []string{"principals"})

	if _, err := rig.db.Exec(ctx,
		"INSERT INTO principals (principal, version) "+
			"VALUES (gen_random_uuid(), 1)",
	); !a.NoError(err) {
		return
	}

	select {
	case <-ctx.Done():
		a.Fail("timed out")
	case n := <-ch:
		a.Equal("principals", n.Table)
		if a.NotEmpty(n.Key) {
			a.Equal(uint8('['), n.Key[0])
		}
		a.NotEmpty(n.Payload)
	}
}
