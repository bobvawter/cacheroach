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

// Package util contains common utility code for storage operations.
package util

import (
	"context"

	"github.com/jackc/pgconn"
	"github.com/pkg/errors"
)

// ErrVersionSkew is returned from methods that operate on versioned
// data to indicate that the caller should refresh before
// retrying the operation.
var ErrVersionSkew = errors.New("version skew")

// Marker is a settable flag.
type Marker bool

// Mark sets the flag.
func (m *Marker) Mark() {
	*m = true
}

// Marked returns the flag status.
func (m *Marker) Marked() bool {
	return bool(*m)
}

// Retry is a convenience wrapper to automatically retry idempotent
// database operations that experience a transaction or or connection
// failure. The provided callback must be entirely idempotent, with
// no observable side-effects during its execution.
func Retry(ctx context.Context, idempotent func(context.Context) error) error {
	return RetryLoop(ctx, func(ctx context.Context, _ *Marker) error {
		return idempotent(ctx)
	})
}

// RetryLoop is a convenience wrapper to automatically retry idempotent
// database operations that experience a transaction or or connection
// failure. The provided callback may indicate that it has started
// generating observable effects (e.g. sending result data) by calling
// its second parameter to disable the retry behavior.
func RetryLoop(ctx context.Context, fn func(ctx context.Context, sideEffect *Marker) error) error {
	var sideEffect Marker
	for {
		err := fn(ctx, &sideEffect)
		if err == nil {
			return nil
		}

		if pgErr := (*pgconn.PgError)(nil); !sideEffect.Marked() && errors.As(err, &pgErr) {
			switch pgErr.Code {
			case "40001": // Serialization Failure
			case "40003": // Statement Completion Unknown
			case "08003": // Connection Does Not Exist
			case "08006": // Connection Failure
			default:
				return err
			}
		} else {
			return err
		}
	}
}
