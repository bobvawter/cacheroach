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

package session

import (
	"context"
	"database/sql/driver"
	"encoding/base64"
	"io/ioutil"
	"strings"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"google.golang.org/protobuf/encoding/protojson"
)

// NewID constructs a new ID.
func NewID() *ID {
	u := uuid.New()
	return &ID{Data: u[:]}
}

// ParseID will parse the input as either a canonically-formatted UUID
// or as a base64-encoded collection of bytes.
func ParseID(x string) (*ID, error) {
	switch len(x) {
	case 24:
		b, err := ioutil.ReadAll(base64.NewDecoder(base64.StdEncoding, strings.NewReader(x)))
		return &ID{Data: b}, errors.Wrap(err, "value is not valid base64")
	case 36:
		u, err := uuid.Parse(x)
		return &ID{Data: u[:]}, errors.Wrapf(err, "value is not a valid UUID")
	default:
		return nil, errors.New("unsupported format")
	}
}

// AsUUID converts the message to a validated UUID or returns the zero
// value.
func (x *ID) AsUUID() uuid.UUID {
	if x == nil {
		return uuid.UUID{}
	}
	u, err := uuid.FromBytes(x.Data)
	if err == nil {
		return u
	}
	return uuid.UUID{}
}

// IsSubsetOf returns tue if the capabilities and scope of the the
// target session are a subset of or equal to those of another session.
// It will also return true if the other session is a super-token.
func (x *Session) IsSubsetOf(other *Session) bool {
	if x == nil {
		return false
	}
	return other.GetScope().GetSuperToken() ||
		x.Capabilities.IsSubsetOf(other.GetCapabilities()) &&
			x.Scope.IsSubsetOf(other.GetScope())
}

// Scan implements sql.Scanner.
func (x *ID) Scan(v interface{}) error {
	switch t := v.(type) {
	case nil:
		x.Data = nil
	case string:
		u, err := uuid.Parse(t)
		if err != nil {
			return err
		}
		x.Data = u[:]
	case []byte:
		u, err := uuid.FromBytes(t)
		if err != nil {
			return err
		}
		x.Data = u[:]
	case [16]byte:
		// Memory is owned by the DB driver.
		var u uuid.UUID
		copy(u[:], t[:])
		x.Data = u[:]
	default:
		return errors.Errorf("cannot convert from %T", v)
	}
	return nil
}

// Value implements driver.Valuer.
func (x *ID) Value() (driver.Value, error) {
	if x == nil {
		return nil, nil
	}
	return x.Data, nil
}

// Zero returns true if the ID is the zero value.
func (x *ID) Zero() bool {
	return len(x.GetData()) == 0
}

type contextKey int

var sessionKey contextKey = 0

// WithSession returns a Context.
func WithSession(ctx context.Context, s *Session) context.Context {
	return context.WithValue(ctx, sessionKey, s)
}

// FromContext returns the Session associated with the context,
// or nil.
func FromContext(ctx context.Context) *Session {
	s, _ := ctx.Value(sessionKey).(*Session)
	return s
}

// MarshalJSON allows the Session to be correctly encoded into a JWT.
func (x *Session) MarshalJSON() ([]byte, error) {
	return protojson.Marshal(x)
}

// UnmarshalJSON allows the Session to be correctly decoded from a JWT.
func (x *Session) UnmarshalJSON(data []byte) error {
	return protojson.Unmarshal(data, x)
}
