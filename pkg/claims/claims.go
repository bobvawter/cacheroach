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

// Package claims contains the JWT claims structure and a utility method
// for signing them.
package claims

import (
	"time"

	"github.com/bobvawter/cacheroach/api/principal"
	"github.com/bobvawter/cacheroach/api/session"
	"github.com/bobvawter/cacheroach/api/tenant"
	"github.com/bobvawter/cacheroach/api/token"
	"github.com/dgrijalva/jwt-go/v4"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Audience is the JWT claim value that we'll look for.
const Audience = "cacheroach"

// Claims are JWT claims.
type Claims struct {
	Message *session.Session `json:"msg,omitempty"`
	jwt.StandardClaims
}

// Sign will create a signed token from the given session template,
// updating some fields within the Session object.
func Sign(now time.Time, sn *session.Session, key []byte) (*Claims, *token.Token, error) {
	cl := &Claims{
		Message: &session.Session{
			Capabilities: sn.Capabilities,
			Name:         sn.Name,
			Scope:        sn.Scope,
		},
		StandardClaims: jwt.StandardClaims{
			Audience: jwt.ClaimStrings{Audience},
			IssuedAt: &jwt.Time{Time: now},
		},
	}
	if sn.ExpiresAt.GetSeconds() > 0 {
		cl.ExpiresAt = &jwt.Time{Time: sn.ExpiresAt.AsTime()}
	}
	if !sn.PrincipalId.Zero() {
		cl.Subject = sn.PrincipalId.AsUUID().String()
	}
	if !sn.ID.Zero() {
		cl.ID = sn.ID.AsUUID().String()
	}

	// Hoist the tenant information into the standard claim header.
	if tnt := cl.Message.GetScope().GetOnLocation().GetTenantId(); tnt != nil {
		cl.Message.Scope = proto.Clone(cl.Message.Scope).(*session.Scope)
		cl.Issuer = tnt.AsUUID().String()
		cl.Message.Scope.GetOnLocation().TenantId = nil
	}

	tkn := jwt.NewWithClaims(jwt.SigningMethodHS256, cl)
	signed, err := tkn.SignedString(key)
	if err != nil {
		return nil, nil, err
	}

	return cl, &token.Token{Jwt: signed}, nil
}

// Validate will validate the token and expand its contents into a
// Session. Not all fields of the Session will be populated.
func Validate(token string, signingKey []byte) (*Claims, *session.Session, error) {
	parsed, err := jwt.ParseWithClaims(token, &Claims{},
		func(token *jwt.Token) (interface{}, error) {
			return signingKey, nil
		}, jwt.WithAudience(Audience))
	if err != nil {
		return nil, nil, err
	}
	c := parsed.Claims.(*Claims)

	// Re-populate the critical fields form the JSON-encoded claims.
	// See also Server.sign().
	ret := c.Message
	if c.ExpiresAt != nil {
		ret.ExpiresAt = timestamppb.New(c.ExpiresAt.Time)
	}
	if c.ID != "" {
		u, err := uuid.Parse(c.ID)
		if err != nil {
			return nil, nil, err
		}
		ret.ID = &session.ID{Data: u[:]}
	}
	if c.Subject != "" {
		u, err := uuid.Parse(c.Subject)
		if err != nil {
			return nil, nil, err
		}
		ret.PrincipalId = &principal.ID{Data: u[:]}
	}
	if c.Issuer != "" && ret.GetScope().GetOnLocation() != nil {
		u, err := uuid.Parse(c.Issuer)
		if err != nil {
			return nil, nil, err
		}
		ret.GetScope().GetOnLocation().TenantId = &tenant.ID{Data: u[:]}
	}
	return c, ret, nil
}
