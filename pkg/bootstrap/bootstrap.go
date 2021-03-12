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

// Package bootstrap creates default data.
package bootstrap

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/Mandala/go-log"
	"github.com/bobvawter/cacheroach/api/capabilities"
	"github.com/bobvawter/cacheroach/api/principal"
	"github.com/bobvawter/cacheroach/api/session"
	"github.com/bobvawter/cacheroach/api/tenant"
	"github.com/bobvawter/cacheroach/api/token"
	"github.com/bobvawter/cacheroach/api/vhost"
	"github.com/bobvawter/cacheroach/pkg/store/blob"
	"github.com/bobvawter/cacheroach/pkg/store/fs"
	"github.com/bobvawter/cacheroach/pkg/store/schema"
	"github.com/bobvawter/cacheroach/pkg/store/util"
	"github.com/google/wire"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pkg/errors"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	scratchPad = &tenant.ID{Data: []byte{
		0xA, 0xA, 0xA, 0xA, 0xA, 0xA, 0xA, 0xA, 0xA, 0xA, 0xA, 0xA, 0xA, 0xA, 0xA, 0xA}}
	// Set is used by wire.
	Set = wire.NewSet(ProvideBootstrap)
)

// Bootstrapper creates default data.
type Bootstrapper struct {
	// PublicSession is a well-known session for unauthenticated access.
	PublicSession *session.Session
	// ScratchPad is a well-known TenantID for a default tenancy.
	ScratchPad *tenant.ID
	// Unauthenticated is a well-known PrincipalID that represents
	// unauthenticated requests. It may have ACLs associated with it, to
	// make certain vHosts public.
	Unauthenticated *principal.ID
}

// ProvideBootstrap is called by wire.
func ProvideBootstrap(
	ctx context.Context,
	blobs *blob.Store,
	db *pgxpool.Pool,
	f *fs.Store,
	logger *log.Logger,
	principals principal.PrincipalsServer,
	tokens token.TokensServer,
	tenants tenant.TenantsServer,
	vHosts vhost.VHostsServer,
) (*Bootstrapper, error) {
	ret := &Bootstrapper{ScratchPad: scratchPad, Unauthenticated: principal.Unauthenticated}

	if err := schema.EnsureSchema(ctx, db, logger); err != nil {
		return nil, err
	}

	if _, err := tenants.Ensure(ctx, &tenant.EnsureRequest{
		Tenant: &tenant.Tenant{
			ID:    scratchPad,
			Label: "Default Scratchpad",
		}}); errors.Is(err, util.ErrVersionSkew) {
		// Ignore, already created
	} else if err != nil {
		return nil, err
	} else if _, err := vHosts.Ensure(ctx, &vhost.EnsureRequest{
		Vhost: &vhost.VHost{TenantId: scratchPad, Vhost: "*"},
	}); err != nil {
		return nil, err
	}

	if found, _ := principals.Load(ctx, &principal.LoadRequest{
		Kind: &principal.LoadRequest_ID{
			ID: principal.Unauthenticated,
		}}); found == nil {
		claimBytes, err := json.Marshal(map[string]string{
			"name":   "Unauthenticated Principal",
			"source": "bootstrap",
		})
		if err != nil {
			return nil, err
		}

		p := &principal.Principal{
			ID:     principal.Unauthenticated,
			Claims: claimBytes,
		}
		req := &principal.EnsureRequest{Principal: p}
		if _, err := principals.Ensure(ctx, req); errors.Is(err, util.ErrVersionSkew) {
			// This is OK, something else just created it.
		} else if err != nil {
			return nil, err
		}
	}

	// Don't care about error since we're probably creating a duplicate.
	{
		sn := &session.Session{
			Capabilities: &capabilities.Capabilities{Read: true, Delegate: true},
			ExpiresAt:    timestamppb.New(time.Now().AddDate(100, 0, 0)),
			Note:         "Default public access",
			Name:         "public-access-v0",
			PrincipalId:  principal.Unauthenticated,
			Scope: &session.Scope{Kind: &session.Scope_OnPrincipal{
				OnPrincipal: principal.Unauthenticated}},
		}
		_, _ = tokens.Issue(ctx, &token.IssueRequest{Template: sn})
		sn, err := tokens.Load(session.WithSession(ctx, sn), &token.LoadRequest{Kind: &token.LoadRequest_Name{Name: sn.Name}})
		if err != nil {
			return nil, err
		}
		ret.PublicSession = sn
	}

	// Ensure that unauthorized user can read from the scratchpad.
	// Won't create a duplicate due to use of "Name" field.
	// TODO(bob): Check error
	_, _ = tokens.Issue(ctx, &token.IssueRequest{Template: &session.Session{
		Capabilities: &capabilities.Capabilities{Read: true},
		ExpiresAt:    timestamppb.New(time.Now().AddDate(10, 0, 0)),
		Name:         "<bootstrap>",
		Note:         "Default access for unauthorized user to scratchpad",
		PrincipalId:  principal.Unauthenticated,
		Scope: &session.Scope{Kind: &session.Scope_OnLocation{
			OnLocation: &session.Location{
				TenantId: scratchPad,
				Path:     "/*",
			}}},
	}})

	hash, err := blobs.EnsureBlob(ctx, scratchPad, strings.NewReader(
		"<!doctype html><meta charset=utf-8><title>Hello World!</title>"))
	if err != nil {
		return nil, err
	}

	if err := f.FileSystem(scratchPad).Put(ctx, &fs.FileMeta{
		Path: "/index.html"}, hash); errors.Is(err, util.ErrVersionSkew) {
		// OK, already initialized
	} else if err != nil {
		return nil, err
	}

	return ret, nil
}
