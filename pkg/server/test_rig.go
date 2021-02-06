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

//+build wireinject

package server

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/bobvawter/cacheroach/api/principal"
	"github.com/bobvawter/cacheroach/api/tenant"
	"github.com/bobvawter/cacheroach/api/token"
	"github.com/bobvawter/cacheroach/api/vhost"
	"github.com/bobvawter/cacheroach/pkg/bootstrap"
	"github.com/bobvawter/cacheroach/pkg/enforcer"
	"github.com/bobvawter/cacheroach/pkg/server/common"
	"github.com/bobvawter/cacheroach/pkg/store"
	"github.com/bobvawter/cacheroach/pkg/store/storetesting"
	"github.com/google/wire"
)

type rig struct {
	*Server
	certs      []tls.Certificate
	principals principal.PrincipalsServer
	tenants    tenant.TenantsServer
	tokens     token.TokensServer
	vhosts     vhost.VHostsServer
}

func testRig(ctx context.Context) (*rig, func(), error) {
	panic(wire.Build(
		Set,
		bootstrap.Set,
		enforcer.Set,
		store.Set,
		storetesting.Set,
		wire.Struct(new(rig), "*"),
		wire.Value(&common.Config{
			BindAddr:           ":0",
			GenerateSelfSigned: true,
			GracePeriod:        time.Second,
		}),
	))
}
