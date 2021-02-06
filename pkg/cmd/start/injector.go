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

package start

import (
	"context"

	"github.com/Mandala/go-log"
	"github.com/bobvawter/cacheroach/pkg/bootstrap"
	"github.com/bobvawter/cacheroach/pkg/cache"
	"github.com/bobvawter/cacheroach/pkg/enforcer"
	"github.com/bobvawter/cacheroach/pkg/server"
	"github.com/bobvawter/cacheroach/pkg/server/common"
	"github.com/bobvawter/cacheroach/pkg/store"
	"github.com/bobvawter/cacheroach/pkg/store/config"
	"github.com/bobvawter/cacheroach/pkg/store/storeproduction"
	"github.com/google/wire"
)

type injector struct {
	Server *server.Server
}

func newInjector(
	context.Context,
	*cache.Config,
	*config.Config,
	*common.Config,
	*log.Logger,
) (*injector, func(), error) {
	panic(wire.Build(
		bootstrap.Set,
		enforcer.Set,
		server.Set,
		store.Set,
		storeproduction.Set,
		wire.Struct(new(injector), "*"),
	))
}
