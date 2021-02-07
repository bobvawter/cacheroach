// Code generated by Wire. DO NOT EDIT.

//go:generate go run github.com/google/wire/cmd/wire
//+build !wireinject

package enforcer

import (
	"context"
	principal2 "github.com/bobvawter/cacheroach/api/principal"
	tenant2 "github.com/bobvawter/cacheroach/api/tenant"
	token2 "github.com/bobvawter/cacheroach/api/token"
	"github.com/bobvawter/cacheroach/pkg/store/principal"
	"github.com/bobvawter/cacheroach/pkg/store/storetesting"
	"github.com/bobvawter/cacheroach/pkg/store/tenant"
	"github.com/bobvawter/cacheroach/pkg/store/token"
)

// Injectors from test_rig.go:

func testRig(ctx context.Context) (*rig, func(), error) {
	logger := _wireLoggerValue
	config, err := storetesting.ProvideStoreConfig()
	if err != nil {
		return nil, nil, err
	}
	pool, cleanup, err := storetesting.ProvideDB(ctx, config, logger)
	if err != nil {
		return nil, nil, err
	}
	server, err := token.ProvideServer(config, pool, logger)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	enforcer := ProvideEnforcer(logger, server)
	principalServer := &principal.Server{
		Config: config,
		DB:     pool,
		Logger: logger,
	}
	tenantServer := &tenant.Server{
		DB:     pool,
		Logger: logger,
	}
	enforcerRig := &rig{
		Enforcer:   enforcer,
		principals: principalServer,
		tenants:    tenantServer,
		tokens:     server,
	}
	return enforcerRig, func() {
		cleanup()
	}, nil
}

var (
	_wireLoggerValue = storetesting.Logger
)

// test_rig.go:

type rig struct {
	*Enforcer
	principals principal2.PrincipalsServer
	tenants    tenant2.TenantsServer
	tokens     token2.TokensServer
}