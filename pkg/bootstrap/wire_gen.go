// Code generated by Wire. DO NOT EDIT.

//go:generate go run github.com/google/wire/cmd/wire
//+build !wireinject

package bootstrap

import (
	"context"
	"github.com/bobvawter/cacheroach/pkg/cache"
	"github.com/bobvawter/cacheroach/pkg/metrics"
	"github.com/bobvawter/cacheroach/pkg/store/blob"
	"github.com/bobvawter/cacheroach/pkg/store/cdc"
	"github.com/bobvawter/cacheroach/pkg/store/fs"
	"github.com/bobvawter/cacheroach/pkg/store/principal"
	"github.com/bobvawter/cacheroach/pkg/store/storetesting"
	"github.com/bobvawter/cacheroach/pkg/store/tenant"
	"github.com/bobvawter/cacheroach/pkg/store/token"
	"github.com/bobvawter/cacheroach/pkg/store/vhost"
	"github.com/prometheus/client_golang/prometheus"
)

// Injectors from test_rig.go:

func testRig(ctx context.Context) (*rig, func(), error) {
	registry := prometheus.NewPedanticRegistry()
	factory := metrics.ProvideFactory(registry)
	config, cleanup, err := storetesting.ProvideCacheConfig()
	if err != nil {
		return nil, nil, err
	}
	logger := _wireLoggerValue
	cacheCache, cleanup2, err := cache.ProvideCache(ctx, factory, config, logger)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	configConfig, err := storetesting.ProvideStoreConfig()
	if err != nil {
		cleanup2()
		cleanup()
		return nil, nil, err
	}
	pool, cleanup3, err := storetesting.ProvideDB(ctx, configConfig, logger)
	if err != nil {
		cleanup2()
		cleanup()
		return nil, nil, err
	}
	store, cleanup4 := blob.ProvideStore(ctx, cacheCache, configConfig, pool, logger)
	fsStore, cleanup5, err := fs.ProvideStore(ctx, store, configConfig, pool, logger)
	if err != nil {
		cleanup4()
		cleanup3()
		cleanup2()
		cleanup()
		return nil, nil, err
	}
	server := &principal.Server{
		Config: configConfig,
		DB:     pool,
		Logger: logger,
	}
	notifier := cdc.ProvideNotifier(pool, logger)
	tokenServer, cleanup6, err := token.ProvideServer(ctx, configConfig, pool, logger, notifier)
	if err != nil {
		cleanup5()
		cleanup4()
		cleanup3()
		cleanup2()
		cleanup()
		return nil, nil, err
	}
	tenantServer := &tenant.Server{
		DB:     pool,
		Logger: logger,
	}
	vhostServer := &vhost.Server{
		DB:     pool,
		Logger: logger,
	}
	bootstrapper, err := ProvideBootstrap(ctx, store, pool, fsStore, logger, server, tokenServer, tenantServer, vhostServer)
	if err != nil {
		cleanup6()
		cleanup5()
		cleanup4()
		cleanup3()
		cleanup2()
		cleanup()
		return nil, nil, err
	}
	bootstrapRig := &rig{
		Bootstrapper: bootstrapper,
	}
	return bootstrapRig, func() {
		cleanup6()
		cleanup5()
		cleanup4()
		cleanup3()
		cleanup2()
		cleanup()
	}, nil
}

var (
	_wireLoggerValue = storetesting.Logger
)

// test_rig.go:

type rig struct {
	*Bootstrapper
}
