// Code generated by Wire. DO NOT EDIT.

//go:generate go run github.com/google/wire/cmd/wire
//+build !wireinject

package server

import (
	"context"
	"crypto/tls"
	principal2 "github.com/bobvawter/cacheroach/api/principal"
	tenant2 "github.com/bobvawter/cacheroach/api/tenant"
	token2 "github.com/bobvawter/cacheroach/api/token"
	vhost2 "github.com/bobvawter/cacheroach/api/vhost"
	"github.com/bobvawter/cacheroach/pkg/bootstrap"
	"github.com/bobvawter/cacheroach/pkg/cache"
	"github.com/bobvawter/cacheroach/pkg/enforcer"
	"github.com/bobvawter/cacheroach/pkg/metrics"
	"github.com/bobvawter/cacheroach/pkg/server/common"
	"github.com/bobvawter/cacheroach/pkg/server/diag"
	"github.com/bobvawter/cacheroach/pkg/server/oidc"
	"github.com/bobvawter/cacheroach/pkg/server/rest"
	"github.com/bobvawter/cacheroach/pkg/server/rpc"
	"github.com/bobvawter/cacheroach/pkg/store/blob"
	"github.com/bobvawter/cacheroach/pkg/store/cdc"
	"github.com/bobvawter/cacheroach/pkg/store/config"
	"github.com/bobvawter/cacheroach/pkg/store/fs"
	"github.com/bobvawter/cacheroach/pkg/store/principal"
	"github.com/bobvawter/cacheroach/pkg/store/storetesting"
	"github.com/bobvawter/cacheroach/pkg/store/tenant"
	"github.com/bobvawter/cacheroach/pkg/store/token"
	"github.com/bobvawter/cacheroach/pkg/store/upload"
	"github.com/bobvawter/cacheroach/pkg/store/vhost"
	"github.com/prometheus/client_golang/prometheus"
	"time"
)

// Injectors from test_rig.go:

func testRig(ctx context.Context) (*rig, func(), error) {
	registry := prometheus.NewPedanticRegistry()
	factory := metrics.ProvideFactory(registry)
	busyLatch := common.ProvideBusyLatch(factory)
	config := _wireConfigValue
	logger := _wireLoggerValue
	v, err := ProvideCertificates(config, logger)
	if err != nil {
		return nil, nil, err
	}
	handler := metrics.ProvideMetricsHandler(logger, registry, registry)
	configConfig, err := storetesting.ProvideStoreConfig()
	if err != nil {
		return nil, nil, err
	}
	pool, cleanup, err := storetesting.ProvideDB(ctx, configConfig, logger)
	if err != nil {
		return nil, nil, err
	}
	healthz := rest.ProvideHealthz(pool, logger)
	debugMux := rest.ProvideDebugMux(handler, healthz)
	latchWrapper := rest.ProvideLatchWrapper(busyLatch)
	pProfWrapper := rest.ProvidePProfWrapper()
	cacheConfig, cleanup2, err := storetesting.ProvideCacheConfig()
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	cacheCache, cleanup3, err := cache.ProvideCache(ctx, factory, cacheConfig, logger)
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
	bootstrapper, err := bootstrap.ProvideBootstrap(ctx, store, pool, fsStore, logger, server, tokenServer, tenantServer, vhostServer)
	if err != nil {
		cleanup6()
		cleanup5()
		cleanup4()
		cleanup3()
		cleanup2()
		cleanup()
		return nil, nil, err
	}
	connector, err := oidc.ProvideConnector(ctx, factory, bootstrapper, config, logger, server, tokenServer)
	if err != nil {
		cleanup6()
		cleanup5()
		cleanup4()
		cleanup3()
		cleanup2()
		cleanup()
		return nil, nil, err
	}
	sessionWrapper := rest.ProvideSessionWrapper(bootstrapper, connector, tokenServer)
	vHostMap, cleanup7, err := common.ProvideVHostMap(ctx, logger, vhostServer)
	if err != nil {
		cleanup6()
		cleanup5()
		cleanup4()
		cleanup3()
		cleanup2()
		cleanup()
		return nil, nil, err
	}
	vHostWrapper := rest.ProvideVHostWrapper(logger, vHostMap)
	cliConfigHandler := rest.ProvideCLIConfigHandler(config, latchWrapper, pProfWrapper, sessionWrapper, vHostWrapper)
	enforcerEnforcer := enforcer.ProvideEnforcer(logger, tokenServer)
	fileHandler := rest.ProvideFileHandler(store, enforcerEnforcer, fsStore, logger, pProfWrapper, latchWrapper, sessionWrapper, vHostWrapper)
	wrapper := metrics.ProvideWrapper(factory)
	provision, err := rest.ProvideProvision(config, connector, logger, server, pProfWrapper, latchWrapper, sessionWrapper, vHostWrapper)
	if err != nil {
		cleanup7()
		cleanup6()
		cleanup5()
		cleanup4()
		cleanup3()
		cleanup2()
		cleanup()
		return nil, nil, err
	}
	retrieve := rest.ProvideRetrieve(logger, fsStore, pProfWrapper, latchWrapper, sessionWrapper, vHostWrapper)
	authInterceptor, err := rpc.ProvideAuthInterceptor(connector, logger, tokenServer)
	if err != nil {
		cleanup7()
		cleanup6()
		cleanup5()
		cleanup4()
		cleanup3()
		cleanup2()
		cleanup()
		return nil, nil, err
	}
	busyInterceptor := &rpc.BusyInterceptor{
		BusyLatch: busyLatch,
	}
	elideInterceptor := &rpc.ElideInterceptor{
		Enforcer: enforcerEnforcer,
	}
	interceptor := metrics.ProvideInterceptor(factory)
	vHostInterceptor := &rpc.VHostInterceptor{
		Logger: logger,
		Mapper: vHostMap,
	}
	diags := &diag.Diags{}
	fsServer := &fs.Server{
		Config: configConfig,
		DB:     pool,
		FS:     fsStore,
	}
	uploadServer, err := upload.ProvideServer(store, configConfig, pool, fsStore, logger)
	if err != nil {
		cleanup7()
		cleanup6()
		cleanup5()
		cleanup4()
		cleanup3()
		cleanup2()
		cleanup()
		return nil, nil, err
	}
	grpcServer, err := rpc.ProvideRPC(logger, authInterceptor, busyInterceptor, elideInterceptor, interceptor, vHostInterceptor, diags, fsServer, server, tenantServer, tokenServer, uploadServer, vhostServer)
	if err != nil {
		cleanup7()
		cleanup6()
		cleanup5()
		cleanup4()
		cleanup3()
		cleanup2()
		cleanup()
		return nil, nil, err
	}
	publicMux := rest.ProvidePublicMux(cliConfigHandler, connector, fileHandler, wrapper, provision, retrieve, grpcServer)
	serverServer, cleanup8, err := ProvideServer(ctx, busyLatch, v, config, debugMux, logger, publicMux)
	if err != nil {
		cleanup7()
		cleanup6()
		cleanup5()
		cleanup4()
		cleanup3()
		cleanup2()
		cleanup()
		return nil, nil, err
	}
	serverRig := &rig{
		Server:     serverServer,
		certs:      v,
		cfg:        configConfig,
		principals: server,
		tenants:    tenantServer,
		tokens:     tokenServer,
		vhosts:     vhostServer,
	}
	return serverRig, func() {
		cleanup8()
		cleanup7()
		cleanup6()
		cleanup5()
		cleanup4()
		cleanup3()
		cleanup2()
		cleanup()
	}, nil
}

var (
	_wireConfigValue = &common.Config{
		BindAddr:           ":0",
		GenerateSelfSigned: true,
		GracePeriod:        time.Second,
	}
	_wireLoggerValue = storetesting.Logger
)

// test_rig.go:

type rig struct {
	*Server
	certs      []tls.Certificate
	cfg        *config.Config
	principals principal2.PrincipalsServer
	tenants    tenant2.TenantsServer
	tokens     token2.TokensServer
	vhosts     vhost2.VHostsServer
}
