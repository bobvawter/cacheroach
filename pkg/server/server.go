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

// Package server contains a hybrid gRPC+HTTP server to store and
// retrieve files.
package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"crypto/x509"

	"github.com/Mandala/go-log"
	"github.com/bobvawter/cacheroach/pkg/server/common"
	"github.com/bobvawter/cacheroach/pkg/server/diag"
	"github.com/bobvawter/cacheroach/pkg/server/rest"
	"github.com/bobvawter/cacheroach/pkg/server/rpc"
	"github.com/fullstorydev/grpcui/standalone"
	"github.com/google/wire"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Set is used by wire.
var Set = wire.NewSet(
	common.Set,
	diag.Set,
	rest.Set,
	rpc.Set,
	ProvideCertificates,
	ProvideServer,
)

// Server contains the configuration and main HTTP loop.
type Server struct {
	BoundAddr net.Addr
	// A loopback connection to the server.
	Conn *grpc.ClientConn
}

// ProvideServer constructs a new Server.
func ProvideServer(
	ctx context.Context,
	busyLatch common.BusyLatch,
	certificates []tls.Certificate,
	cfg *common.Config,
	logger *log.Logger,
	mux *rest.Mux,
) (*Server, func(), error) {
	var tlsConfig *tls.Config
	if len(certificates) > 0 {
		tlsConfig = &tls.Config{
			Certificates: certificates,
			RootCAs:      x509.NewCertPool(),
		}
		for i := range certificates {
			tlsConfig.RootCAs.AddCert(certificates[i].Leaf)
		}
	}

	l, err := net.Listen("tcp", cfg.BindAddr)
	if err != nil {
		return nil, nil, err
	}
	logger.Infof("listening on %s", l.Addr())

	if tlsConfig == nil {
		go func() {
			_ = (&http.Server{
				// Enable H2C upgrades over plain-text.
				Handler: h2c.NewHandler(mux, &http2.Server{}),
			}).Serve(l)
		}()
	} else {
		go func() {
			_ = (&http.Server{
				Handler:   mux,
				TLSConfig: tlsConfig.Clone(),
			}).ServeTLS(l, "", "")
		}()
	}

	loopbackOpts := []grpc.DialOption{grpc.WithBlock()}
	if tlsConfig == nil {
		loopbackOpts = append(loopbackOpts, grpc.WithInsecure())
	} else {
		loopbackOpts = append(loopbackOpts,
			grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig.Clone())))

	}

	loopback, err := grpc.DialContext(
		ctx,
		fmt.Sprintf("localhost:%d", l.Addr().(*net.TCPAddr).Port),
		loopbackOpts...)

	if err != nil {
		return nil, nil, err
	}

	// Late-bind the debug UI since it requires a loopback connection.
	if cfg.UI && !cfg.FilesOnly {
		ui, err := standalone.HandlerViaReflection(ctx, loopback, "cacheroach")
		if err != nil {
			return nil, nil, err
		}
		mux.Handle("/_/ui/", http.StripPrefix("/_/ui", ui))
		logger.Info("enabled /_/ui/ handler")
	}

	cleanup := func() {
		_ = l.Close()
		select {
		case <-busyLatch.Wait():
			logger.Info("active connections drained")
		case <-time.After(cfg.GracePeriod):
			logger.Warnf("grace period expired with %d active requests", busyLatch.Count())
		}
	}

	return &Server{
		BoundAddr: l.Addr(),
		Conn:      loopback,
	}, cleanup, nil
}
