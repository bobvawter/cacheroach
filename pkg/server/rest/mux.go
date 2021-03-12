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

package rest

import (
	"context"
	"net/http"
	"net/http/pprof"
	"strings"

	"github.com/bobvawter/cacheroach/pkg/metrics"
	"github.com/bobvawter/cacheroach/pkg/server/diag"
	"github.com/bobvawter/cacheroach/pkg/server/oidc"
	"google.golang.org/grpc"
)

// PublicMux has public functionality attached.
type PublicMux struct {
	*http.ServeMux
}

// ProvidePublicMux is called by wire.
func ProvidePublicMux(
	cliConfig CLIConfigHandler,
	connector *oidc.Connector,
	fileHandler FileHandler,
	measure metrics.Wrapper,
	provision Provision,
	retrieve Retrieve,
	rpc *grpc.Server,
) PublicMux {
	fileHandler = measure(fileHandler, "files")
	retrieve = measure(retrieve, "files")
	mux := http.NewServeMux()

	mux.HandleFunc(oidc.ReceivePath, connector.Receive)
	mux.Handle("/_/v0/config", cliConfig)
	mux.Handle("/_/v0/provision", provision)
	mux.Handle("/_/v0/retrieve/", retrieve)
	mux.Handle("/_/", http.NotFoundHandler())
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), diag.RequestKey, r))
		if r.ProtoMajor == 2 && strings.HasPrefix(
			r.Header.Get("Content-Type"), "application/grpc") {
			rpc.ServeHTTP(w, r)
		} else {
			fileHandler.ServeHTTP(w, r)
		}
	})

	return PublicMux{mux}
}

// DebugMux has additional debugging endpoints attached.
type DebugMux struct {
	*http.ServeMux
}

// ProvideDebugMux is called by wire.
func ProvideDebugMux(
	metrics metrics.Handler,
	healthz Healthz,
) DebugMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.Handle("/healthz", healthz)
	mux.Handle("/varz", metrics)
	return DebugMux{mux}
}
