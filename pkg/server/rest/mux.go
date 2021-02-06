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
	"net/http"
	"net/http/pprof"
	"strings"

	"context"

	"github.com/Mandala/go-log"
	"github.com/bobvawter/cacheroach/pkg/server/common"
	"github.com/bobvawter/cacheroach/pkg/server/diag"
	"google.golang.org/grpc"
)

// Mux has all functionality attached.
type Mux struct {
	*http.ServeMux
}

// ProvideMux is called by wire.
func ProvideMux(
	cfg *common.Config,
	logger *log.Logger,
	fileHandler FileHandler,
	healthz Healthz,
	retrieve Retrieve,
	rpc *grpc.Server,
) *Mux {
	mux := http.NewServeMux()

	if cfg.FilesOnly {
		mux.Handle("/_/v0/retrieve/", retrieve)
		mux.Handle("/_/", http.NotFoundHandler())
		mux.Handle("/", fileHandler)
		logger.Info("not binding RPC endpoints")
	} else {
		mux.HandleFunc("/_/debug/pprof/", pprof.Index)
		mux.HandleFunc("/_/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/_/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/_/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/_/debug/pprof/trace", pprof.Trace)
		mux.Handle("/_/healthz", healthz)
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
	}

	return &Mux{mux}
}
