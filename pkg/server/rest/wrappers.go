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
	"runtime/pprof"
	"strings"

	"github.com/Mandala/go-log"
	"github.com/bobvawter/cacheroach/api/session"
	"github.com/bobvawter/cacheroach/api/token"
	"github.com/bobvawter/cacheroach/api/vhost"
	"github.com/bobvawter/cacheroach/pkg/bootstrap"
	"github.com/bobvawter/cacheroach/pkg/server/common"
	"github.com/bobvawter/latch"
)

// A Wrapper alters the behavior of an http.Handler.
type Wrapper func(http.Handler) http.Handler

// BusyLatch holds a latch.Counter when there is an active request.
type BusyLatch struct {
	*latch.Counter
}

// ProvideBusyLatch is called by wire.
func ProvideBusyLatch() *BusyLatch {
	return &BusyLatch{latch.New()}
}

// LatchWrapper holds and releases a latch when its enclosed handler is
// active.
type LatchWrapper Wrapper

// ProvideLatchWrapper is called by wire.
func ProvideLatchWrapper(latch *BusyLatch) LatchWrapper {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			latch.Hold()
			h.ServeHTTP(w, req)
			latch.Release()
		})
	}
}

// PProfWrapper decorates the goroutines with additional pprof labels.
type PProfWrapper Wrapper

// ProvidePProfWrapper is called by wire.
func ProvidePProfWrapper() PProfWrapper {
	return func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			data := []string{"path", req.URL.Path, "method", req.Method}
			labels := pprof.Labels(data...)
			pprof.Do(req.Context(), labels, func(ctx context.Context) {
				req = req.WithContext(ctx)
				handler.ServeHTTP(w, req)
			})
		})
	}
}

// SessionWrapper will extract a validated session token from the
// incoming request or attach a "public" session.
type SessionWrapper Wrapper

// ProvideSessionWrapper is called by wire.
func ProvideSessionWrapper(
	bootstrap *bootstrap.Bootstrapper,
	tokens token.TokensServer,
) SessionWrapper {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var jwt string
			if hdr := req.Header.Get("authorization"); strings.Index(hdr, "Bearer ") == 0 {
				jwt = hdr[7:]
			} else if p := req.URL.Query().Get("access_token"); p != "" {
				jwt = p
			}
			sn := bootstrap.PublicSession
			if jwt != "" {
				var err error
				if sn, err = tokens.Validate(req.Context(), &token.Token{Jwt: jwt}); err != nil {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
			}
			ctx := session.WithSession(req.Context(), sn)
			req = req.WithContext(ctx)
			h.ServeHTTP(w, req)
		})
	}
}

// VHostWrapper will inject a VHost reference into the context.
type VHostWrapper Wrapper

// ProvideVHostWrapper is called by wire.
func ProvideVHostWrapper(
	logger *log.Logger,
	mapper *common.VHostMap,
) VHostWrapper {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := req.Context()

			// Defer to a session that already defines a tenant
			var host *vhost.VHost
			if tnt := session.FromContext(ctx).GetScope().GetOnLocation().GetTenantId(); tnt != nil {
				host = &vhost.VHost{TenantId: tnt}
			} else {
				host = mapper.Resolve(req.Host)
			}

			if host == nil {
				w.WriteHeader(http.StatusNotFound)
				logger.Trace("no vhost found")
				return
			}
			logger.Tracef("vhost %s", host)
			ctx = vhost.WithVHost(ctx, host)
			req = req.WithContext(ctx)
			h.ServeHTTP(w, req)
		})
	}
}
