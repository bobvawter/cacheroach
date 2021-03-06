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
	"github.com/bobvawter/cacheroach/pkg/server/oidc"
)

// A Wrapper alters the behavior of an http.Handler.
type Wrapper func(http.Handler) http.Handler

// LatchWrapper holds and releases a latch when its enclosed handler is
// active.
type LatchWrapper Wrapper

// ProvideLatchWrapper is called by wire.
func ProvideLatchWrapper(latch common.BusyLatch) LatchWrapper {
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
	connector *oidc.Connector,
	tokens token.TokensServer,
) SessionWrapper {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var sn *session.Session
			// Find a JWT token somewhere in the request and validate it.
			if jwt := extractJWT(req); jwt != "" {
				var err error
				if sn, err = tokens.Validate(req.Context(), &token.Token{Jwt: jwt}); err != nil {
					sn = nil
				}
			}
			// Ensure that the principal is still valid.
			if sn != nil && connector.Validate(req.Context(), sn.PrincipalId) != nil {
				sn = nil
			}
			// Fall back to an unauthenticated session.
			if sn == nil {
				sn = bootstrap.PublicSession
			}
			ctx := session.WithSession(req.Context(), sn)
			req = req.WithContext(ctx)
			h.ServeHTTP(w, req)
		})
	}
}

// extractJWT extracts an un-validated JWT from the request.
func extractJWT(req *http.Request) string {
	if hdr := req.Header.Get("authorization"); strings.Index(hdr, "Bearer ") == 0 {
		return hdr[7:]
	}
	if p := req.URL.Query().Get("access_token"); p != "" {
		return p
	}
	if c, err := req.Cookie("authorization"); err == nil {
		return c.Value
	}
	return ""
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
