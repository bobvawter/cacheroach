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
	"encoding/json"
	"html/template"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/Mandala/go-log"
	"github.com/bobvawter/cacheroach/api/capabilities"
	"github.com/bobvawter/cacheroach/api/principal"
	"github.com/bobvawter/cacheroach/api/session"
	"github.com/bobvawter/cacheroach/api/vhost"
	cliConfig "github.com/bobvawter/cacheroach/pkg/cmd/cli/config"
	"github.com/bobvawter/cacheroach/pkg/enforcer"
	"github.com/bobvawter/cacheroach/pkg/server/common"
	"github.com/bobvawter/cacheroach/pkg/server/oidc"
	"github.com/bobvawter/cacheroach/pkg/store/blob"
	"github.com/bobvawter/cacheroach/pkg/store/fs"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"
)

// CLIConfigHandler allows a user to download a ready-to-run CLI configuration file.
type CLIConfigHandler http.Handler

// ProvideCLIConfigHandler is called by wire.
func ProvideCLIConfigHandler(
	cfg *common.Config,
	latchWrapper LatchWrapper,
	pprofWrapper PProfWrapper,
	sessionWrapper SessionWrapper,
	vhostWrapper VHostWrapper,
) CLIConfigHandler {
	fn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-disposition", `attachment; filename="cacheroach.cfg"`)
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = makeConfig(r.Context(), r, cfg.IsSecure(r)).WriteTo(w)
	})

	return wrap(fn, latchWrapper, vhostWrapper, sessionWrapper, pprofWrapper)
}

func makeConfig(ctx context.Context, r *http.Request, secure bool) *cliConfig.Config {
	sn := session.FromContext(ctx)
	vh := vhost.FromContext(ctx)

	host := r.Host
	if _, _, err := net.SplitHostPort(host); err == nil {
		// Already has a port number
	} else if secure {
		host += ":443"
	} else {
		host += ":80"
	}

	return &cliConfig.Config{
		DefaultTenant: vh.GetTenantId(),
		Host:          host,
		Insecure:      !secure,
		Session:       sn,
		Token:         extractJWT(r),
	}
}

// FileHandler implements a traditional web-server.
type FileHandler http.Handler

// ProvideFileHandler is called by wire.
func ProvideFileHandler(
	blobs *blob.Store,
	enforcer *enforcer.Enforcer,
	f *fs.Store,
	logger *log.Logger,
	pprofWrapper PProfWrapper,
	latchWrapper LatchWrapper,
	sessionWrapper SessionWrapper,
	vHostWrapper VHostWrapper,
) FileHandler {
	fn := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		sn := session.FromContext(req.Context())
		if sn == nil {
			w.Header().Add("WWW-Authenticate", "Bearer")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		h := vhost.FromContext(ctx)
		if h == nil {
			w.WriteHeader(http.StatusNotFound)
			logger.Trace("no vhost in context")
			return
		}

		f := f.FileSystem(h.TenantId)

		check := func(caps *capabilities.Capabilities) (bool, error) {
			return enforcer.Check(ctx, &capabilities.Rule{Kind: &capabilities.Rule_May{
				May: &capabilities.SessionReference{
					Capabilities: caps,
					Scope: &capabilities.ScopeReference{Kind: &capabilities.ScopeReference_OnLocation{
						OnLocation: &capabilities.LocationReference{
							TenantId: &capabilities.Reference{Kind: &capabilities.Reference_Context{
								Context: capabilities.ContextReference_VHOST_TENANT,
							}},
							Path: &capabilities.Reference{Kind: &capabilities.Reference_StringValue{
								StringValue: req.URL.Path}},
						},
					}}}}})
		}

		switch req.Method {
		case http.MethodDelete:
			if ok, err := check(&capabilities.Capabilities{Write: true}); err != nil {
				logger.Errorf("%s %v", req.URL, err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			} else if !ok {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if err := f.Delete(ctx, req.URL.Path); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				logger.Debugf("delete: %v", err)
				return
			}
			w.WriteHeader(http.StatusOK)

		case http.MethodGet, http.MethodHead, http.MethodOptions:
			if ok, err := check(&capabilities.Capabilities{Read: true}); err != nil {
				logger.Errorf("%s %v", req.URL, err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			} else if !ok {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			http.FileServer(http.FS(f)).ServeHTTP(w, req)

		case http.MethodPost, http.MethodPut:
			if ok, err := check(&capabilities.Capabilities{Write: true}); err != nil {
				logger.Errorf("%s %v", req.URL, err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			} else if !ok {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			hash, err := blobs.EnsureBlob(ctx, f.Tenant(), req.Body)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				logger.Debugf("put: %v", err)
				return
			}
			_ = req.Body.Close()
			meta := &fs.FileMeta{
				Path:    req.URL.Path,
				Tenant:  f.Tenant(),
				Version: -1, // Unconditionally overwrite.
			}
			if err := f.Put(ctx, meta, hash); err != nil {
				w.WriteHeader(http.StatusNotFound)
				logger.Debugf("put: %v", err)
				return
			}
			w.WriteHeader(http.StatusAccepted)
			w.Write([]byte(hash.String()))

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	return wrap(fn, latchWrapper, vHostWrapper, sessionWrapper, pprofWrapper)
}

// Healthz verifies database connectivity.
type Healthz http.Handler

// ProvideHealthz is called by wire.
func ProvideHealthz(db *pgxpool.Pool, logger *log.Logger) Healthz {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx, cancel := context.WithTimeout(req.Context(), time.Second)
		defer cancel()

		var count int
		err := db.QueryRow(ctx, "SELECT 1").Scan(&count)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			logger.Errorf("failed health check: %v", err)
			return
		}
		w.Header().Set("content-type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
}

// Retrieve implements the signed-URL endpoint.
type Retrieve http.Handler

// ProvideRetrieve is called by wire.
func ProvideRetrieve(
	logger *log.Logger,
	fs *fs.Store,
	pprofWrapper PProfWrapper,
	latchWrapper LatchWrapper,
	sessionWrapper SessionWrapper,
	vHostWrapper VHostWrapper,
) Retrieve {
	fn := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		sn := session.FromContext(ctx)

		if !sn.GetCapabilities().GetRead() {
			logger.Trace("did not have read capability")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		loc := sn.GetScope().GetOnLocation()
		if loc == nil {
			logger.Tracef("unexpected token scope: %s", sn.GetScope())
			w.WriteHeader(http.StatusForbidden)
			return
		}

		f, err := fs.FileSystem(loc.TenantId).OpenVersion(ctx, loc.Path, loc.Version)
		if errors.Is(err, os.ErrNotExist) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err != nil {
			logger.Infof("error reading file: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
		http.ServeContent(w, req, f.Name(), f.ModTime(), f)
	})

	return wrap(fn, latchWrapper, vHostWrapper, sessionWrapper, pprofWrapper)
}

// Provision hosts a trivial landing page to trigger OIDC login.
type Provision http.Handler

// ProvideProvision is called by wire.
func ProvideProvision(
	cfg *common.Config,
	connector *oidc.Connector,
	logger *log.Logger,
	principals principal.PrincipalsServer,
	pprofWrapper PProfWrapper,
	latchWrapper LatchWrapper,
	sessionWrapper SessionWrapper,
	vHostWrapper VHostWrapper,
) (Provision, error) {
	type Data struct {
		Config string
		P      *principal.Principal
		Port   int
	}

	tmpl, err := template.New("landing").Parse(`
<!DOCTYPE html>
<html><head><title>Hello Cacheroach!</title></head>
<body>Hello {{.P.Label}} aka Principal {{.P.ID.AsUUID}}!<br/>
{{if and .Config .Port}}
<form name="f" method="POST" target="_self" action="http://localhost:{{.Port}}/" >
<input name="config" value="{{.Config}}" type="hidden" />
</form>
<script>document.f.requestSubmit()</script>
{{end}}
Install CLI locally with <code>go get github.com/bobvawter/cacheroach</code><br/>
<a href="config">Click here</a> to download a CLI configuration file and move it to <code>$HOME/.cacheroach/config</code><br/>
Test your setup with <code>cacheroach auth whoami</code>
</body></html>
`)
	if err != nil {
		return nil, err
	}

	fn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sn := session.FromContext(r.Context())

		if proto.Equal(principal.Unauthenticated, sn.PrincipalId) {
			if !connector.Redirect(w, r, r.URL) {
				http.Error(w, "not logged in and no OIDC provider", http.StatusUnauthorized)
			}
			return
		}

		p, err := principals.Load(r.Context(), &principal.LoadRequest{
			Kind: &principal.LoadRequest_ID{ID: sn.PrincipalId}})
		if err != nil {
			logger.Errorf("could not load principal %s: %v", sn.PrincipalId.AsUUID(), err)
			http.Error(w, "could not load principal", http.StatusInternalServerError)
			return
		}

		data := &Data{P: p}
		if raw := r.URL.Query().Get("port"); raw != "" {
			data.Port, err = strconv.Atoi(raw)
			if err != nil {
				http.Error(w, "bad port value", http.StatusBadRequest)
				return
			}

			buf, _ := json.Marshal(makeConfig(r.Context(), r, cfg.IsSecure(r)))
			data.Config = string(buf)
		}

		w.Header().Add("content-type", "text/html; charset=utf-8")
		if err := tmpl.Execute(w, data); err != nil {
			logger.Errorf("could not execute template: %v", err)
		}
	})
	return wrap(fn, latchWrapper, vHostWrapper, sessionWrapper, pprofWrapper), nil
}

func wrap(h http.Handler, wrappers ...func(http.Handler) http.Handler) http.Handler {
	for i := range wrappers {
		h = wrappers[i](h)
	}
	return h
}
