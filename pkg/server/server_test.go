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

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"io"

	"github.com/bobvawter/cacheroach/api/capabilities"
	"github.com/bobvawter/cacheroach/api/file"
	"github.com/bobvawter/cacheroach/api/principal"
	"github.com/bobvawter/cacheroach/api/session"
	"github.com/bobvawter/cacheroach/api/tenant"
	"github.com/bobvawter/cacheroach/api/token"
	"github.com/bobvawter/cacheroach/api/upload"
	"github.com/bobvawter/cacheroach/pkg/claims"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/oauth"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestSmoke(t *testing.T) {
	a := assert.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	rig, cleanup, err := testRig(ctx)
	if !a.NoError(err) {
		return
	}
	defer cleanup()

	pID := principal.NewID()
	p := &principal.Principal{
		ID:      pID,
		Version: 0,
	}
	if _, err := rig.principals.Ensure(ctx, &principal.EnsureRequest{Principal: p}); !a.NoError(err) {
		return
	}

	tID := tenant.NewID()
	if _, err := rig.tenants.Ensure(ctx, &tenant.EnsureRequest{Tenant: &tenant.Tenant{
		ID:    tID,
		Label: "Server testing",
	}}); !a.NoError(err) {
		return
	}

	var jwt string
	{
		issued, err := rig.tokens.Issue(ctx, &token.IssueRequest{Template: &session.Session{
			Capabilities: &capabilities.Capabilities{Read: true, Write: true},
			PrincipalId:  pID,
			Scope: &session.Scope{Kind: &session.Scope_OnLocation{OnLocation: &session.Location{
				TenantId: tID,
				Path:     "/*",
			}}},
			ExpiresAt: timestamppb.New(time.Now().Add(time.Hour).Round(time.Minute)),
		}})
		if !a.NoError(err) {
			return
		}
		jwt = issued.Token.Jwt
	}

	var superTokenOpt grpc.CallOption
	{
		issued, err := rig.tokens.Issue(ctx, &token.IssueRequest{Template: &session.Session{
			PrincipalId: pID,
			Scope:       &session.Scope{Kind: &session.Scope_SuperToken{SuperToken: true}},
			ExpiresAt:   timestamppb.New(time.Now().Add(time.Hour).Round(time.Minute)),
		}})
		if !a.NoError(err) {
			return
		}
		superTokenOpt = grpc.PerRPCCredentials(oauth.NewOauthAccess(
			&oauth2.Token{AccessToken: issued.Token.Jwt}))
	}

	tlsConfig := &tls.Config{RootCAs: x509.NewCertPool()}
	tlsConfig.RootCAs.AddCert(rig.certs[0].Leaf)

	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		}}

	foobar := fmt.Sprintf("https://localhost:%d/foobar.txt",
		rig.Server.BoundAddr.(*net.TCPAddr).Port)

	t.Run("404", func(t *testing.T) {
		a := assert.New(t)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, foobar, nil)
		if !a.NoError(err) {
			return
		}
		req.Header.Add("Authorization", "Bearer "+jwt)

		resp, err := client.Do(req)
		if !a.NoError(err) {
			return
		}
		a.Equal(http.StatusNotFound, resp.StatusCode)
	})

	t.Run("PUT", func(t *testing.T) {
		a := assert.New(t)
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, foobar,
			strings.NewReader("Hello World!"))
		if !a.NoError(err) {
			return
		}
		req.Header.Add("Authorization", "Bearer "+jwt)

		resp, err := client.Do(req)
		if !a.NoError(err) {
			return
		}
		a.Equal(http.StatusAccepted, resp.StatusCode)
	})

	t.Run("GET", func(t *testing.T) {
		a := assert.New(t)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, foobar, nil)
		if !a.NoError(err) {
			return
		}
		req.Header.Add("Authorization", "Bearer "+jwt)

		resp, err := client.Do(req)
		if !a.NoError(err) {
			return
		}
		a.Equal(http.StatusOK, resp.StatusCode)

		data, err := io.ReadAll(resp.Body)
		a.NoError(err)
		a.Equal("Hello World!", string(data))
	})

	t.Run("GET-bad-auth", func(t *testing.T) {
		a := assert.New(t)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, foobar, nil)
		if !a.NoError(err) {
			return
		}
		req.Header.Add("Authorization", "Bearer x"+jwt)

		resp, err := client.Do(req)
		if !a.NoError(err) {
			return
		}
		a.Equal(http.StatusNotFound, resp.StatusCode)
	})

	t.Run("testLoadPrincipalWithElision", func(t *testing.T) {
		a := assert.New(t)

		p := proto.Clone(p).(*principal.Principal)

		principals := principal.NewPrincipalsClient(rig.Conn)
		loaded, err := principals.Load(ctx,
			&principal.LoadRequest{Kind: &principal.LoadRequest_ID{ID: pID}}, superTokenOpt)
		if a.NoError(err) {
			a.True(loaded.Version >= p.Version)
			a.Nil(loaded.RefreshAfter)
			a.Empty(loaded.RefreshToken)
			a.Empty(loaded.Claims)
		}

		in, err := principals.List(ctx, &emptypb.Empty{}, superTokenOpt)
		if a.NoError(err) {
			received, err := in.Recv()
			if a.NoError(err) && proto.Equal(pID, received.ID) {
				a.Equal(loaded.String(), received.String())
			}
		}
		a.NoError(in.CloseSend())
	})

	t.Run("testBootstrapFlow", func(t *testing.T) {
		a := assert.New(t)

		_, tkn, err := claims.Sign(time.Now(), &session.Session{
			ExpiresAt:   timestamppb.New(time.Now().Add(time.Minute)),
			Note:        "CLI bootstrap supertoken",
			PrincipalId: nil,
			Scope:       &session.Scope{Kind: &session.Scope_SuperToken{SuperToken: true}},
		}, rig.cfg.SigningKeys[0])
		if !a.NoError(err) {
			return
		}
		creds := grpc.PerRPCCredentials(oauth.NewOauthAccess(&oauth2.Token{AccessToken: tkn.Jwt}))

		principals := principal.NewPrincipalsClient(rig.Conn)
		ret, err := principals.Ensure(ctx,
			&principal.EnsureRequest{Principal: &principal.Principal{}},
			creds)
		if !a.NoError(err) {
			return
		}
		a.NotNil(ret.Principal.ID)
		a.Equal(int64(1), ret.Principal.Version)

		tokens := token.NewTokensClient(rig.Conn)
		resp, err := tokens.Issue(ctx, &token.IssueRequest{
			Template: &session.Session{
				ExpiresAt:   timestamppb.New(time.Now().AddDate(0, 0, 1)),
				Note:        "cli bootstrap",
				PrincipalId: ret.Principal.ID,
				Scope:       &session.Scope{Kind: &session.Scope_SuperToken{SuperToken: true}},
			},
		}, creds)
		if a.NoError(err) {
			a.NotEmpty(resp.Token.Jwt)
		}
	})

	t.Run("rpc put and http get", func(t *testing.T) {
		a := assert.New(t)

		up := upload.NewUploadsClient(rig.Conn)
		creds := grpc.PerRPCCredentials(oauth.NewOauthAccess(
			&oauth2.Token{AccessToken: jwt}))

		bgn, err := up.Begin(ctx, &upload.BeginRequest{Tenant: tID, Path: "/rpc.test"}, creds)
		if !a.NoError(err) {
			return
		}

		trn, err := up.Transfer(ctx,
			&upload.TransferRequest{State: bgn.State, Data: ([]byte)("Hello World!")}, creds)
		if !a.NoError(err) {
			return
		}

		_, err = up.Commit(ctx, &upload.CommitRequest{State: trn.State}, creds)
		if !a.NoError(err) {
			return
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			fmt.Sprintf("https://localhost:%d/rpc.test",
				rig.Server.BoundAddr.(*net.TCPAddr).Port), nil)
		if !a.NoError(err) {
			return
		}
		req.Header.Add("authorization", "Bearer "+jwt)
		if !a.NoError(err) {
			return
		}

		resp, err := client.Do(req)
		if !a.NoError(err) {
			return
		}
		a.Equal(200, resp.StatusCode)

		data, err := io.ReadAll(resp.Body)
		if !a.NoError(err) {
			return
		}
		a.Equal("Hello World!", string(data))

		t.Run("signed requests", func(t *testing.T) {
			a := assert.New(t)
			retr, err := file.NewFilesClient(rig.Conn).Retrieve(ctx,
				&file.RetrievalRequest{
					Path:     "/rpc.test",
					Tenant:   tID,
					ValidFor: durationpb.New(time.Minute),
				}, creds)
			if !a.NoError(err) {
				return
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet,
				fmt.Sprintf("https://localhost:%d%s",
					rig.Server.BoundAddr.(*net.TCPAddr).Port, retr.GetPath), nil)
			if !a.NoError(err) {
				return
			}

			resp, err := client.Do(req)
			if !a.NoError(err) {
				return
			}
			a.Equal(200, resp.StatusCode)

			data, err := io.ReadAll(resp.Body)
			if !a.NoError(err) {
				return
			}
			a.Equal("Hello World!", string(data))
		})
	})

	t.Run("list my tenants", func(t *testing.T) {
		a := assert.New(t)
		creds := grpc.PerRPCCredentials(oauth.NewOauthAccess(
			&oauth2.Token{AccessToken: jwt}))

		data, err := tenant.NewTenantsClient(rig.Conn).List(ctx, &emptypb.Empty{}, creds)
		if !a.NoError(err) {
			return
		}

		tnt, err := data.Recv()
		if !a.NoError(err) {
			return
		}
		a.Equal(tID.String(), tnt.GetID().String())

		_, err = data.Recv()
		a.Equal(io.EOF, err)
	})
}
