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
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"io"

	"github.com/bobvawter/cacheroach/api/auth"
	"github.com/bobvawter/cacheroach/api/capabilities"
	"github.com/bobvawter/cacheroach/api/file"
	"github.com/bobvawter/cacheroach/api/principal"
	"github.com/bobvawter/cacheroach/api/session"
	"github.com/bobvawter/cacheroach/api/tenant"
	"github.com/bobvawter/cacheroach/api/token"
	"github.com/bobvawter/cacheroach/api/upload"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/oauth"
	"google.golang.org/grpc/status"
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
	username := "you@example.com"
	passwd := "Str0ngPassword!"
	p := &principal.Principal{
		Handles: []string{"username:" + username},
		ID:      pID,
		Label:   "Some User",
		Version: 0,
	}
	a.NoError(p.SetPassword(passwd))
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

		data, err := ioutil.ReadAll(resp.Body)
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
		a.Equal(http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("log in and delegate", func(t *testing.T) {
		a := assert.New(t)

		ath := auth.NewAuthClient(rig.Conn)
		resp, err := ath.Login(ctx,
			&auth.LoginRequest{Handle: "username:" + username, Password: passwd})
		if !a.NoError(err) {
			return
		}
		a.Equal(pID.String(), resp.GetSession().GetPrincipalId().String())
		a.NotEmpty(resp.GetToken().GetJwt())
		creds := grpc.PerRPCCredentials(oauth.NewOauthAccess(&oauth2.Token{AccessToken: resp.Token.Jwt}))

		tokens := token.NewTokensClient(rig.Conn)
		sn, err := tokens.Current(ctx, &emptypb.Empty{}, creds)
		if a.NoError(err) {
			resp.GetSession().Note = "" // The note is stripped.
			a.Equal(resp.GetSession().String(), sn.String())
			a.True(resp.GetSession().Capabilities.GetDelegate())
		}

		// Create a delegated token.
		template := &session.Session{
			Capabilities: &capabilities.Capabilities{Read: true},
			PrincipalId:  pID,
			Scope: &session.Scope{Kind: &session.Scope_OnLocation{OnLocation: &session.Location{
				TenantId: tID,
				Path:     "/foo/bar",
			}}},
			ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
		}

		restricted, err := tokens.Issue(ctx, &token.IssueRequest{Template: template}, creds)
		if a.NoError(err) {
			a.Equal("/foo/bar", restricted.GetIssued().GetScope().GetOnLocation().GetPath())
			a.NotEqual(resp.Token.Jwt, restricted.Token.Jwt)
		}

		// Try creating a token on something we normally can't access.
		tOther := tenant.NewID()
		if _, err := rig.tenants.Ensure(ctx, &tenant.EnsureRequest{Tenant: &tenant.Tenant{
			ID:    tOther,
			Label: "More testing",
		}}); !a.NoError(err) {
			return
		}

		badTemplate := proto.Clone(template).(*session.Session)
		badTemplate.GetScope().GetOnLocation().TenantId = tOther
		_, err = tokens.Issue(ctx, &token.IssueRequest{Template: badTemplate}, creds)
		if a.Error(err) {
			s, _ := status.FromError(err)
			a.Equal(codes.PermissionDenied, s.Code())
		}

		// Try creating a token for another principal.
		pOther := principal.NewID()
		if _, err := rig.principals.Ensure(ctx, &principal.EnsureRequest{
			Principal: &principal.Principal{
				ID:          pOther,
				Label:       "More testing",
				PasswordSet: "Nothing",
			}}); !a.NoError(err) {
			return
		}

		badTemplate = proto.Clone(template).(*session.Session)
		badTemplate.PrincipalId = pOther
		_, err = tokens.Issue(ctx, &token.IssueRequest{Template: badTemplate}, creds)
		if a.Error(err) {
			s, _ := status.FromError(err)
			a.Equal(codes.PermissionDenied, s.Code())
		}
	})

	t.Run("testLoadPrincipalWithElision", func(t *testing.T) {
		a := assert.New(t)

		// We should have stored a hash in the original object.
		p := proto.Clone(p).(*principal.Principal)
		a.NotEmpty(p.PasswordHash)
		p.PasswordHash = ""

		principals := principal.NewPrincipalsClient(rig.Conn)
		loaded, err := principals.Load(ctx, pID, superTokenOpt)
		if a.NoError(err) {
			a.Equal(p.String(), loaded.String())
		}

		in, err := principals.List(ctx, &emptypb.Empty{}, superTokenOpt)
		if a.NoError(err) {
			loaded, err := in.Recv()
			if a.NoError(err) {
				a.Equal(p.String(), loaded.String())
			}
		}
		a.NoError(in.CloseSend())
	})

	t.Run("createPrincipalUsingSuperToken", func(t *testing.T) {
		a := assert.New(t)

		principals := principal.NewPrincipalsClient(rig.Conn)
		ret, err := principals.Ensure(ctx, &principal.EnsureRequest{Principal: &principal.Principal{
			Label:       "created",
			PasswordSet: "woot!",
		}}, superTokenOpt)
		if !a.NoError(err) {
			return
		}
		a.NotNil(ret.Principal.ID)
		a.Equal(int64(1), ret.Principal.Version)
	})

	t.Run("whoAmIFlow", func(t *testing.T) {
		a := assert.New(t)

		ath := auth.NewAuthClient(rig.Conn)
		resp, err := ath.Login(ctx, &auth.LoginRequest{Handle: "username:" + username, Password: passwd})
		if !a.NoError(err) {
			return
		}
		if !a.NoError(err) {
			return
		}
		sn := resp.Session

		creds := grpc.PerRPCCredentials(oauth.NewOauthAccess(
			&oauth2.Token{AccessToken: resp.Token.Jwt}))
		p, err := principal.NewPrincipalsClient(rig.Conn).Load(ctx, sn.PrincipalId, creds)
		if !a.NoError(err) {
			return
		}
		a.NotEmpty(p.Handles)
		a.Equal(pID.String(), p.ID.String())
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

		data, err := ioutil.ReadAll(resp.Body)
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

			data, err := ioutil.ReadAll(resp.Body)
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
