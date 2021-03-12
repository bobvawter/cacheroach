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

// Package oidc provide OpenID Connect integration for cacheroach.
package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Mandala/go-log"
	"github.com/bobvawter/cacheroach/api/capabilities"
	"github.com/bobvawter/cacheroach/api/principal"
	"github.com/bobvawter/cacheroach/api/session"
	"github.com/bobvawter/cacheroach/api/token"
	"github.com/bobvawter/cacheroach/pkg/bootstrap"
	"github.com/bobvawter/cacheroach/pkg/server/common"
	"github.com/bobvawter/cacheroach/pkg/store/util"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/wire"
	lru "github.com/hashicorp/golang-lru"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/oauth2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// These cookies are used during the authentication flow.
const (
	AuthorizationCookie = "authorization"
	DestinationCookie   = "cacheroach-destination"
	NonceCookie         = "cacheroach-oidc-nonce"
	StateCookie         = "cacheroach-oidc-state"
)

// ReceivePath will be added to the redirect path.
const ReceivePath = "/_/oidc/receive"

// ErrPermanentFailure indicates that the principal must be reauthorized
// by the OIDC provider in order to be usable.
var ErrPermanentFailure = errors.New("OIDC refresh needed")

// Set is used by wire.
var Set = wire.NewSet(
	ProvideConnector,
)

// Connector encapsulates the OIDC integration.
type Connector struct {
	cache           *lru.TwoQueueCache // UUID -> time.Time for refreshes
	cfg             *common.Config
	logger          *log.Logger
	p               *oidc.Provider
	principals      principal.PrincipalsServer
	tokens          token.TokensServer
	unauthenticated *principal.ID

	cacheHits             prometheus.Counter
	cacheMisses           prometheus.Counter
	dbHits                prometheus.Counter
	dbMisses              prometheus.Counter
	principalsCreated     prometheus.Counter
	principalsInvalidated prometheus.Counter
	principalsRefreshed   prometheus.Counter
	redirects             prometheus.Counter
	refreshFailures       prometheus.Counter
	sessionsCreated       prometheus.Counter
}

// ProvideConnector is called by wire.
func ProvideConnector(
	ctx context.Context,
	auto promauto.Factory,
	bt *bootstrap.Bootstrapper,
	cfg *common.Config,
	logger *log.Logger,
	principals principal.PrincipalsServer,
	tokens token.TokensServer,
) (*Connector, error) {
	for i := range cfg.OIDC.Domains {
		cfg.OIDC.Domains[i] = strings.ToLower(cfg.OIDC.Domains[i])
	}
	cache, err := lru.New2Q(10000)
	if err != nil {
		return nil, err
	}
	c := &Connector{
		cache:           cache,
		cfg:             cfg,
		logger:          logger,
		principals:      principals,
		tokens:          tokens,
		unauthenticated: bt.Unauthenticated,
		cacheHits: auto.NewCounter(prometheus.CounterOpts{
			Name: "oidc_cache_hit_total",
			Help: "the number of cached principal validations",
		}),
		cacheMisses: auto.NewCounter(prometheus.CounterOpts{
			Name: "oidc_cache_miss_total",
			Help: "the number of un-cached principal validations",
		}),
		dbHits: auto.NewCounter(prometheus.CounterOpts{
			Name: "oidc_db_hit_total",
			Help: "the number of times a valid token was found in the DB",
		}),
		dbMisses: auto.NewCounter(prometheus.CounterOpts{
			Name: "oidc_db_miss_total",
			Help: "the number of times a valid token was not found in the DB",
		}),
		principalsCreated: auto.NewCounter(prometheus.CounterOpts{
			Name: "oidc_created_principal_total",
			Help: "the number of new Principals created from OIDC redirects",
		}),
		principalsInvalidated: auto.NewCounter(prometheus.CounterOpts{
			Name: "oidc_invalidated_principal_total",
			Help: "the number of times a Principal was canceled by the OIDC provider",
		}),
		principalsRefreshed: auto.NewCounter(prometheus.CounterOpts{
			Name: "oidc_refreshed_principal_total",
			Help: "the number of times a Principal had its refresh token updated",
		}),
		redirects: auto.NewCounter(prometheus.CounterOpts{
			Name: "oidc_redirect_total",
			Help: "the number of redirects send to the OIDC provider",
		}),
		refreshFailures: auto.NewCounter(prometheus.CounterOpts{
			Name: "oidc_refresh_failure_total",
			Help: "the number of times the OIDC provider could not be contacted",
		}),
		sessionsCreated: auto.NewCounter(prometheus.CounterOpts{
			Name: "oidc_created_session_total",
			Help: "the number of cacheroach auth sessions created",
		}),
	}

	ok := cfg.OIDC.ClientID != "" &&
		cfg.OIDC.ClientSecret != "" &&
		cfg.OIDC.Issuer != "" &&
		len(cfg.OIDC.Domains) > 0
	if !ok {
		logger.Infof("OIDC integration not configured")
		return c, nil
	}

	c.p, err = oidc.NewProvider(ctx, cfg.OIDC.Issuer)
	if err == nil {
		end := c.p.Endpoint()
		logger.Infof("OIDC integration ready: %s %s", end.AuthURL, end.TokenURL)
	}

	return c, err
}

// Redirect implements an endpoint to redirect a caller to the OIDC
// provider. Once the flow has been successfully completed, the caller
// will be redirected to the given destination.
//
// This method returns true if it was able to generate a response.
func (c *Connector) Redirect(w http.ResponseWriter, r *http.Request, dest *url.URL) bool {
	if c.p == nil {
		return false
	}
	const cookieAge = 60
	secure := c.cfg.IsSecure(r)

	http.SetCookie(w, &http.Cookie{
		HttpOnly: true,
		MaxAge:   60,
		Name:     DestinationCookie,
		Path:     ReceivePath,
		Secure:   secure,
		Value:    dest.String(),
	})

	// State is relayed via the series of HTTP redirects.
	var state = make([]byte, 16)
	if _, err := rand.Read(state); err != nil {
		c.logger.Errorf("could not create random state: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return true
	}

	stateString := base64.RawURLEncoding.EncodeToString(state)
	http.SetCookie(w, &http.Cookie{
		HttpOnly: true,
		MaxAge:   cookieAge,
		Name:     StateCookie,
		Path:     ReceivePath,
		Secure:   secure,
		Value:    stateString,
	})

	// Nonce is relayed via the received JWT token.
	var nonce = make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		c.logger.Errorf("could not create random nonce: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return true
	}

	nonceString := base64.RawURLEncoding.EncodeToString(nonce)
	http.SetCookie(w, &http.Cookie{
		HttpOnly: true,
		MaxAge:   cookieAge,
		Name:     NonceCookie,
		Path:     ReceivePath,
		Secure:   secure,
		Value:    nonceString,
	})

	cfg := c.oauthConfig(r)
	u := cfg.AuthCodeURL(stateString, oauth2.AccessTypeOffline,
		oauth2.ApprovalForce, oidc.Nonce(nonceString))
	http.Redirect(w, r, u, http.StatusFound)
	c.redirects.Inc()
	return true
}

// Receive a JWT token from the OIDC provider to create a principal and
// issue a session token.
func (c *Connector) Receive(w http.ResponseWriter, r *http.Request) {
	cfg := c.oauthConfig(r)

	nonce, err := r.Cookie(NonceCookie)
	if err != nil {
		http.Error(w, "no nonce", http.StatusBadRequest)
		return
	}

	state, err := r.Cookie(StateCookie)
	if err != nil {
		http.Error(w, "no state", http.StatusBadRequest)
		return
	}
	if state.Value != r.URL.Query().Get("state") {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}

	exchanged, err := cfg.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		c.logger.Errorf("could not exchange OIDC code: %v", err)
		http.Error(w, "could not exchange OIDC code", http.StatusBadRequest)
		return
	}
	id, ok := exchanged.Extra("id_token").(string)
	if !ok {
		http.Error(w, "oauth2 token missing id_token OIDC field", http.StatusBadRequest)
		return
	}

	verified, err := c.p.Verifier(&oidc.Config{ClientID: c.cfg.OIDC.ClientID}).Verify(r.Context(), id)
	if err != nil {
		c.logger.Errorf("could not verify OIDC token: %v", err)
		http.Error(w, "could not verify OIDC token", http.StatusBadRequest)
		return
	}
	if nonce.Value != verified.Nonce {
		http.Error(w, "exchanged nonce did not match", http.StatusBadRequest)
		return
	}

	if c.logger.IsDebug() {
		var raw json.RawMessage
		_ = verified.Claims(&raw)
		c.logger.Tracef("verified OIDC credentials: %s", string(raw))
	}

	var claims struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
	}

	if err := verified.Claims(&claims); err != nil {
		c.logger.Errorf("could not extract claims: %v", err)
		http.Error(w, "could not extract claims", http.StatusBadRequest)
		return
	}

	if !claims.Verified {
		http.Error(w, "email not verified", http.StatusBadRequest)
		return
	}

	claims.Email = strings.ToLower(claims.Email)
	ok = false
	for _, domain := range c.cfg.OIDC.Domains {
		if strings.HasSuffix(claims.Email, "@"+domain) {
			ok = true
			break
		}
	}
	if !ok {
		http.Error(w, "email not in approved domains list", http.StatusBadRequest)
		return
	}

	c.logger.Tracef("ensuring account based on OIDC email: %s", claims.Email)

	// Create a fake super-token.
	ctx := session.WithSession(r.Context(), &session.Session{
		Scope: &session.Scope{
			Kind: &session.Scope_SuperToken{
				SuperToken: true,
			}}})

	// We'll always try to create a principal, relying on the uniqueness
	// constraints on the handles to prevent creation of unnecessary
	// data.
	var pID *principal.ID
	{
		var raw json.RawMessage
		_ = verified.Claims(&raw)
		resp, err := c.principals.Ensure(ctx, &principal.EnsureRequest{
			Principal: &principal.Principal{
				Claims:        raw,
				ID:            principal.NewID(),
				RefreshAfter:  timestamppb.New(exchanged.Expiry),
				RefreshStatus: principal.TokenStatus_VALID,
				RefreshToken:  exchanged.RefreshToken,
			}})
		if err == nil {
			pID = resp.GetPrincipal().GetID()
			c.principalsCreated.Inc()
		}
	}

	// We couldn't create a principal, so load it by email address.
	if pID == nil {
	save:
		p, err := c.principals.Load(ctx, &principal.LoadRequest{
			Kind: &principal.LoadRequest_Email{
				Email: claims.Email,
			}})
		if err != nil {
			c.logger.Errorf("could not create or find user: %v", err)
			http.Error(w, "could not create or find user", http.StatusInternalServerError)
			return
		}
		pID = p.ID

		// Record the updated token status.
		p.RefreshAfter = timestamppb.New(exchanged.Expiry)
		p.RefreshStatus = principal.TokenStatus_VALID
		p.RefreshToken = exchanged.RefreshToken
		_, err = c.principals.Ensure(ctx, &principal.EnsureRequest{Principal: p})
		if errors.Is(err, util.ErrVersionSkew) {
			goto save
		} else if err != nil {
			c.logger.Errorf("could not save refreshed OIDC token: %v", err)
			http.Error(w, "could not save refreshed OIDC token", http.StatusInternalServerError)
			return
		}
		c.principalsRefreshed.Inc()
	}

	issued, err := c.tokens.Issue(ctx, &token.IssueRequest{Template: &session.Session{
		Note:         "created via OIDC login",
		PrincipalId:  pID,
		Capabilities: capabilities.All(),
		Scope:        &session.Scope{Kind: &session.Scope_OnPrincipal{OnPrincipal: pID}},
		ExpiresAt:    timestamppb.New(time.Now().AddDate(10, 0, 0).Round(time.Minute)),
	}})
	if err != nil {
		c.logger.Errorf("could not issue OIDC token: %v", err)
		http.Error(w, "could not issue OIDC token", http.StatusInternalServerError)
		return
	}

	c.logger.Tracef("issued session %s from OIDC token", issued.Issued.ID.AsUUID())
	c.sessionsCreated.Inc()

	http.SetCookie(w, &http.Cookie{
		Expires:  issued.Issued.ExpiresAt.AsTime(),
		HttpOnly: true,
		Name:     AuthorizationCookie,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
		Value:    issued.Token.Jwt,
	})

	dest := "/"
	if found, err := r.Cookie(DestinationCookie); err == nil {
		dest = found.Value
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

// Validate ensures that the Principal is still valid, according to the OIDC provider.
func (c *Connector) Validate(ctx context.Context, pID *principal.ID) error {
	// The unauthenticated user is always valid.
	if pID.Zero() || proto.Equal(pID, c.unauthenticated) {
		return nil
	}
	now := time.Now()
	isAcceptable := func(when time.Time) bool {
		return when.IsZero() || when.After(now)
	}

	u := pID.AsUUID()
	if v, ok := c.cache.Get(u); ok {
		refreshAfter := v.(time.Time)
		if isAcceptable(refreshAfter) {
			c.cacheHits.Inc()
			return nil
		}
	}
	c.cacheMisses.Inc()

	// We're using the principal's version for locking purposes, so
	// we may need to restart this sequence.
top:
	p, err := c.principals.Load(ctx, &principal.LoadRequest{Kind: &principal.LoadRequest_ID{ID: pID}})
	if err != nil {
		return err
	}

	if p.RefreshStatus == principal.TokenStatus_PERMANENT_FAILURE {
		return ErrPermanentFailure
	}

	// Principals created via RPCs won't have a refresh token.  Treat
	// them as ok, and cache the result to keep from repeatedly hitting
	// the database.
	if p.RefreshToken == "" {
		c.cache.Add(u, now.Add(time.Hour))
		return nil
	}

	refreshAfter := p.GetRefreshAfter().AsTime()
	if isAcceptable(refreshAfter) {
		c.dbHits.Inc()
		c.cache.Add(u, refreshAfter)
		return nil
	}
	c.dbMisses.Inc()

	// Add some grace time while we refresh the principal.
	refreshAfter = now.Add(5 * time.Minute)
	c.cache.Add(u, refreshAfter)

	// Mark the principal as undergoing a refresh cycle.
	p.RefreshAfter = timestamppb.New(refreshAfter)
	p.RefreshStatus = principal.TokenStatus_REFRESHING
	resp, err := c.principals.Ensure(ctx, &principal.EnsureRequest{Principal: p})
	if errors.Is(err, util.ErrVersionSkew) {
		goto top
	} else if err != nil {
		return err
	}
	p = resp.Principal

	// Now we can attempt to refresh the token.
	var tkn *oauth2.Token
	if c.p == nil {
		tkn = &oauth2.Token{
			AccessToken:  "<access token>",
			RefreshToken: "<refresh token>",
			Expiry:       now.Add(time.Hour),
		}
	} else {
		src := c.oauthConfig(nil).TokenSource(ctx, &oauth2.Token{RefreshToken: p.RefreshToken})
		tkn, err = src.Token()
	}

	if r := (*oauth2.RetrieveError)(nil); errors.As(err, &r) {
		// OAuth2 spec says that bad tokens are reported as 400's. If
		// the user falls into this state, they can go back through the
		// provisioning process to restore access.
		if r.Response.StatusCode == http.StatusBadRequest {
			c.logger.Warnf("OIDC principal %s in permanent failure mode: %s", u, string(r.Body))
			c.cache.Remove(u)
			p.RefreshAfter = timestamppb.New(time.Time{})
			p.RefreshStatus = principal.TokenStatus_PERMANENT_FAILURE
			c.principalsInvalidated.Inc()
		} else {
			// Treat it as a temporary failure in case of 500's etc...
			c.logger.Warnf("could not refresh OIDC token for principal %s: %s", u, string(r.Body))
			c.refreshFailures.Inc()
			return err
		}
	} else if err != nil {
		return err
	} else {
		// Everything is refreshed, store the new data.
		c.cache.Add(u, tkn.Expiry)
		p.RefreshAfter = timestamppb.New(tkn.Expiry)
		p.RefreshStatus = principal.TokenStatus_VALID
		if tkn.RefreshToken != "" {
			p.RefreshToken = tkn.RefreshToken
		}
		c.logger.Tracef("refreshed OIDC token for %s", u)
		c.principalsRefreshed.Inc()
	}

	// Save the update, but only log the error since we do want the
	// enclosing API request to succeed.
	if _, err := c.principals.Ensure(ctx, &principal.EnsureRequest{Principal: p}); err != nil {
		c.logger.Warnf("error while refreshing OIDC token for %s: %v", u, err)
	}
	return err
}

func (c *Connector) oauthConfig(r *http.Request) *oauth2.Config {
	cfg := &oauth2.Config{
		ClientID:     c.cfg.OIDC.ClientID,
		ClientSecret: c.cfg.OIDC.ClientSecret,
		Endpoint:     c.p.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}
	if r != nil {
		u := &url.URL{
			Host:   r.Host,
			Path:   ReceivePath,
			Scheme: "https",
		}
		if !c.cfg.IsSecure(r) {
			u.Scheme = "http"
		}
		cfg.RedirectURL = u.String()
	}
	return cfg
}
