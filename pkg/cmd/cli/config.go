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

package cli

import (
	"net/url"
	"strings"
	"syscall"

	"context"

	"github.com/bobvawter/cacheroach/api/session"
	"github.com/bobvawter/cacheroach/api/tenant"
	"github.com/bobvawter/cacheroach/api/token"
	"github.com/pkg/errors"
	"golang.org/x/term"
)

// config contains the JSON-serializable configuration data.
type config struct {
	DefaultTenant *tenant.ID
	Host          string
	Insecure      bool
	Session       *session.Session
	Token         string
}

// configureHostname parses the given host as a URL and updates the Host
// and Insecure fields. The url must include a username and may include
// a password. If no password is provided, then one will be read in a
// secure fashion from the console.
func (c *config) configureHostname(urlString string, requirePassword bool) (*url.URL, error) {
	u, err := url.Parse(urlString)
	if err != nil {
		return nil, err
	}

	if u.User.Username() == "" {
		return nil, errors.New("must specify a username")
	}
	if requirePassword {
		password, _ := u.User.Password()
		if password == "" {
			print("Enter password: ")
			data, err := term.ReadPassword(syscall.Stdin)
			if err != nil {
				return nil, err
			}
			password = string(data)
			println()
			u.User = url.UserPassword(u.User.Username(), password)
		}
		if password == "" {
			return nil, errors.New("a password is required")
		}
	}

	c.Host = u.Host
	c.Token = ""

	switch strings.ToLower(u.Scheme) {
	case "http":
		c.Insecure = true
		if u.Port() == "" {
			c.Host += ":80"
		}
	case "https":
		c.Insecure = false
		if u.Port() == "" {
			c.Host += ":443"
		}
	}
	return u, nil
}

// configureSession extracts the elements from the IssueResponse.
func (c *config) configureSession(sn *session.Session, tkn *token.Token) {
	c.Session = sn
	c.Token = tkn.Jwt
}

// A wrapper around a proper credentials that will disable the GRPC code
// path requiring secure transport.
type insecureCredentials struct {
	token string
}

func (c *insecureCredentials) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": "Bearer " + c.token,
	}, nil
}

func (c *insecureCredentials) RequireTransportSecurity() bool {
	return false
}
