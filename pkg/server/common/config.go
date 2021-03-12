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

package common

import (
	"time"

	"net/http"

	"github.com/spf13/pflag"
)

// Config contains all of the flag-worthy configuration for a Server.
type Config struct {
	AssumeSecure       bool          // Treat all incoming connections as though they were secure.
	BindAddr           string        // The network address to bind the API to.
	CertBundle         string        // A path to a certificate bundle file.
	DebugAddr          string        // If set serve additional debugging endpoints.
	GenerateSelfSigned bool          // If true, a self-signed certificate will be created.
	GracePeriod        time.Duration // The time to allow connections to drain.
	PrivateKey         string        // A path to a private key file.

	OIDC struct {
		ClientID     string
		ClientSecret string
		Domains      []string // Allowable domains for provisioning
		Issuer       string   // OIDC discovery URL
	}
}

// Bind adds flags to the FlagSet.
func (c *Config) Bind(flags *pflag.FlagSet) {
	flags.BoolVar(&c.AssumeSecure, "assumeSecure", false,
		"set this if you have a TLS load-balancer connecting to cacheroach "+
			"over an unencrypted connection")
	flags.StringVar(&c.BindAddr, "bindAddr", ":0",
		"the local IP and port to bind to")
	flags.StringVar(&c.CertBundle, "certs", "",
		"a file that contains a certificate bundle")
	flags.StringVar(&c.DebugAddr, "debugAddr", "",
		"bind additional debugging endpoints, if set")
	flags.BoolVar(&c.GenerateSelfSigned, "selfSign", false,
		"generate self-signed certificates")
	flags.DurationVar(&c.GracePeriod, "gracePeriod", 10*time.Second,
		"the grace period for draining connections")
	flags.StringVar(&c.PrivateKey, "key", "",
		"a file that contains a private key")

	flags.StringVar(&c.OIDC.ClientID, "oidcClientID", "",
		"the OIDC client ID")
	flags.StringVar(&c.OIDC.ClientSecret, "oidcClientSecret", "",
		"the OIDC client secret")
	flags.StringSliceVar(&c.OIDC.Domains, "oidcDomains", nil,
		"acceptable user email domains")
	flags.StringVar(&c.OIDC.Issuer, "oidcIssuer", "",
		"the OIDC discovery base URL")

}

// IsSecure returns true if the request should be considered secure.
func (c *Config) IsSecure(r *http.Request) bool {
	return c.AssumeSecure || r.TLS != nil
}
