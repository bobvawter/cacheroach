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

// Package config contains a JSON-serializable configuration file for
// use by the CLI tooling. This is a separate package to allow a
// browser-based user to download a ready-to-run configuration file from
// the server.
package config

import (
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/bobvawter/cacheroach/api/session"
	"github.com/bobvawter/cacheroach/api/tenant"
	"github.com/bobvawter/cacheroach/api/token"
	"golang.org/x/term"
	"google.golang.org/protobuf/proto"
)

// Config contains the JSON-serializable configuration data.
type Config struct {
	DefaultTenant *tenant.ID
	Host          string
	Insecure      bool
	Session       *session.Session
	Token         string
}

// Clone returns a deep copy of the Config.
func (c *Config) Clone() *Config {
	ret := &Config{
		Host:     c.Host,
		Insecure: c.Insecure,
		Token:    c.Token,
	}
	if c.DefaultTenant != nil {
		ret.DefaultTenant = proto.Clone(c.DefaultTenant).(*tenant.ID)
	}
	if c.Session != nil {
		ret.Session = proto.Clone(c.Session).(*session.Session)
	}
	return ret
}

// ConfigureHostname parses the given host as a URL and updates the Host
// and Insecure fields. The url must include a username and may include
// a password. If no password is provided, then one will be read in a
// secure fashion from the console.
func (c *Config) ConfigureHostname(urlString string, requirePassword bool) (*url.URL, error) {
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

// ConfigureSession extracts the elements from the IssueResponse.
func (c *Config) ConfigureSession(sn *session.Session, tkn *token.Token) {
	c.Session = sn
	c.Token = tkn.Jwt
}

// WriteTo writes the configuration to the given writer.
func (c *Config) WriteTo(w io.Writer) (int64, error) {
	counter := &countingWriter{Writer: w}
	e := json.NewEncoder(counter)
	e.SetIndent("", "  ")
	return counter.count, e.Encode(c)
}

// WriteToFile writes the configuration to disk. This method will create
// any necessary directories.
func (c *Config) WriteToFile(out string) error {
	out, err := filepath.Abs(out)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(out), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = c.WriteTo(f)
	return err
}

type countingWriter struct {
	io.Writer
	count int64
}

func (w *countingWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	w.count += int64(n)
	return n, err
}
