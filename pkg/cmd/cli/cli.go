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

// Package cli contains the bulk of command-line tools that call
// RPC methods on a cacheroach server.
package cli

import (
	"encoding/json"
	"os"

	"path/filepath"

	"context"
	"crypto/tls"
	"crypto/x509"

	"github.com/Mandala/go-log"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"
)

// CLI contains common state for the command-line tooling.
type CLI struct {
	config

	configDirty bool
	configFile  string
	logger      *log.Logger
}

// Commands returns the CLI commands.
func Commands(logger *log.Logger) []*cobra.Command {
	c := &CLI{logger: logger}
	cmds := []*cobra.Command{
		c.auth(),
		c.boostrap(),
		c.file(),
		c.principal(),
		c.session(),
		c.tenant(),
		c.vhost(),
	}

	for _, added := range cmds {
		// The Cobra library doesn't have a built-in chaining mechanism.
		pre := added.PersistentPreRunE
		added.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
			if fn := added.Parent().PersistentPreRunE; fn != nil {
				if err := fn(cmd, args); err != nil {
					return err
				}
			}
			if err := c.start(cmd, args); err != nil {
				return err
			}
			if pre != nil {
				return pre(cmd, args)
			}
			return nil
		}

		post := added.PersistentPostRunE
		added.PersistentPostRunE = func(cmd *cobra.Command, args []string) error {
			if post != nil {
				if err := post(cmd, args); err != nil {
					return err
				}
			}
			if err := c.stop(cmd, args); err != nil {
				return err
			}
			if fn := added.Parent().PersistentPostRunE; fn != nil {
				return fn(cmd, args)
			}
			return nil
		}

		added.PersistentFlags().StringVarP(&c.configFile, "config", "c",
			"$HOME/.cacheroach/config",
			"the location to load configuration data from")
	}
	return cmds
}

func (c *CLI) conn(ctx context.Context) (*grpc.ClientConn, error) {
	opts := []grpc.DialOption{
		grpc.WithAuthority(c.Host),
		grpc.WithBlock(),
		grpc.WithUserAgent("cacheroach"),
	}
	if c.Host == "" {
		return nil, errors.New("no hostname configured; try auth login")
	}
	if c.Token != "" {
		var creds credentials.PerRPCCredentials
		if c.Insecure {
			creds = &insecureCredentials{c.Token}
		} else {
			creds = oauth.NewOauthAccess(&oauth2.Token{AccessToken: c.Token})
		}
		opts = append(opts, grpc.WithPerRPCCredentials(creds))
	}
	if c.Insecure {
		c.logger.Warn("connection is insecure")
		opts = append(opts, grpc.WithInsecure())
	} else {
		systemRoots, err := x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		creds := credentials.NewTLS(&tls.Config{
			RootCAs: systemRoots,
		})
		opts = append(opts, grpc.WithTransportCredentials(creds))
	}
	ret, err := grpc.DialContext(ctx, c.Host, opts...)
	if err == nil {
		c.logger.Trace("connected")
	}
	return ret, err
}

func (c *CLI) start(*cobra.Command, []string) error {
	p := os.ExpandEnv(c.configFile)
	f, err := os.Open(p)
	if errors.Is(err, os.ErrNotExist) {
		c.logger.Errorf("could not open configuration file %s", p)
		return nil
	} else if err != nil {
		return err
	}
	defer f.Close()
	return json.NewDecoder(f).Decode(&c.config)
}

func (c *CLI) stop(*cobra.Command, []string) error {
	if !c.configDirty {
		return nil
	}
	p := os.ExpandEnv(c.configFile)
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(&c.config); err != nil {
		return err
	}
	c.logger.Infof("wrote configuration to: %s", p)
	return nil
}
