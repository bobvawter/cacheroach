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
	"github.com/bobvawter/cacheroach/api/auth"
	"github.com/bobvawter/cacheroach/api/session"
	"github.com/bobvawter/cacheroach/api/token"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (c *CLI) auth() *cobra.Command {
	top := &cobra.Command{
		Use:   "auth",
		Short: "authentication services",
	}
	top.AddCommand(
		&cobra.Command{
			Use:   "login https://username[:password]@cacheroach.server/",
			Short: "log into a cacheroach server",
			Long: "if a password is not specified, " +
				"it will be securely prompted for",
			Args: cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				u, err := c.configureHostname(args[0], true)
				if err != nil {
					return err
				}
				password, _ := u.User.Password()

				conn, err := c.conn(cmd.Context())
				if err != nil {
					return err
				}
				client := auth.NewAuthClient(conn)
				resp, err := client.Login(cmd.Context(), &auth.LoginRequest{
					Handle:   "username:" + u.User.Username(),
					Password: password,
				})
				if err != nil {
					return err
				}

				c.configureSession(resp.Session, resp.Token)
				c.configDirty = true

				return nil
			},
		},
		&cobra.Command{
			Use:   "logout",
			Short: "destroy authentication",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				conn, err := c.conn(cmd.Context())
				if err != nil {
					return err
				}
				if _, err := token.NewTokensClient(conn).Invalidate(cmd.Context(),
					&token.InvalidateRequest{Kind: &token.InvalidateRequest_Current{
						Current: true}}); err != nil {
					c.logger.Warnf("could not invalidate session on server: %v", err)
				}

				c.config.Token = ""
				c.configDirty = true
				return nil
			},
		},
		&cobra.Command{
			Use:   "set https://<JWT auth token>@cacheroach.server/",
			Short: "log in using an authentication token",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				u, err := c.configureHostname(args[0], false)
				if err != nil {
					return err
				}

				c.Token = u.User.Username()

				conn, err := c.conn(cmd.Context())
				if err != nil {
					return err
				}
				resp, err := token.NewTokensClient(conn).Current(cmd.Context(), &emptypb.Empty{})
				if err != nil {
					return err
				}

				c.Session = resp
				c.configDirty = true

				return nil
			},
		},
		&cobra.Command{
			Use:   "whoami",
			Short: "show the current principal",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				conn, err := c.conn(cmd.Context())
				if err != nil {
					return err
				}

				out := newTabs()
				defer out.Close()

				s, err := token.NewTokensClient(conn).Current(cmd.Context(), &emptypb.Empty{})
				if err != nil {
					return err
				}

				out.Printf("Principal\t%s\n", s.PrincipalId.AsUUID())
				out.Printf("Session\t%s\n", s.ID.AsUUID())
				out.Printf("Name\t%s\n", s.Name)
				out.Printf("Expires\t%s\n", s.ExpiresAt.AsTime().String())
				out.Printf("Scope\t")
				switch t := s.Scope.Kind.(type) {
				case *session.Scope_SuperToken:
					out.Printf("SUPERTOKEN")
				case *session.Scope_OnPrincipal:
					out.Printf("Principal\t%s", t.OnPrincipal.AsUUID())
				case *session.Scope_OnLocation:
					out.Printf("Tenant\t%s\t%s", t.OnLocation.TenantId.AsUUID(), t.OnLocation.Path)
				default:
					out.Printf("%T", t)
				}
				out.Printf("\n")
				out.Printf("Capabilities\t%s\n", s.Capabilities)
				out.Printf("Note\t%s\n", s.Note)

				return nil
			},
		},
	)
	return top
}
