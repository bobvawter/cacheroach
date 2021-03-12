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
	"encoding/json"
	"io"
	"strconv"
	"time"

	"github.com/bobvawter/cacheroach/api/capabilities"
	"github.com/bobvawter/cacheroach/api/principal"
	"github.com/bobvawter/cacheroach/api/session"
	"github.com/bobvawter/cacheroach/api/token"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (c *CLI) principal() *cobra.Command {
	ret := &cobra.Command{
		Use:   "principal",
		Short: "principal management",
	}

	var createDomain, createOut string
	create := &cobra.Command{
		Use:   "create <username>",
		Short: "create a principal",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			username := args[0]
			conn, err := c.conn(cmd.Context())
			if err != nil {
				return err
			}
			claimBytes, err := json.Marshal(map[string]string{
				"name":   username,
				"source": "cli principal",
			})
			if err != nil {
				return err
			}
			req := &principal.EnsureRequest{
				Principal: &principal.Principal{
					ID:          principal.NewID(),
					Claims:      claimBytes,
					EmailDomain: createDomain,
				},
			}
			prn, err := principal.NewPrincipalsClient(conn).Ensure(cmd.Context(), req)
			if err != nil {
				return err
			}

			// Give the user access to itself
			iss, err := token.NewTokensClient(conn).Issue(cmd.Context(), &token.IssueRequest{
				Template: &session.Session{
					ExpiresAt:    timestamppb.New(time.Now().AddDate(1, 0, 0).Round(time.Second)),
					Capabilities: capabilities.All(),
					Name:         "<self>",
					Scope: &session.Scope{Kind: &session.Scope_OnPrincipal{
						OnPrincipal: prn.Principal.ID,
					}},
					PrincipalId: prn.Principal.ID,
				}})
			if err != nil {
				return err
			}

			cfg := c.Config.Clone()
			cfg.Session = iss.Issued
			cfg.Token = iss.Token.Jwt

			if createOut == "" {
				createOut = username + ".cfg"
			}
			if err := cfg.WriteToFile(createOut); err != nil {
				return err
			}
			c.logger.Infof("Wrote configuration to %s", createOut)
			out := newTabs()
			defer out.Close()
			out.Printf("Principal ID\t%s\n", prn.Principal.ID.AsUUID())
			return nil
		},
	}
	create.Flags().StringVar(&createDomain, "emailDomain", "",
		"create a unique principal that represents all principals with "+
			"an email address in the given domain")
	create.Flags().StringVarP(&createOut, "out", "o", "",
		"write a new configuration file, defaults to username.cfg")

	ret.AddCommand(
		create,
		&cobra.Command{
			Use:   "ls",
			Short: "list all principals",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				conn, err := c.conn(cmd.Context())
				if err != nil {
					return err
				}
				data, err := principal.NewPrincipalsClient(conn).List(cmd.Context(), &emptypb.Empty{})
				if err != nil {
					return err
				}
				out := newTabs()
				defer out.Close()
				out.Printf("ID\tVersion\tLabel\tDomain\tClaims\n")
				for {
					p, err := data.Recv()
					if errors.Is(err, io.EOF) {
						break
					} else if err != nil {
						return err
					}
					out.Printf("%s\t%d\t%s\t%s\t%s\n", p.ID.AsUUID(), p.Version, p.Label, p.EmailDomain, p.Claims)
				}
				return nil
			},
		},
		&cobra.Command{
			Use:   "rm <principal id> <principal version>",
			Short: "delete a principal",
			Args:  cobra.ExactArgs(2),
			RunE: func(cmd *cobra.Command, args []string) error {
				id, err := principal.ParseID(args[0])
				if err != nil {
					return errors.Wrapf(err, "%q", args[0])
				}
				ver, err := strconv.Atoi(args[1])
				if err != nil {
					return err
				}

				conn, err := c.conn(cmd.Context())
				if err != nil {
					return err
				}

				req := &principal.EnsureRequest{
					Delete: true,
					Principal: &principal.Principal{
						ID:      id,
						Version: int64(ver),
					}}
				_, err = principal.NewPrincipalsClient(conn).Ensure(cmd.Context(), req)
				if err != nil {
					return err
				}
				c.logger.Info("Success")
				return nil
			},
		},
	)
	return ret
}
