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
	"io"

	"strconv"

	"github.com/bobvawter/cacheroach/api/principal"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (c *CLI) principal() *cobra.Command {
	ret := &cobra.Command{
		Use:   "principal",
		Short: "principal management",
	}

	var label, password string
	create := &cobra.Command{
		Use:   "create <username>",
		Short: "create a principal",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			conn, err := c.conn(cmd.Context())
			if err != nil {
				return err
			}
			req := &principal.EnsureRequest{
				Principal: &principal.Principal{
					ID:      principal.NewID(),
					Handles: []string{"username:" + args[0]},
				},
			}
			if label != "" {
				req.Principal.Label = label
			}
			if password != "" {
				req.Principal.PasswordSet = password
			}
			if _, err = principal.NewPrincipalsClient(conn).Ensure(cmd.Context(), req); err != nil {
				return err
			}
			c.logger.Info("Success")
			return nil
		},
	}
	create.Flags().StringVar(&label, "label", "",
		"set the principal's label (defaults to username)")
	create.Flags().StringVar(&password, "password", "",
		"set a password when creating the principal")

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
				out.Printf("ID\tVersion\tLabel\tHandles\n")
				for {
					p, err := data.Recv()
					if errors.Is(err, io.EOF) {
						break
					} else if err != nil {
						return err
					}
					out.Printf("%s\t%d\t%s", p.ID.AsUUID(), p.Version, p.Label)
					for i := range p.Handles {
						out.Printf("\t%s", p.Handles[i])
					}
					out.Printf("\n")
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
