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
	"fmt"
	"io"

	"strconv"

	"github.com/bobvawter/cacheroach/api/tenant"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (c *CLI) tenant() *cobra.Command {
	ret := &cobra.Command{
		Use:   "tenant",
		Short: "tenant configuration",
	}

	ret.AddCommand(
		&cobra.Command{
			Use:   "create <tenant label>",
			Short: "create a new tenant",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				conn, err := c.conn(cmd.Context())
				if err != nil {
					return err
				}
				req := &tenant.EnsureRequest{
					Tenant: &tenant.Tenant{
						ID:    tenant.NewID(),
						Label: args[0],
					},
				}
				tnt, err := tenant.NewTenantsClient(conn).Ensure(cmd.Context(), req)
				if err != nil {
					return err
				}
				fmt.Println(tnt.Tenant.ID.AsUUID())
				return nil
			},
		},
		&cobra.Command{
			Use:   "default <tenant id>",
			Short: "set a default tenant ID for all future commands",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				id, err := tenant.ParseID(args[0])
				if err != nil {
					return err
				}
				c.DefaultTenant = id
				c.configDirty = true
				return nil
			},
		},
		&cobra.Command{
			Use:   "ls",
			Short: "list all tenants",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				conn, err := c.conn(cmd.Context())
				if err != nil {
					return err
				}
				data, err := tenant.NewTenantsClient(conn).List(cmd.Context(), &emptypb.Empty{})
				if err != nil {
					return err
				}
				out := newTabs()
				defer out.Close()
				out.Printf("ID\tVersion\tName\n")
				for {
					tnt, err := data.Recv()
					if errors.Is(err, io.EOF) {
						break
					} else if err != nil {
						return err
					}
					out.Printf("%s\t%d\t%s\n", tnt.ID.AsUUID(), tnt.Version, tnt.Label)
				}
				return nil
			},
		},
		&cobra.Command{
			Use:   "rm <tenant id> <tenant version>",
			Short: "delete a tenant",
			Args:  cobra.ExactArgs(2),
			RunE: func(cmd *cobra.Command, args []string) error {
				id, err := tenant.ParseID(args[0])
				if err != nil {
					return err
				}
				ver, err := strconv.Atoi(args[1])
				if err != nil {
					return err
				}
				conn, err := c.conn(cmd.Context())
				if err != nil {
					return err
				}

				req := &tenant.EnsureRequest{
					Tenant: &tenant.Tenant{
						ID:      id,
						Version: int64(ver),
					},
					Delete: true,
				}
				tnt, err := tenant.NewTenantsClient(conn).Ensure(cmd.Context(), req)
				if err != nil {
					return err
				}
				fmt.Println(tnt.Tenant.ID.AsUUID())
				return nil
			},
		},
	)

	return ret
}
