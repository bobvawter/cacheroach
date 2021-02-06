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

	"github.com/bobvawter/cacheroach/api/tenant"
	"github.com/bobvawter/cacheroach/api/vhost"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (c *CLI) vhost() *cobra.Command {
	ret := &cobra.Command{
		Use:   "vhost",
		Short: "virtual-hosting configuration",
	}

	ret.AddCommand(
		&cobra.Command{
			Use:   "create <tenant ID> <hostname | *>",
			Short: "create a new virtual host",
			Args:  cobra.ExactArgs(2),
			RunE: func(cmd *cobra.Command, args []string) error {
				tnt, err := tenant.ParseID(args[0])
				if err != nil {
					return err
				}
				host := args[1]

				conn, err := c.conn(cmd.Context())
				if err != nil {
					return err
				}
				_, err = vhost.NewVHostsClient(conn).Ensure(cmd.Context(), &vhost.EnsureRequest{
					Vhost: &vhost.VHost{
						Vhost:    host,
						TenantId: tnt,
					},
				})
				if err == nil {
					c.logger.Infof("Success")
				}
				return err
			},
		},
		&cobra.Command{
			Use:   "ls",
			Short: "list all virtual hosts",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				conn, err := c.conn(cmd.Context())
				if err != nil {
					return err
				}
				data, err := vhost.NewVHostsClient(conn).List(cmd.Context(), &emptypb.Empty{})
				if err != nil {
					return err
				}
				out := newTabs()
				defer out.Close()
				out.Printf("%s\t%s\n", "Tenant ID", "Hostname")
				for {
					vh, err := data.Recv()
					if errors.Is(err, io.EOF) {
						break
					} else if err != nil {
						return err
					}
					out.Printf("%s\t%s\n", vh.TenantId.AsUUID(), vh.Vhost)
				}
				return nil
			},
		},
		&cobra.Command{
			Use:   "rm <tenant ID> <hostname | *>",
			Short: "remove a virtual host mapping",
			Args:  cobra.ExactArgs(2),
			RunE: func(cmd *cobra.Command, args []string) error {
				tnt, err := tenant.ParseID(args[0])
				if err != nil {
					return err
				}
				host := args[1]

				conn, err := c.conn(cmd.Context())
				if err != nil {
					return err
				}
				_, err = vhost.NewVHostsClient(conn).Ensure(cmd.Context(), &vhost.EnsureRequest{
					Vhost: &vhost.VHost{
						Vhost:    host,
						TenantId: tnt,
					},
					Delete: true,
				})
				if err == nil {
					c.logger.Infof("Success")
				}
				return err
			},
		},
	)

	return ret
}
