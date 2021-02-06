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

	"time"

	"github.com/bobvawter/cacheroach/api/capabilities"
	"github.com/bobvawter/cacheroach/api/principal"
	"github.com/bobvawter/cacheroach/api/session"
	"github.com/bobvawter/cacheroach/api/tenant"
	"github.com/bobvawter/cacheroach/api/token"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (c *CLI) session() *cobra.Command {
	top := &cobra.Command{
		Use:   "session",
		Short: "session management",
	}

	var capNames []string
	var duration time.Duration
	var name, note, pID string
	var onType, onID, onPath string
	delegate := &cobra.Command{
		Use:   "delegate",
		Short: "create a session and access token",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			conn, err := c.conn(cmd.Context())
			if err != nil {
				return err
			}

			req := &token.IssueRequest{Template: &session.Session{
				ID:        session.NewID(),
				ExpiresAt: timestamppb.New(time.Now().Add(duration).Round(time.Second)),
				Name:      name,
				Note:      note,
			}}

			if pID == "" {
				req.Template.PrincipalId = c.Session.PrincipalId
			} else if parsed, err := principal.ParseID(pID); err == nil {
				req.Template.PrincipalId = parsed
			} else {
				return errors.Wrap(err, "for")
			}

			if len(capNames) == 0 {
				req.Template.Capabilities = c.Session.Capabilities
			} else if parsed, err := capabilities.Parse(capNames); err == nil {
				req.Template.Capabilities = parsed
			} else {
				return errors.Wrap(err, "capabilities")
			}
			if req.Template.Capabilities.Zero() {
				return errors.New("missing required --capabilities")
			}

			switch onType {
			case "super":
				req.Template.Scope = &session.Scope{
					Kind: &session.Scope_SuperToken{
						SuperToken: true,
					}}

			case "principal":
				id, err := principal.ParseID(onID)
				if err != nil {
					return errors.Wrap(err, "onID")
				}
				req.Template.Scope = &session.Scope{
					Kind: &session.Scope_OnPrincipal{
						OnPrincipal: id,
					}}

			case "tenant":
				id, err := tenant.ParseID(onID)
				if err != nil {
					return errors.Wrap(err, "onID")
				}
				req.Template.Scope = &session.Scope{
					Kind: &session.Scope_OnLocation{
						OnLocation: &session.Location{
							TenantId: id,
							Path:     onPath,
						}}}
			default:
				return errors.Errorf("unknown --on value %q", onType)
			}

			data, err := token.NewTokensClient(conn).Issue(cmd.Context(), req)
			if err != nil {
				return err
			}
			out := newTabs()
			defer out.Close()
			out.Printf("Session ID\t%s\n", data.Issued.ID.AsUUID())
			out.Printf("JWT Token\t%s\n", data.Token.Jwt)
			return nil
		},
	}
	delegate.Flags().StringSliceVar(&capNames, "capabilities", nil,
		"the capabilities in the new session; defaults to capabilities of the logged-in principal")
	delegate.Flags().DurationVar(&duration, "duration", 10*365*24*time.Hour,
		"validity of issued token")
	delegate.Flags().StringVar(&name, "name", "",
		"provides a per-principal name for the session to make it easy to find programmatically")
	delegate.Flags().StringVar(&note, "note", "",
		"a note to further describe the session")
	delegate.Flags().StringVar(&pID, "for", "",
		"the ID of the principal receiving the delegation; defaults to the logged-in principal")
	delegate.Flags().StringVar(&onType, "on", "",
		"the type of scope being granted; one of (super, principal, tenant)")
	delegate.Flags().StringVar(&onID, "id", "",
		"the id of the principal or tenant being delegated")
	delegate.Flags().StringVar(&onPath, "path", "/*",
		"the path within a tenant being delegated")

	top.AddCommand(
		delegate,
		&cobra.Command{
			Use:   "ls",
			Short: "list all sessions for the current principal",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				conn, err := c.conn(cmd.Context())
				if err != nil {
					return err
				}
				data, err := token.NewTokensClient(conn).Find(cmd.Context(), &session.Scope{})
				if err != nil {
					return err
				}
				out := newTabs()
				defer out.Close()
				out.Printf("ID\tPrincipal\tName\tCaps\tType\tTarget ID\tPath\n")
				for {
					sn, err := data.Recv()
					if errors.Is(err, io.EOF) {
						return nil
					} else if err != nil {
						return err
					}
					out.Printf("%s\t%s\t%s\t%s\t", sn.ID.AsUUID(), sn.PrincipalId.AsUUID(), sn.Name, sn.Capabilities.Pretty())
					switch t := sn.Scope.Kind.(type) {
					case *session.Scope_SuperToken:
						out.Printf("SUPERTOKEN\t\t")
					case *session.Scope_OnPrincipal:
						out.Printf("Principal\t%s\t", t.OnPrincipal.AsUUID())
					case *session.Scope_OnLocation:
						out.Printf("Tenant\t%s\t%s", t.OnLocation.TenantId.AsUUID(), t.OnLocation.Path)
					default:
						out.Printf("unknown %T", t)
					}
					out.Printf("\n")
				}
			},
		},
		&cobra.Command{
			Use:   "rm <session id>",
			Short: "invalidate an active session",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				id, err := session.ParseID(args[0])
				if err != nil {
					return err
				}
				conn, err := c.conn(cmd.Context())
				if err != nil {
					return err
				}
				_, err = token.NewTokensClient(conn).Invalidate(cmd.Context(),
					&token.InvalidateRequest{Kind: &token.InvalidateRequest_ID{ID: id}})
				return err
			},
		},
	)

	return top
}
