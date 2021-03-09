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
	"context"
	"encoding/base64"
	"io"
	"strings"
	"time"

	"github.com/bobvawter/cacheroach/api/principal"
	"github.com/bobvawter/cacheroach/api/session"
	"github.com/bobvawter/cacheroach/api/token"
	"github.com/bobvawter/cacheroach/pkg/claims"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type bootstrap struct {
	*CLI
	hmacKey   string
	validDays int
}

func (c *CLI) boostrap() *cobra.Command {
	params := &bootstrap{CLI: c}
	ret := &cobra.Command{
		Use:   "bootstrap [flags] https://username[:password]@cacheroach.server/",
		Short: "create a super-user principal using the server's HMAC key",
		Long: "This command should be used to create an initial user on a newly-created " +
			"cacheroach installation. It requires access to the server's HMAC key that is used " +
			"to sign tokens. The resulting session will have superuser access; the resulting " +
			"configuration file should be treated with the same security as the key.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return params.execute(cmd.Context(), args)
		},
	}
	f := ret.Flags()
	f.StringVar(&params.hmacKey, "hmacKey", "", "the base64-encoded HMAC key (or @/path/to/file)")
	f.IntVar(&params.validDays, "validity", 365, "the number of days the session will be valid for")
	return ret
}

func (b *bootstrap) execute(ctx context.Context, args []string) error {
	u, err := b.configureHostname(args[0], false)
	if err != nil {
		return err
	}
	if b.hmacKey == "" {
		return errors.New("supertoken is required")
	}

	hmacData, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, strings.NewReader(b.hmacKey)))
	if err != nil {
		return err
	}

	_, tkn, err := claims.Sign(time.Now(), &session.Session{
		ExpiresAt: timestamppb.New(time.Now().Add(time.Minute)),
		Note:      "CLI bootstrap supertoken",
		Scope:     &session.Scope{Kind: &session.Scope_SuperToken{SuperToken: true}},
	}, hmacData)
	if err != nil {
		return err
	}

	b.Token = tkn.Jwt

	conn, err := b.conn(ctx)
	if err != nil {
		return err
	}

	p := &principal.Principal{
		Handles: []string{"username:" + u.User.Username()},
		Label:   u.User.Username(),
		ID:      principal.NewID(),
	}
	if pwd, ok := u.User.Password(); ok {
		p.PasswordSet = pwd
	}
	req := &principal.EnsureRequest{Principal: p}
	_, err = principal.NewPrincipalsClient(conn).Ensure(ctx, req)
	if err != nil {
		return err
	}
	b.logger.Tracef("created principal: %s", p.ID.AsUUID())

	resp, err := token.NewTokensClient(conn).Issue(ctx, &token.IssueRequest{
		Template: &session.Session{
			ExpiresAt:   timestamppb.New(time.Now().AddDate(0, 0, b.validDays)),
			Note:        "cli bootstrap",
			PrincipalId: p.ID,
			Scope:       &session.Scope{Kind: &session.Scope_SuperToken{SuperToken: true}},
		},
	})
	if err != nil {
		return err
	}
	b.logger.Tracef("issued session: %s", resp.Issued.ID.AsUUID())

	b.configureSession(resp.Issued, resp.Token)
	b.configDirty = true
	return nil
}
