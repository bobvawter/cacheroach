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

// Package start implements a command.
package start

import (
	"context"

	"github.com/Mandala/go-log"
	"github.com/bobvawter/cacheroach/pkg/cache"
	"github.com/bobvawter/cacheroach/pkg/server/common"
	"github.com/bobvawter/cacheroach/pkg/store/config"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type bound interface {
	Bind(flags *pflag.FlagSet)
}
type configured interface {
	Configure(ctx context.Context) error
}

// Command returns the start command.
func Command(
	logger *log.Logger,
) *cobra.Command {

	cacheCfg := &cache.Config{}
	storeCfg := &config.Config{}
	svrCfg := &common.Config{}

	cfgs := []bound{
		cacheCfg,
		storeCfg,
		svrCfg,
	}

	cmd := &cobra.Command{
		Use:   "start",
		Short: "start the server",
		RunE: func(cmd *cobra.Command, _ []string) error {
			for _, cfg := range cfgs {
				if x, ok := cfg.(configured); ok {
					if err := x.Configure(cmd.Context()); err != nil {
						return err
					}
				}
			}

			_, cleanup, err := newInjector(cmd.Context(), cacheCfg, storeCfg, svrCfg, logger)
			if err != nil {
				logger.Errorf("could not start: %v", err)
				return err
			}
			// cleanup won't return until all requests are drained
			defer cleanup()

			<-cmd.Context().Done()

			return nil
		},
	}
	for _, cfg := range cfgs {
		cfg.Bind(cmd.Flags())
	}
	return cmd
}
