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

// Package root contains the top-level cacheroach command definition.
package root

import (
	"context"
	"os"
	"strings"

	"github.com/Mandala/go-log"
	"github.com/bobvawter/cacheroach/pkg/cmd/cli"
	"github.com/bobvawter/cacheroach/pkg/cmd/start"
	"github.com/spf13/cobra"
)

// Execute is the main entry point for cacheroach.
func Execute(ctx context.Context) error {
	logger := log.New(os.Stderr).Quiet()

	// Cacheroach is delivered in a single-file image, so there's no
	// shell to perform environment expansion. We'll also take this
	// as an opportunity to "at-expand", treating any arguments that
	// begin with an @ as a reference to a file to be read in.
	for i := range os.Args {
		s := os.ExpandEnv(os.Args[i])

		if len(s) > 0 && s[0] == '@' {
			data, err := os.ReadFile(s[1:])
			if err != nil {
				logger.Errorf("args[%d]: %v", i, err)
				return err
			}
			s = string(data)
		}
		os.Args[i] = strings.TrimSpace(s)
	}
	rootCmd := Command(logger)
	err := rootCmd.ExecuteContext(ctx)
	if err != nil {
		logger.NoQuiet()
		logger.Errorf("%v", err)
	}
	return err
}

// Command is exposed for the documentation generator. Use Execute().
func Command(logger *log.Logger) *cobra.Command {
	var verbose int
	rootCmd := &cobra.Command{
		Use:           "cacheroach",
		Short:         "cacheroach is a file storage service built on CockroachDB",
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			if verbose > 0 {
				logger.NoQuiet()
				if verbose > 1 {
					logger.WithDebug()
					logger.Tracef("args are: %v", os.Args)
				}
			}
			return nil
		},
	}
	rootCmd.PersistentFlags().CountVarP(&verbose, "verbose", "v", "enable logging, repeat for tracing")
	rootCmd.AddCommand(
		completionCmd,
		start.Command(logger),
	)
	rootCmd.AddCommand(cli.Commands(logger)...)

	return rootCmd
}

// Taken from https://github.com/spf13/cobra/blob/master/shell_completions.md
var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate completion script",
	Long: `To load completions:

Bash:

$ source <(yourprogram completion bash)

# To load completions for each session, execute once:
Linux:
  $ yourprogram completion bash > /etc/bash_completion.d/yourprogram
MacOS:
  $ yourprogram completion bash > /usr/local/etc/bash_completion.d/yourprogram

Zsh:

# If shell completion is not already enabled in your environment you will need
# to enable it.  You can execute the following once:

$ echo "autoload -U compinit; compinit" >> ~/.zshrc

# To load completions for each session, execute once:
$ yourprogram completion zsh > "${fpath[1]}/_yourprogram"

# You will need to start a new shell for this setup to take effect.

Fish:

$ yourprogram completion fish | source

# To load completions for each session, execute once:
$ yourprogram completion fish > ~/.config/fish/completions/yourprogram.fish

Powershell:

PS> yourprogram completion powershell | Out-String | Invoke-Expression

# To load completions for every new session, run:
PS> yourprogram completion powershell > yourprogram.ps1
# and source this file from your powershell profile.
`,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.ExactValidArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		switch args[0] {
		case "bash":
			cmd.Root().GenBashCompletion(os.Stdout)
		case "zsh":
			cmd.Root().GenZshCompletion(os.Stdout)
		case "fish":
			cmd.Root().GenFishCompletion(os.Stdout, true)
		case "powershell":
			cmd.Root().GenPowerShellCompletion(os.Stdout)
		}
	},
}
