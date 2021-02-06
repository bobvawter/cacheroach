## cacheroach completion

Generate completion script

### Synopsis

To load completions:

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


```
cacheroach completion [bash|zsh|fish|powershell]
```

### Options

```
  -h, --help   help for completion
```

### Options inherited from parent commands

```
  -v, --verbose count   enable logging, repeat for tracing
```

### SEE ALSO

* [cacheroach](cacheroach.md)	 - cacheroach is a file storage service built on CockroachDB

