## cacheroach session delegate

create a session and access token

```
cacheroach session delegate [flags]
```

### Options

```
      --capabilities strings   the capabilities in the new session; defaults to capabilities of the logged-in principal
      --duration duration      validity of issued token (default 87600h0m0s)
      --for string             the ID of the principal receiving the delegation; defaults to the logged-in principal
  -h, --help                   help for delegate
      --id string              the id of the principal or tenant being delegated
      --name string            provides a per-principal name for the session to make it easy to find programmatically
      --note string            a note to further describe the session
      --on string              the type of scope being granted; one of (super, principal, tenant)
      --path string            the path within a tenant being delegated (default "/*")
```

### Options inherited from parent commands

```
  -c, --config string   the location to load configuration data from (default "$HOME/.cacheroach/config")
  -v, --verbose count   enable logging, repeat for tracing
```

### SEE ALSO

* [cacheroach session](cacheroach_session.md)	 - session management

