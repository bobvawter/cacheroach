## cacheroach file fetch

execute an HTTP request from the server

```
cacheroach file fetch <cacheroach path> <remote URL> ... [flags]
```

### Options

```
      --headers stringToString   remote request headers (default [])
  -h, --help                     help for fetch
      --method string            the http method to use (default "GET")
```

### Options inherited from parent commands

```
  -c, --config string   the location to load configuration data from (default "$HOME/.cacheroach/config")
      --tenant string   sent the tenant to use if one is not present in the logged-in scope
  -v, --verbose count   enable logging, repeat for tracing
```

### SEE ALSO

* [cacheroach file](cacheroach_file.md)	 - file operations

