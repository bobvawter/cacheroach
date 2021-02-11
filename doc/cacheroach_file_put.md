## cacheroach file put

upload files

```
cacheroach file put <remote path> <local file or dir> ... [flags]
```

### Options

```
  -h, --help              help for put
  -p, --parallelism int   the number of concurrent uploads (default 4)
  -r, --recurse           recursively upload directories
```

### Options inherited from parent commands

```
  -c, --config string   the location to load configuration data from (default "$HOME/.cacheroach/config")
  -t, --tenant string   sent the tenant to use if one is not present in the logged-in scope
  -v, --verbose count   enable logging, repeat for tracing
```

### SEE ALSO

* [cacheroach file](cacheroach_file.md)	 - file operations

