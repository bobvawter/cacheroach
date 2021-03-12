## cacheroach bootstrap

create a super-user principal using the server's HMAC key

### Synopsis

This command should be used to create an initial user on a newly-created cacheroach installation. It requires access to the server's HMAC key that is used to sign tokens. The resulting session will have superuser access; the resulting configuration file should be treated with the same security as the key.

```
cacheroach bootstrap [flags] https://cacheroach.server/
```

### Options

```
  -c, --config string    the location to load configuration data from (default "$HOME/.cacheroach/config")
  -h, --help             help for bootstrap
      --hmacKey string   the base64-encoded HMAC key (or @/path/to/file)
      --validity int     the number of days the session will be valid for (default 365)
```

### Options inherited from parent commands

```
  -v, --verbose count   enable logging, repeat for tracing
```

### SEE ALSO

* [cacheroach](cacheroach.md)	 - cacheroach is a file storage service built on CockroachDB

