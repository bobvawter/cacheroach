## cacheroach start

start the server

```
cacheroach start [flags]
```

### Options

```
      --assumeSecure                   set this if you have a TLS load-balancer connecting to cacheroach over an unencrypted connection
      --bindAddr string                the local IP and port to bind to (default ":0")
      --cacheDir string                persistent cache location
      --cacheDiskSpace int             the size (in megabytes) of the persistent cache (default 1024)
      --cacheMemory int                the size (in megabytes) of the in-memory cache (default 256)
      --certs string                   a file that contains a certificate bundle
      --chunkConcurrency int           the number of concurrent chunk operations (default 16)
      --chunkSize int                  the desired size for newly-stored chunks (default 524288)
      --connect string                 the database connection string (default "postgres://root@localhost:26257/cacheroach")
      --debugAddr string               bind additional debugging endpoints, if set
      --gracePeriod duration           the grace period for draining connections (default 10s)
  -h, --help                           help for start
      --key string                     a file that contains a private key
      --oidcClientID string            the OIDC client ID
      --oidcClientSecret string        the OIDC client secret
      --oidcDomains strings            acceptable user email domains
      --oidcIssuer string              the OIDC discovery base URL
      --purgeDuration duration         the length of time for which deleted data should be retained; set to 0 to disable (default 168h0m0s)
      --purgeLimit int                 the deletion batch size to use when purging old data; set to 0 to disable (default 1000)
      --readAmplificationBackoff int   slow chunk insertions if the CockroachDB cluster's read amplification rises above this (default 10)
      --selfSign                       generate self-signed certificates
      --signingKey strings             a base64-encoded HMAC signing key or @/path/to/base64.key
      --uploadTimeout duration         the timeout for any multi-part upload process (default 1h0m0s)
```

### Options inherited from parent commands

```
  -v, --verbose count   enable logging, repeat for tracing
```

### SEE ALSO

* [cacheroach](cacheroach.md)	 - cacheroach is a file storage service built on CockroachDB

