# Wire dependency injection

The cacheroach project uses [Wire](https://github.com/google/wire),
which provides compile-time dependency injection for Go. Wire takes care
of handling both set-up and tear-down of singleton service objects
within cacheroach.

## Rules

* Each package should expose a public
  [`ProviderSet`](https://pkg.go.dev/github.com/google/wire#ProviderSet)
  named `Set`.
* If [provider functions](https://github.com/google/wire/blob/master/docs/guide.md#defining-providers)
  are used to construct a stateful object, it should be in a
  ready-to-use state when it is returned from the provider.
  Stateful objects should return a [cleanup
  function](https://github.com/google/wire/blob/master/docs/guide.md#cleanup-functions)
  from the provider which will release any external resources.
* Packages that need to test injected types should define an unexported,
  minimally-scoped "test rig" injector type.