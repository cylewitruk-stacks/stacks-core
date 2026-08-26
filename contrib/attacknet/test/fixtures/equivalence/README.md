# Equivalence fixtures

These immutable vectors preserve the approved v1alpha1 topology and fault
contracts without shipping or executing the retired JavaScript and shell
runtime.

[`v1alpha1/manifest.json`](v1alpha1/manifest.json) binds every vector by SHA-256
and records the exact reviewed revisions and oracle paths that produced it.
Normal tests only verify and consume the committed vectors. Maintainers may
reproduce them from a full Git clone with:

```bash
node contrib/attacknet/test/support/generate-v1alpha1-equivalence-fixtures.mjs
```

Regeneration is a compatibility-contract change and requires review of the
origin revision, every input, and every output.
