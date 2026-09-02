# Attacknet product tests

This directory owns cross-subsystem product contracts:

- [`contracts/`](contracts/) enforces repository, packaging, and security
  boundaries.
- [`equivalence/`](equivalence/) compares the Go implementation with the
  frozen, approved v1alpha1 reference.
- [`fixtures/`](fixtures/) contains test-only adversarial inputs.
- [`integration/`](integration/) is reserved for product integration fixtures
  and tests that do not belong to one subsystem.
- [`support/`](support/) contains shared test helpers.

Run the offline product suite from the repository root:

```bash
bash contrib/attacknet/test/check.sh
```

Subsystem tests remain beside the code they exercise.
