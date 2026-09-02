# Attacknet documentation

The root [`README.md`](../README.md) is the operator quickstart. Supporting
material is grouped by audience and responsibility:

- [`concepts/`](concepts/) explains scheduling, minimization, reproducibility,
  [mixed versions and rolling upgrades](concepts/mixed-version-images.md),
  Bitcoin reorganizations and split views, and adversarial actors.
- [`operations/`](operations/) covers runtime operation, evidence, failure
  attribution, and [seeded fuzz sessions](operations/fuzzing.md).
- [`development/`](development/) covers image and controller development plus
  deferred work.
- [`reference/`](reference/) defines the
  [fault catalog](reference/faults/), Go CLI, instrumentation, and clock
  contracts.

The supported product surface is the typed Go CLI and the
`testing.stacks.org/v1beta1` API. Digest-verified v1alpha1 compatibility vectors
live under [`../test/fixtures/equivalence/`](../test/fixtures/equivalence/);
retired implementations are available only from their pinned Git revisions.
