# Attacknet documentation

The root [`README.md`](../README.md) is the operator quickstart. Supporting
material is grouped by audience and responsibility:

- [`concepts/`](concepts/) explains scheduling, minimization, reproducibility,
  mixed versions, and adversarial actors.
- [`operations/`](operations/) covers runtime operation, evidence, and failure
  attribution.
- [`development/`](development/) covers image and controller development plus
  deferred work.
- [`reference/`](reference/) defines the Go CLI, instrumentation, and clock
  contracts.

The supported product surface is the typed Go CLI and the
`testing.stacks.org/v1beta1` API. Historical v1alpha1 implementation material
lives under [`../legacy/`](../legacy/README.md).
