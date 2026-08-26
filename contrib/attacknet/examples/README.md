# Attacknet examples

Human-authored Kubernetes resources in this directory use v1beta1 YAML. Check
them locally with `attacknet validate --file FILE` before submission.

Examples are grouped by intent:

- [`campaigns/`](campaigns/) contains single `FaultCampaign` scenarios.
- [`runs/`](runs/) contains scheduled or minimization-oriented `AttacknetRun`
  inputs.
- [`matrices/`](matrices/) contains machine-consumed image and version plans.

The `*.plan.json` files are intentionally JSON: they are machine-consumed
image-build and mixed-version planning inputs, not Kubernetes resources.
Runtime evidence, generated manifests, digests, and replay descriptors also
remain canonical JSON.

Legacy v1alpha1 compatibility fixtures live under
`../testdata/legacy-v1alpha1/`; they are not supported authoring examples. Use
`attacknet convert` for the bounded legacy resource kinds it supports.
