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

The multi-Bitcoin example is composed from six single-document resources:

- [`../../helm/hacknet/examples/multi-bitcoin-policy-a.yaml`](../../helm/hacknet/examples/multi-bitcoin-policy-a.yaml)
  bootstraps the shared chain;
- [`../../helm/hacknet/examples/multi-bitcoin-policy-b.yaml`](../../helm/hacknet/examples/multi-bitcoin-policy-b.yaml)
  starts paused and follows the primary node;
- [`../../helm/hacknet/examples/multi-bitcoin.yaml`](../../helm/hacknet/examples/multi-bitcoin.yaml)
  declares the Bitcoin graph and Stacks bindings;
- [`campaigns/bitcoin-competing-branches.yaml`](campaigns/bitcoin-competing-branches.yaml)
  is an inert campaign template that holds a Bitcoin P2P partition while the
  bounded A9 reorganization worker creates a higher-work competing branch; and
- [`campaigns/bitcoin-propagation-delay.yaml`](campaigns/bitcoin-propagation-delay.yaml)
  is an inert template for bounded latency on one admitted Bitcoin edge; and
- [`runs/bitcoin-split-view.yaml`](runs/bitcoin-split-view.yaml) proves the
  Bitcoin and bound Stacks cohorts diverge, then remain converged for a stable
  recovery window.

Submit both policies before the network, then submit the templates and run.
The example is regtest-only and requires `allowBurnchain`, bounded
reorganization budgets, and the exact admitted Bitcoin graph. It does not
expose arbitrary Bitcoin RPC.

Immutable v1alpha1 compatibility vectors live under
[`../test/fixtures/equivalence/`](../test/fixtures/equivalence/); they are not
supported authoring examples. Use `attacknet convert` for the bounded legacy
resource kinds it supports.
