# Attacknet examples

Human-authored Kubernetes resources in this directory use v1beta1 YAML. Check
them locally with `attacknet validate --file FILE` before submission.

Examples are grouped by intent:

- [`campaigns/`](campaigns/) contains single `FaultCampaign` scenarios.
- [`runs/`](runs/) contains scheduled or minimization-oriented `AttacknetRun`
  inputs.
- [`matrices/`](matrices/) contains human-authored source, image, configuration,
  assignment, and upgrade plans.
- [`fuzzing/`](fuzzing/) contains inert campaign templates and a finite seeded
  local-kind session plan. See the
  [operator guide](../docs/operations/fuzzing.md) before running it unattended.

[`campaigns/signer-withhold-window.yaml`](campaigns/signer-withhold-window.yaml)
observes one deterministic testing signer declared by
[`../../helm/hacknet/examples/adversarial-signer.yaml`](../../helm/hacknet/examples/adversarial-signer.yaml).
Apply the accompanying burnchain policy and network first, then submit the
campaign before its Stacks-height trigger. Its signed report proves a bounded
testing-policy attempt; network impact still requires independent protocol
assertions.

Version plans are YAML because operators author them. `attacknet version
prepare` produces canonical, digest-bound JSON descriptors; runtime evidence,
generated receipts, and replay descriptors also remain canonical JSON.

[`matrices/stable-with-candidate.plan.yaml`](matrices/stable-with-candidate.plan.yaml)
mixes a released remote ref with the current local checkout and defines a
bounded three-stage rollout. [`matrices/raw-config-fallback.plan.yaml`](matrices/raw-config-fallback.plan.yaml)
shows the optional Secret-backed compatibility escape hatch. Its private
config file is intentionally not included in the repository.

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
