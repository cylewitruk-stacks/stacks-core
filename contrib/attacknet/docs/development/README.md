# Attacknet development

This guide is for maintainers extending the API, controllers, images,
observability, or evidence machinery. Operators should begin with the root
[`README.md`](../../README.md).

## Architecture boundaries

- Helm installs and upgrades the namespaced control plane.
- The topology operator owns `StacksNetwork`, actor ConfigMaps, Services,
  StatefulSets, admitted inventory, and network status. Its
  `UpgradeCampaign` reconciler advances rollout status while topology alone
  applies the cumulative workload overlay. It cannot inject faults.
- The run operator owns `BurnchainPolicy`, `FaultCampaign`, `AttacknetRun`,
  immutable schedules, bounded fault resources, and run-owned upgrade children.
- Bitcoin Core and the Stacks-blind burnchain clock are separate failure
  domains.
- Actor Pods have no Kubernetes service-account token.
- The typed Go CLI submits intent and reads status; controllers own admission,
  mutation, rollback, recovery, and terminal classification.

The Go module is under [`../../../helm/hacknet/operator/`](../../../helm/hacknet/operator/).
Do not create parallel API types or canonical encoders outside it.

## Public and compatibility interfaces

Build the supported CLI and inspect its machine contract:

```bash
(cd contrib/helm/hacknet/operator && go build -o /tmp/attacknet ./cmd/attacknet)
/tmp/attacknet commands --json
```

The v1alpha1 Node/shell prototype is retained by Git history, not as executable
code in the current tree. Immutable vectors under
[`../../test/fixtures/equivalence/`](../../test/fixtures/equivalence/) protect
the approved compatibility boundary without creating a second extension point.

## Local images

`attacknet image build` is the supported build workflow. The individual image
definitions are grouped under [`../../images/`](../../images/README.md):

```bash
/tmp/attacknet image build --repo-root "$(pwd)" --stacks
```

For low-level chart development, the Helm helper builds the same contexts:

```bash
BUILD_STACKS_IMAGE=1 contrib/helm/hacknet/scripts/build-local.sh
```

The Stacks image pins Rust and `cargo-chef`, uses `CARGO_INCREMENTAL=0`, and
separates dependency cooking from source compilation. See
[`image-packaging.md`](image-packaging.md) for provenance and debug-symbol
requirements.

Docker Desktop's host image store differs from containerd in each kind node.
The typed installer content-tags images, imports them into every kind node, and
verifies the selected platform's CRI image identity before Helm install.

## Topology and scenarios

Human-authored inputs are v1beta1 YAML. Start from the chart examples and use
the typed validator:

```bash
/tmp/attacknet validate --file contrib/helm/hacknet/examples/minimal.yaml
/tmp/attacknet validate --file contrib/helm/hacknet/examples/fault-campaign.yaml
/tmp/attacknet validate --file contrib/helm/hacknet/examples/attacknet-run.yaml
```

`StacksNetwork` supports per-actor images, configuration references, storage,
telemetry, probes, signer sets, and enrollment. Mixed-version plans and
modified-actor build inputs live under [`../../examples/`](../../examples/README.md).
Production images must not carry runtime adversary switches; modified behavior
belongs in separately built, provenance-bound images. See
[`../concepts/adversarial-actors.md`](../concepts/adversarial-actors.md).
The arbitrary-revision and upgrade-boundary workflow is documented in
[`Mixed-version networks and upgrades`](../concepts/mixed-version-images.md);
its release scope is specified in
[`R1A11 mixed-version and upgrade-boundary campaigns`](issues/r1/r1a11-mixed-version-upgrade-campaigns.md).

Release-scoped implementation plans live under [`issues/`](issues/). These are
planning artifacts, not release-gate contracts.

## Controller development

Follow controller-runtime conventions:

- keep reconcilers as orchestration, with rendering, compilation, identity,
  storage, and mechanism policy in focused packages;
- use cached clients for ordinary reconciliation and `APIReader` for the
  immediate pre-mutation identity barrier;
- use owner references and finalizers only for resources the controller owns;
- fail closed on identity, schedule, capability, or aggregate-budget drift;
- keep status monotonic and set `observedGeneration` only for reconciled state;
- never infer success from resource creation or Pod readiness alone.

The topology operator and run operator intentionally have separate namespaced
RBAC. Changes must preserve the exact structural RBAC allowlist.

## Instrumentation and observability

Instrumentation is an explicit image capability, not an image-tag assumption.
The 22-family contract records `merged`, `attacknet-patch`, or `unavailable`
provenance and requires runtime family-presence evidence for advertised
signals. Read [`../reference/instrumentation.md`](../reference/instrumentation.md)
before changing node/signer metrics or dashboard queries.

Grafana is a human view; raw Prometheus, Loki, Kubernetes, and event-journal
artifacts are the evidence sources. Observability helpers remain grouped under
[`../../observability/`](../../observability/README.md).

## Verification

Run the product and chart checks from the repository root:

```bash
bash contrib/attacknet/test/check.sh
bash contrib/helm/hacknet/scripts/check.sh
make -C contrib/helm/hacknet/operator verify
```

The product suite enforces the root allowlist, image paths, retired-runtime
absence, golden v1alpha1 equivalence, instrumentation, observability, and historical
release contracts. The operator suite covers unit tests, race checks, generated
artifacts, envtest when configured, and structural RBAC.

Live changes must capture admitted state rather than trusting requested YAML.
Preserve a failing environment until attribution and evidence capture are
complete, and add a regression assertion for every detector that previously
failed open.

## Documentation responsibilities

Keep documentation synchronized with each material product change:

- update the development roadmap and release baseline for status and scope;
- update this guide for architecture and extension-point changes;
- update the root README and `docs/operations/` for operator workflows;
- update examples and reference material for CRD or CLI changes; and
- update observability and evidence guidance when interpretation changes.

Documentation completeness is part of the implementation, not post-release
cleanup. Routine status recording after an approved amendment remains ordinary
review and does not require another qualification packet.
