# Attacknet development

This document is for maintainers extending the renderer, controllers, images,
assertions, or evidence machinery. End users should begin with
[`README.md`](README.md) and use the public `attacknet` facade.

## Architecture boundaries

- Helm installs and upgrades the namespaced control plane.
- `StacksNetwork` reconciles the system under test and has no fault permission.
- A separate run controller owns `FaultCampaign`, `AttacknetRun`, sealed
  schedules, and narrowly bounded fault resources.
- Bitcoin Core, its Stacks-blind clock, and cadence policy are separate failure
  domains.
- Actor Pods have no Kubernetes service-account token.
- Control-plane hardening must not prevent an admitted scenario from exposing
  actors to realistic disorder.
- Actor counts and loops derive from `manifest.json`; no harness code may embed
  a fixed signer count.
- Compose and Kubernetes render from the same topology model and execute the
  same assertions through a thin backend adapter.

Adaptive decisions remain outside the controllers. Agents submit bounded APIs
and observe status/evidence rather than receiving unrestricted cluster access.

## Public and internal interfaces

`contrib/attacknet/attacknet` and its versioned command registry are the public
interface:

```bash
contrib/attacknet/attacknet commands --json
contrib/attacknet/attacknet help
```

Helper scripts and their environment variables are internal unless explicitly
promoted into that registry. Tests should exercise the facade contract rather
than pinning helper implementation details.

## Local images

Build all control-plane/probe images and optionally the current Stacks image:

```bash
BUILD_STACKS_IMAGE=1 contrib/helm/hacknet/scripts/build-local.sh
docker build -t stacks-attacknet-stacker:local contrib/attacknet/stacker
```

The Stacks Dockerfile uses upstream's `release-lite` profile and adds only the
CA certificates and `curl` required by startup/evidence probes. It pins the
Rust toolchain and `cargo-chef`, separates dependency cooking from source
compilation, and sets `CARGO_INCREMENTAL=0`. Release artifacts retain the
repository's fat-LTO profile; local experiments avoid its single-codegen-unit
link cost.

BuildKit cache namespaces should be keyed by Rust version, `Cargo.lock`, and
target platform. Run descriptors must retain builder/runtime image digests,
recipe digest, invocation digest, output image digest, and attestation.

See [`IMAGE-PACKAGING.md`](IMAGE-PACKAGING.md) for the complete packaging and
provenance contract.

## Local `kind` image transport

Docker Desktop's image store differs from containerd in each `kind` node.
`contrib/helm/hacknet/scripts/install-local.sh` assigns content-derived tags,
imports exact controller images into every node, verifies them, and then runs
Helm.

For independently built actor images:

```bash
contrib/helm/hacknet/scripts/load-kind-images.sh \
  --mode=require \
  --output=receipt.json \
  IMAGE...
```

Retain the receipt with build and admission evidence. Registry deployments
must use immutable digest references rather than mutable local tags.

## Topology renderer

Render a topology offline:

```bash
node contrib/attacknet/topology.mjs \
  --network=attacknet-dev \
  --miners=1 --signers=1 --followers=1 \
  --probes=true \
  --output=contrib/attacknet/generated/dev
```

The renderer emits Kubernetes resources, actor configs, a shared manifest,
policy files, and Compose bootstrap/final/observability files. Kubernetes and
Compose must remain behaviorally comparable, but Kubernetes is canonical for
fault campaigns.

Startup dependencies are two-phase because signer nodes must complete initial
block download before live event observers are enabled. Do not create a second
startup implementation in a backend-specific harness.

## Mixed-version and modified actors

Per-actor overrides permit current, released, and deliberately modified
participants:

```bash
node contrib/attacknet/topology.mjs \
  --miners=3 --signers=10 --followers=5 \
  --actor-image=miner-3=stacks-core:v4.0.2 \
  --actor-image=signer-10=stacks-core:modified \
  --actor-env=signer-10:STACKS_SIGNER_TEST_DIRECTIVE=reject-all \
  --output=contrib/attacknet/generated/mixed
```

Modified directives belong only in separately built, provenance-bound
adversarial images. Production images must not carry a runtime adversary
switch. See [`ADVERSARIAL-ACTORS.md`](ADVERSARIAL-ACTORS.md).

For a reviewable matrix, compile
[`version-matrix.schema.json`](version-matrix.schema.json):

```bash
node contrib/attacknet/version-matrix.mjs \
  contrib/attacknet/examples/version-matrix.plan.json \
  --output=contrib/attacknet/generated/version-matrix.json
```

Planning mode permits mutable tags and incomplete provenance but marks the
result `acceptanceReady: false`. Acceptance mode requires digest-pinned actor,
builder, and runtime images plus build/attestation provenance. Source
resolution is offline: `current` resolves local `HEAD` and worktree state;
`releasedGitRef` resolves an already-present ref; `localModified` additionally
records the change ID, patch/untracked digest, and Dockerfile digest.

On Apple Silicon, `linux/arm64` is native. An amd64-only historical image must
declare emulation so timing/performance caveats enter evidence explicitly. See
[`MIXED-VERSION-IMAGES.md`](MIXED-VERSION-IMAGES.md).

## Instrumentation

Instrumentation is an explicit image capability, not an assumption inferred
from an image tag. The 22-family contract distinguishes `merged`,
`attacknet-patch`, and `unavailable` provenance, binds source/build/runtime
identity, and verifies required metric-family presence per actor.

Read [`INSTRUMENTATION.md`](INSTRUMENTATION.md) before changing node/signer
metrics or observability queries. Alert and dashboard behavior must remain
truthful for actors that legitimately lack a family.

## Controller development

The chart contains two singleton controllers:

- the topology operator reconciles actor ConfigMaps, Services, StatefulSets,
  telemetry, and network status;
- the run operator resolves immutable schedules and owns bounded fault
  resources and trusted helper Pods.

RBAC is namespaced and deliberately separated. The topology operator cannot
inject faults. The run operator can manage only its APIs, owner-bound schedule
ConfigMaps, five supported Chaos Mesh kinds, and the fixed I/O-pressure helper
Pod shape.

The local installer applies CRDs explicitly because Helm does not upgrade
existing files under `crds/`. It also uses content-derived rollout annotations;
do not use `kubectl set image`, which can create conflicting managed-field
ownership.

Read [`contrib/helm/hacknet/README.md`](../helm/hacknet/README.md) before
modifying controller lifecycle, PVC retention, token projection, readiness, or
fault admission.

## Verification

Run the complete offline suite from the repository root:

```bash
contrib/attacknet/check.sh
```

The suite covers the command registry, renderer and schemas, backend command
drift, campaign admission, observability, release contracts, Python
controllers, and the offline 31-workload render.

Before a live full-topology change:

```bash
contrib/attacknet/capacity-preflight.sh
```

Live work must capture admitted resources rather than trusting requested YAML.
Kubernetes LimitRange, ResourceQuota, image resolution, scheduling, and storage
binding can change the environment after rendering.

## Change discipline

- Preserve an active failed environment until evidence and attribution are
  complete.
- Record every new limitation in the external issue tracker and in the release
  baseline when it constrains an advertised capability.
- Do not treat configuration rendering, `AllInjected`, Pod readiness, or a
  dashboard screenshot as behavioral proof.
- Keep fault decisions bounded, seeded, ordered, and replayable.
- Add a regression assertion for every check that previously could not fail.

