# Hacknet operator

Hacknet is the Kubernetes control plane for disposable Stacks regtest and
adversarial networks. It reconciles actor workloads, executes bounded fault
campaigns, and records status suitable for humans and automation.

This is test infrastructure, not a production Stacks operator. Use only
generated regtest keys and funds with no value.

## Start here

Most users should follow the product-level
[Attacknet guide](../../attacknet/README.md). It covers the supported public
CLI, topology rendering, observability, fault execution, evidence capture, and
teardown.

Use this document when you need to install or operate the Hacknet controllers,
submit custom resources directly, or develop the chart. Raw helper scripts and
custom-resource layouts are lower-level interfaces; the typed Go `attacknet`
client is the Release 1 automation boundary.

## What the chart installs

Hacknet installs two namespaced controller managers with separate service
accounts:

- the topology operator reconciles `StacksNetwork` resources into ConfigMaps,
  Services, StatefulSets, PVCs, and optional telemetry/probe sidecars, and
  reconciles `BurnchainPolicy` resources into externally steerable clock
  workloads; it also applies sealed `UpgradeCampaign` overlays while remaining
  the only actor-workload writer;
- the run operator reconciles `FaultCampaign` and `AttacknetRun` resources and
  has narrowly scoped permissions for supported Chaos Mesh resources; and
- both controllers expose health and Prometheus endpoints through namespaced
  Services.

The local installer applies all five CRDs before running Helm so an existing
installation receives schema updates. Helm intentionally leaves those CRDs
installed when the release is removed.

Hacknet does **not** install or configure:

- Docker Desktop or Kubernetes;
- Chaos Mesh;
- host tools such as Helm, `kubectl`, Docker, or Go;
- Stacks actor images; or
- the per-network Prometheus, Grafana, Loki, Alloy, and event-bridge stack.

Attacknet renders the observability resources with each network. Chaos Mesh is
cluster infrastructure with a separate privilege and upgrade lifecycle.

## Supported local profile

The chart declares Kubernetes 1.27 or newer because it relies on stable
StatefulSet PVC-retention policy. Release 1 qualification is narrower: a local,
three-node, arm64 Docker Desktop cluster using the `kind` provisioner. Treat
`attacknet doctor` and
[`baseline-v1.json`](../../attacknet/release/baseline-v1.json) as authoritative
for the currently accepted product profile.

From the repository root, the local workflow requires:

| Dependency | Requirement |
| --- | --- |
| Docker | Docker Desktop with the daemon running |
| Kubernetes | Docker Desktop `kind`; one control plane and two workers for the accepted profile |
| Helm | Major version 3 or 4 |
| `kubectl` | Within one minor version of the Kubernetes server |
| Go | 1.26 for controller development and local source builds |
| Metrics API | `metrics.k8s.io/v1beta1` reachable for capacity checks |
| Storage | One default StorageClass; at least 8 GiB available per node for the full topology |
| Architecture | Local `arm64` or `x64`; cluster `arm64` or `amd64` |

Do not apply Hacknet to a shared or production cluster.

## Install on Docker Desktop Kubernetes

### 1. Verify the cluster

```bash
kubectl config current-context
kubectl cluster-info
kubectl get nodes -o wide
```

Confirm this is the intended local Docker Desktop cluster before continuing.

### 2. Install Chaos Mesh

Release 1 is pinned to Chaos Mesh 2.8.3. Docker Desktop `kind` nodes use
containerd:

```bash
helm repo add chaos-mesh https://charts.chaos-mesh.org
helm repo update
helm upgrade --install chaos-mesh chaos-mesh/chaos-mesh \
  --namespace chaos-mesh \
  --create-namespace \
  --version 2.8.3 \
  --set chaosDaemon.runtime=containerd \
  --set chaosDaemon.socketPath=/run/containerd/containerd.sock \
  --wait

kubectl get pods -n chaos-mesh
```

Every Chaos Mesh Pod must become Ready. Use the
[official installation guide](https://chaos-mesh.org/docs/production-installation-using-helm/)
when the cluster uses a different container runtime.

The supported installation enables Chaos Mesh namespace filtering. The local
installer annotates its release namespace with
`chaos-mesh.org/inject=enabled`; without that annotation Chaos Mesh accepts a
fault resource but selects no Pods. Set
`attacknet install local --chaos-injection disabled` only for a control plane
that must never inject native Chaos Mesh faults.

### 3. Build local images

Build the typed client, control-plane images, active probe, I/O-pressure helper,
stacker client, and the current Stacks node/signer image:

```bash
(cd contrib/helm/hacknet/operator && \
  go build -o /tmp/stacks-attacknet ./cmd/attacknet)
ATTACKNET=/tmp/stacks-attacknet

$ATTACKNET image build --repo-root "$(pwd)" --stacks
```

A cold Stacks image build can take tens of minutes. Its Dockerfile uses Cargo
Chef and BuildKit cache mounts for subsequent revisions.

### 4. Install Hacknet

```bash
$ATTACKNET install local \
  --chart-dir contrib/helm/hacknet \
  --namespace hacknet-system \
  --release hacknet \
  --kind-image-load require
kubectl get deployments -n hacknet-system
kubectl get crd \
  stacksnetworks.testing.stacks.org \
  burnchainpolicies.testing.stacks.org \
  faultcampaigns.testing.stacks.org \
  attacknetruns.testing.stacks.org \
  upgradecampaigns.testing.stacks.org
```

Both controller Deployments must become Available. The installer:

- assigns content-derived tags to the local chart-managed images;
- replaces stale mutable tags, imports the selected platform into every Docker
  Desktop `kind` node, and verifies its CRI runtime image ID;
- verifies that the five required Chaos Mesh APIs are installed;
- server-side applies and waits for all five CRDs; and
- performs an atomic Helm upgrade with rollback on failure.

Use `--kind-image-load disabled` only when a registry or external image loader
already provides immutable references.

### 5. Run the compatibility doctor

```bash
$ATTACKNET doctor
```

Do not begin a run until every v1beta1 API is available. Use
`$ATTACKNET doctor --output json` for automation.

## First Stacks smoke

`examples/minimal.yaml` declares Bitcoin Core and a Stacks follower;
`examples/minimal-burnchain-policy.yaml` controls bootstrap and cadence through
a separate `BurnchainPolicy`. Import the locally built Stacks image into every
`kind` node before applying both resources:

```bash
$ATTACKNET image load --mode require \
  stacks-core-attacknet:main

$ATTACKNET submit --namespace hacknet-system \
  --file contrib/helm/hacknet/examples/minimal-burnchain-policy.yaml
$ATTACKNET submit --namespace hacknet-system \
  --file contrib/helm/hacknet/examples/minimal.yaml

kubectl get stacksnetworks,pods,pvc --namespace hacknet-system --watch
```

This is a controller smoke, not the supported full-network workflow. Use the
[Attacknet guide](../../attacknet/README.md) to render a funded signer/miner
topology, deploy observability, verify invariants, and retain evidence.

## Status, suspension, and storage

The topology controller reports `Pending`, `Progressing`, `Ready`, `Degraded`,
or `Suspended`, plus each actor's resolved image, resource name, and readiness:

```bash
kubectl get stacksnetworks --namespace hacknet-system
kubectl get stacksnetwork minimal \
  --namespace hacknet-system \
  --output=jsonpath='{.status.actors}'
```

Setting `spec.suspended: true` scales actor StatefulSets to zero while retaining
their PVCs. Removing it reconciles each actor back to one replica.

Every actor StatefulSet uses:

```yaml
persistentVolumeClaimRetentionPolicy:
  whenDeleted: Delete
  whenScaled: Retain
```

Deleting the `StacksNetwork` garbage-collects its owned ConfigMaps, Services,
StatefulSets, and PVCs. The StorageClass determines when the backing volume is
physically reclaimed.

An invalid actor makes the complete desired topology invalid. The controller
validates all actors before mutation, leaves the last known-good topology
running, and reports `Degraded`. It never adopts a same-named resource unless
that resource's controller owner UID matches the current `StacksNetwork`.

## API model

### `StacksNetwork`

`StacksNetwork` owns the system under test. Its controller has no Chaos Mesh
permission. The normal v1beta1 interface declares Bitcoin nodes, Stacks nodes,
signer sets, signer enrollment, shared workload policy, telemetry, and probes.
The operator derives deterministic names, ports, dependencies, and service
relationships. `rawActors` and bounded `advanced` overrides are conspicuous
escape hatches for non-standard adversarial workloads, not the normal path.

Each actor configuration has exactly one source:

- a versioned `generated` profile for routine Bitcoin and follower nodes;
- `configMapRef` for externally managed configuration; or
- `secretRef` for keys and tokens.

The operator cannot read Secrets. Kubernetes mounts a referenced Secret
directly into the actor Pod. Prefer Secret-backed signer and miner
configuration even in disposable environments.

`spec.defaults.bootstrapPeers` supplies the initial P2P peers inherited by
generated Stacks node profiles. A profile-local list overrides the shared
default. Bootstrap configuration must be present before a node initializes its
PeerDB; adding it after persistent chainstate exists does not retroactively
make the peer initial.

`spec.genesis` is the network-wide genesis contract for generated Stacks node
profiles. It carries PoX-5 sBTC contract identifiers and bounded initial STX
balances; it does not deploy the sBTC contracts. Because `stacks-node` requires
an Epoch 4 entry, the R1 `nakamoto-regtest-node/v1` profile parks activation at
reward-phase burn height 1,000,005 instead of exercising it. Use complete ConfigMap- or
Secret-backed configs only when the environment independently provisions the
contracts required for an earlier Epoch 4 activation. Balances are rendered in
deterministic address order. Complete node
configs supplied through `configMapRef` or `secretRef` remain opaque to the
operator and therefore must reproduce `spec.genesis` exactly; otherwise actors
can exchange blocks successfully while rejecting them as belonging to another
genesis chain.

Complete Stacks node and signer configs may use `${SERVICE:actor-name}` for a
logical actor Service. Stacks node configs may also use `__NODE_IP__`. A small
immutable wrapper renders these tokens inside the actor Pod, writes the result
to `/tmp/stacks-attacknet-config.toml`, and then replaces itself with the real
binary. Unknown logical actors fail closed before startup. This gives
Secret-backed and ConfigMap-backed configs the same deterministic naming as
generated profiles without exposing their contents to the operator.

Every actor Pod receives these non-overridable labels:

```text
testing.stacks.org/network=<StacksNetwork name>
testing.stacks.org/actor=<actor name>
testing.stacks.org/role=<role>
app.kubernetes.io/managed-by=hacknet-operator
```

These labels are the supported selection surface for fault injection and
evidence. A signer's configured Stacks node is called a signer node throughout
the v1beta1 API and examples.

After every actor rollout is complete, `status.inventoryDigest` binds the
current generation to the admitted StatefulSet UID/revision, Pod UID, requested
image, runtime image ID, Service, and role of every actor. The digest is absent
while any identity is incomplete. Observation timestamps and Kubernetes
resource versions are reported alongside it but are deliberately excluded from
the digest. Consumers must wait for `status.inventoryReady: true` and must still
recheck live Pod identity immediately before a mutation.

For multiple Bitcoin nodes, `spec.burnchain.nodes[].peerRefs` declares directed
persistent Bitcoin P2P edges. The renderer emits deterministic `addnode`
settings; it does not turn peer edges into startup gates, so cycles are valid.
Declare both directions for symmetric reconnect behavior. Each Stacks actor's
`burnchainNodeRef` identifies the Bitcoin view it follows.

Each Bitcoin node in a multi-node graph must resolve to a distinct
`BurnchainPolicy`. Set `policyRef` on the node; the network-level
`spec.burnchain.policyRef` remains the single-node default. Once all actors and
policies are admitted, `status.burnchainTopology` publishes the normalized peer
graph, policy names and UIDs, policy Services, actor bindings, and a canonical
digest. The digest is withheld during partial rollout and excludes timestamps
network generation, and Kubernetes resource versions; generation remains a
separate status and admission binding. Fault and run controllers still re-read
live identities immediately before mutation; status alone is not a freshness
guarantee.

An actor may set `runtimeExposure: reachable` to publish its headless-Service
endpoint before its Pod is Ready. The default, `ready`, keeps bootstrap
deterministic. This affects DNS discovery and new connections, not established
sessions, and is not a runtime fault mechanism.

### `BurnchainPolicy`

`BurnchainPolicy` controls one selected Bitcoin actor without coupling Bitcoin
Core to Stacks progress. It declares bootstrap height, steady cadence,
pause/resume, destination rotation, bounded flash blocks, and bounded RPC retry.
Its unprivileged clock process has no Kubernetes credentials and never exits
Bitcoin Core on RPC failure. Bitcoin forks, partitions, and reconsideration are
fault mechanisms rather than cadence policy.

The referenced policy is both a Stacks-process startup barrier and a
`StacksNetwork` readiness barrier. Bitcoin actors start immediately so their
clocks can bootstrap them. Each bound Stacks actor waits for Bitcoin RPC and
for the policy clock's `/readyz` Service endpoint, which is published only
after bootstrap and policy acknowledgement. The network does not report Ready
until the current policy generation and every actor are Ready.
For a fresh miner-backed regtest, choose a bootstrap height at or above the
first mature coinbase output (normally 101) and leave enough blocks before the
first configured epoch transition for node sync, stacking, signer startup, and
an initial Stacks tip. The bootstrap height is the actor-release point, not a
target to place immediately before activation.
In a follower-only secondary Bitcoin node, use `bootstrapHeight: 0`,
`reserveOutputs: 0`, and `paused: true`: the node learns the primary branch
over Bitcoin P2P without an independent clock mining a competing genesis
suffix. `reserveOutputs` defaults to four for the primary policy so its wallet
has explicit initial coinbase outputs.

### `FaultCampaign`

`FaultCampaign` is either an inert reusable template (`spec.template: true`) or
one bounded graph of stages and fault actions. The fault controller resolves
exact admitted Pod identities and owns cleanup through a finalizer. Actions in
a stage are admitted against their aggregate safety impact. Stages can overlap
using deterministic time, dependency, burn-height, Stacks-height, or trusted
observation triggers.

Admission snapshots the complete `StacksNetwork` inventory digest. Every later
reconciliation compares the snapshot with both current status and live Pods.
An unplanned identity change is never silently retargeted: owned fault state is
cleaned up and the campaign ends `Inconclusive` with reason
`TargetIdentityDiverged` and structured before/current evidence. An intentional
`pod-kill` may replace only its selected Pod identity; all other identities
remain pinned.

Supported native Chaos Mesh resources are `PodChaos`, `NetworkChaos`,
`DNSChaos`, `IOChaos`, and `TimeChaos`. The controller can also create one
restricted I/O-pressure Pod from the chart-configured trusted image. Campaigns
cannot supply that image, executable, shell, or arbitrary arguments.

Apply examples only after the referenced network is Ready. The topology
controller owns the environment lease and fault/run controllers own mutation
leases; host processes never claim parallel mutation authority:

```bash
$ATTACKNET submit --namespace hacknet-system \
  --file contrib/helm/hacknet/examples/fault-campaign.yaml
$ATTACKNET submit --namespace hacknet-system \
  --file contrib/helm/hacknet/examples/fault-campaign-io-pressure.yaml
$ATTACKNET watch --namespace hacknet-system FaultCampaign network-partition
```

A campaign created without the matching environment lease remains `Pending`
with reason `WaitingForEnvironmentLease`; it never injects a fault.

Chaos Mesh `AllInjected` and `AllRecovered` conditions are context, not proof
that the target experienced the requested effect. Without trusted effect and
recovery observations, a campaign terminates `Inconclusive`, never `Passed`.

The operator-facing [`fault reference`](../../attacknet/docs/reference/faults/)
documents every supported type, parameter, invariant, and assertion.

### `UpgradeCampaign`

`UpgradeCampaign` declares one bounded, topology-owned image and configuration
transition. Profiles carry immutable image, provenance, configuration, source,
revision, instrumentation-capability, and compatibility-expectation fields.
Ordered stages assign profiles to logical actors and bound parallel actors,
signer weight, miner percentage, stage deadlines, stable windows, and optional
protocol assertions.

The topology operator reconciles the resulting overlays and remains the only
StatefulSet writer. The upgrade controller records the admitted baseline,
current inventory, applied assignments, and every authorized before/after
identity digest. An unexpected network UID or workload identity change fails
closed; it is not accepted as part of the rollout.

Render profiles on the host, import every image into each kind node, and submit
an inert template for `AttacknetRun` scheduling:

```bash
$ATTACKNET version prepare \
  --file contrib/attacknet/examples/matrices/stable-with-candidate.plan.yaml \
  --workspace .attacknet/version-workspace \
  --recipe-root . \
  --output .attacknet/stable-with-candidate.json
$ATTACKNET version load \
  --descriptor .attacknet/stable-with-candidate.json --mode require \
  > .attacknet/stable-with-candidate-import.json
$ATTACKNET version render-upgrade \
  --descriptor .attacknet/stable-with-candidate.json \
  --namespace hacknet-system --template=true \
  > .attacknet/roll-candidate.yaml
$ATTACKNET submit --file .attacknet/roll-candidate.yaml
```

Use `--template=false` only for a deliberately standalone rollout. One
`AttacknetRun` may execute one upgrade campaign; express rollout batches as its
ordered stages. With `rollbackOnFailure: true`, a failed or inconclusive stage
restores the admitted baseline before terminal status and sets
`rollbackComplete`. Without it, the failed deployment remains available for
triage until campaign deletion invokes finalizer-owned rollback. A successful
standalone campaign likewise retains the upgraded overlay until deletion; wait
for foreground deletion rather than manually reverting workloads.

`StartupIncompatible` means assigned actors did not become Ready with the
expected image and configuration before the deadline. `TelemetryUnavailable`
and `ProtocolAssertionInconclusive` terminate as `Inconclusive` and never prove
version incompatibility. Preserve the descriptor, image-import receipt,
campaign status, and incident evidence before cleanup. The complete workflow is
documented in the
[`mixed-version guide`](../../attacknet/docs/concepts/mixed-version-images.md).

### `AttacknetRun`

`AttacknetRun` resolves a finite fault catalog before the first action. It pins
template identity and generation, network identity and generation, admitted
actor image digests, seeded decisions, triggers, dependencies, and aggregate
budgets in a sealed, owner-bound ConfigMap. Eligible campaign children are
created deterministically within those budgets. Run-owned campaign children
share the immutable run UID as their mutation lease and may overlap within the
run's active-fault and cumulative safety reservations. Standalone campaigns
remain mutually exclusive. Use one multi-stage campaign when effects require a
single aggregate admission decision; use overlapping run executions when each
campaign is independently admitted and the run-level union budget is sufficient.
If the canonical signer set is not observable yet, the run remains `Pending`
with reason `SignerSetObservationPending`; this is dependency state, not a
failed reconcile or a safety verdict.

The run also pins the complete admitted inventory. Unplanned divergence ends
the run `Inconclusive` and prevents remaining actions from starting. A proven,
intentional `pod-kill` records an explicit inventory transition before a later
action may use the replacement Pod.

Terminal phase records the run outcome; it does not by itself prove cleanup.
Wait for `status.cleanup.completed: true` before archiving the terminal result
or tearing down its network. The controller continues observing owned
campaigns after the outcome is known and sets `status.finishedAt` only after
each campaign has proved mutation cleanup and target recovery.

```bash
kubectl apply --filename contrib/helm/hacknet/examples/attacknet-run.yaml
kubectl get attacknetruns,faultcampaigns \
  --namespace hacknet-system \
  --watch
```

Replay verifies the source schedule digest, requires the same manifest and
admitted images, and refuses to run against the source network UID. It
reproduces intended actions and seeded choices; Kubernetes and protocol
interleavings remain nondeterministic.

## Telemetry and trusted probes

When actor telemetry is enabled, the topology controller adds an OpenTelemetry
Collector sidecar. It scrapes the actor on localhost (`31000` for signers and
`20446` for nodes) and exports OTLP/HTTP to `telemetry.exporterEndpoint`. A
bearer token may come from `telemetry.tokenSecretRef` without the operator
reading it.

`spec.probe.enabled` is false by default. When enabled, each actor receives a
credential-free `attacknet-probe` sidecar on Pod port `18080`. The actor
Service publishes that port so enrolled peers can perform bounded throughput
observations. Actor-defined port name `probe` and TCP service port `18080` are
therefore reserved and rejected before workload mutation. The API is
intentionally unauthenticated; do not expose actor Services outside the
isolated test network. The bounded probe API can observe:

- enrolled TCP endpoints and latency;
- a selected DNS name plus a fixed cluster control;
- confined filesystem I/O under the actor data volume;
- wall and monotonic clocks; and
- bounded platform and architecture identity.

There is no shell, arbitrary hostname, or arbitrary path operation. The run
controller admits probe evidence only from an exact Ready Pod UID whose probe
container is independently Ready. Actor logs and actor-provided payloads are
not authoritative probe evidence.

Actor Services are always included in the probe allowlist. Additional
credential-free harness Services must be declared explicitly through bounded
`spec.probe.additionalServices` entries containing a DNS-label Service name and
named ports. Attacknet's topology renderer uses this extension for its
Prometheus endpoint; the generic default adds no Attacknet-specific peer.

The local installer content-tags and imports the chart-selected default probe
image. A network that explicitly overrides `spec.probe.image` must load or
publish that exact image separately.

## Architecture-specific fault boundaries

Chaos Mesh 2.8.3 native `IOChaos` and `TimeChaos` are rejected on arm64. The
installed I/O helper is x86-64-only, and local TimeChaos testing reported an
ineffective process-clock shift plus a wedged daemon canary. Extend
`runOperator.ioChaosSupportedArchitectures` or
`runOperator.timeChaosSupportedArchitectures` only after an effect-and-recovery
canary succeeds on that architecture.

Attacknet supplies two separately labelled portable mechanisms:

- `io-pressure` applies bounded controller-owned pressure to a selected actor
  PVC and proves an FSYNC latency effect and recovery; and
- `clock-skew` updates a mounted application-clock policy for compatible node
  images and proves the process wall-clock offset against a control actor.

Neither mechanism may be reported as native Chaos Mesh IOChaos or TimeChaos.

## Security and controller behavior

- Actor Pods receive no Kubernetes service-account token.
- The topology operator has namespaced workload permissions and no Chaos Mesh
  permissions.
- The run operator has a separate namespaced identity and a finite Chaos Mesh
  resource allowlist.
- Both controllers use restricted Pod security contexts and projected,
  rotating service-account tokens.
- Readiness reflects Kubernetes API availability; liveness reflects controller
  loop progress, avoiding restart storms during API outages.
- Controller metrics expose bounded API, reconcile, process, and managed-run
  measurements for capacity and incident attribution.

Control-plane hardening is always enabled. Adversarial freedom belongs in
explicit actor images and data-plane fault controls, not in compromising the
experiment controller.

## Troubleshooting

| Symptom | First action |
| --- | --- |
| Controller image is unavailable | Re-run `attacknet image build`, then `attacknet install local`; Docker Engine and `kind` node image stores are separate. |
| CRD schema did not update | Inspect managed fields, then use `--force-crd-conflicts` once only when deliberately reclaiming ownership. |
| Helm release is `failed` | Run `helm status hacknet -n hacknet-system`; use `--recover-failed-release` only after identifying the cause. |
| Upgrade reports a managed-field conflict | Do not use `kubectl set image`; inspect ownership before considering `--force-helm-conflicts`. |
| Upgrade waits in `Pending` | Inspect `UpgradeLeaseHeld`, network readiness, admitted inventory, and profile image/configuration identities. |
| Upgrade misses its deadline | Distinguish `StartupIncompatible`, telemetry loss, assertion failure, and identity drift before attributing a version defect. |
| Upgrade is rolling back | Wait for `rollbackComplete: true` or foreground deletion; never patch topology-owned StatefulSets. |
| New same-named network is `Degraded` | Wait for old-UID garbage collection; if it persists, inspect finalizers and garbage-collector health. Never adopt old children. |
| Actor Pod remains Pending after node disruption | Inspect PVC node affinity and placement. Local-path storage does not prove cross-node reattachment. |
| Fault remains `Inconclusive` | Inspect probe availability and effect evidence; Chaos Mesh injection conditions alone are insufficient. |

The operator intentionally does not duplicate Kubernetes garbage collection.
If an old owner UID's child is stuck, visible failure is preferable to silently
hiding a cluster-level finalizer or garbage-collector fault.

## Uninstall

Delete or archive all test networks and evidence before removing the control
plane:

```bash
kubectl get stacksnetworks,faultcampaigns,attacknetruns --all-namespaces
helm uninstall hacknet --namespace hacknet-system
```

The Hacknet CRDs remain installed. Remove them only after confirming that no
custom resources remain. Chaos Mesh is independent and can remain installed
for future runs:

```bash
helm uninstall chaos-mesh --namespace chaos-mesh
```

## Development

Run the offline chart and controller checks from the repository root:

```bash
contrib/helm/hacknet/scripts/check.sh
```

A live change should additionally prove:

- StatefulSet recreation and status transitions;
- telemetry and active-probe readiness when enabled;
- projected service-account token rotation;
- suspension with PVC retention;
- custom-resource deletion with PVC reclamation; and
- delete-and-immediate-recreate behavior without adoption of old resources.

For a registry deployment, publish immutable topology-operator, run-operator,
probe, I/O-pressure, and actor image references. Controllers are compiled Go
binaries; no source-mount execution fallback exists.

Controller implementation and envtest instructions are in
[`operator/README.md`](operator/README.md). The authored CRDs remain the schema
source of truth, while `controller-gen` owns typed deep-copy generation.

## Current product boundary

Kubernetes is the sole Attacknet runtime. Hacknet supplies its Kubernetes
control plane; Attacknet supplies topology, scenarios, assertions, and evidence.

Release 1 has qualified the local three-node arm64 profile, full 28-actor
topology, authenticated telemetry, bounded fault campaigns, seeded runs,
replay, and removal-only minimization. Managed clusters, x86-native Chaos
helpers, portable or multi-zone CSI, registry/enterprise identity integration,
and controller HA remain explicitly unqualified. Consult the machine-readable
[Release 1 baseline](../../attacknet/release/baseline-v1.json) rather than
inferring support from a rendered resource or successful Helm installation.
