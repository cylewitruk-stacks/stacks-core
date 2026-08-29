# Stacks Attacknet

Stacks Attacknet runs disposable adversarial Stacks regtest networks. It can
mix node and signer versions, execute bounded concurrent faults, schedule
experiments from trusted observations, verify recovery, and retain evidence for
reproduction and triage.

This is test infrastructure, not a production deployment. Use only generated
regtest keys and funds with no value.

## Release 1 scope

Release 1 is qualified on a three-node, arm64 Docker Desktop Kubernetes cluster
using the `kind` provisioner. Kubernetes is the only runtime. The accepted full
topology has 3 miners, 10 signers with one signer node each, and 5 followers.
Start with the minimal topology before attempting the 28-actor example.

Release 1 does not claim managed-cluster, x86-64, portable CSI, multi-zone, or
controller-HA qualification. Native Chaos Mesh `IOChaos` and `TimeChaos` are
not supported on arm64; use Attacknet's `io-pressure` and `clock-skew`
mechanisms. See [`release/baseline-v1.json`](release/baseline-v1.json).

## Prerequisites

Run commands from the repository root.

| Dependency | Release 1 requirement |
| --- | --- |
| Docker | Docker Desktop with the daemon running |
| Kubernetes | Docker Desktop `kind`, one control plane and two workers |
| Go | 1.26 |
| Node.js | 20 or newer only for developer/release qualification |
| Python | 3.11 or newer only for developer/release qualification |
| Helm | Major version 3 or 4 |
| `kubectl` | Within one minor version of the Kubernetes server |
| Storage | One default StorageClass and at least 8 GiB per node |
| Architecture | Local `arm64` or `x64`; cluster `arm64` or `amd64` |

Do not continue if the active Kubernetes context points at a shared or
production cluster.

```bash
kubectl config current-context
kubectl cluster-info
kubectl get nodes -o wide
```

## Install

### 1. Install Chaos Mesh

Release 1 pins Chaos Mesh 2.8.3. Docker Desktop `kind` uses containerd.

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

Every Chaos Mesh Pod must become Ready.

The supported installation enables Chaos Mesh namespace filtering. The local
installer explicitly annotates its target namespace with
`chaos-mesh.org/inject=enabled`; without that annotation Chaos Mesh accepts a
fault resource but selects no Pods. Set
`HACKNET_CHAOS_NAMESPACE_INJECTION=disabled` only for a control plane that must
never inject native Chaos Mesh faults.

### 2. Build and install the control plane

```bash
(cd contrib/helm/hacknet/operator && \
  go build -o /tmp/stacks-attacknet ./cmd/attacknet)
ATTACKNET=/tmp/stacks-attacknet

$ATTACKNET image build --repo-root "$(pwd)" --stacks
$ATTACKNET install local \
  --chart-dir contrib/helm/hacknet \
  --namespace hacknet-system \
  --release hacknet \
  --kind-image-load require

$ATTACKNET image load --mode require \
  stacks-core-attacknet:main \
  stacks-attacknet-stacker:local
```

The typed installer resolves every control-plane image to an immutable local
Docker ID, content-tags it, imports it into every `kind` node, and verifies the
selected platform's CRI runtime image ID. It then applies the four v1beta1 CRDs
explicitly and performs an atomic Helm install. Actor images are loaded
separately because a `StacksNetwork`, not the chart, selects them.
Actor Pods never receive Kubernetes service-account credentials.

```bash
kubectl get deployments -n hacknet-system
$ATTACKNET doctor
```

Do not start a run until both controller Deployments are Available and the
doctor reports every v1beta1 API available. Use `--output json` for automation.

## First network

Human inputs are YAML. JSON remains the canonical machine format for schedules,
digests, evidence, and review packets.

```bash
$ATTACKNET validate \
  --file contrib/helm/hacknet/examples/minimal-burnchain-policy.yaml
$ATTACKNET validate --file contrib/helm/hacknet/examples/minimal.yaml

$ATTACKNET submit --namespace hacknet-system \
  --file contrib/helm/hacknet/examples/minimal-burnchain-policy.yaml
$ATTACKNET submit --namespace hacknet-system \
  --file contrib/helm/hacknet/examples/minimal.yaml

$ATTACKNET wait --namespace hacknet-system --for condition=Ready \
  BurnchainPolicy minimal
$ATTACKNET wait --namespace hacknet-system --for condition=Ready \
  StacksNetwork minimal
```

`StacksNetwork` declares Bitcoin actors, Stacks nodes, signer sets, enrollment,
workload defaults, telemetry, and probes. `BurnchainPolicy` independently
controls Bitcoin bootstrap, cadence, pause/resume, destinations, and bounded
flash blocks. Bitcoin Core does not wait for or interpret Stacks.

Inspect admitted identities and policy state:

```bash
$ATTACKNET get --namespace hacknet-system StacksNetwork minimal
$ATTACKNET get --namespace hacknet-system BurnchainPolicy minimal
```

The 28-actor shape is in
[`../helm/hacknet/examples/accepted-28.yaml`](../helm/hacknet/examples/accepted-28.yaml).
It references complete miner/signer configs and enrollment credentials in
Secrets; create those inputs before submitting it.

## Run concurrent faults

A `FaultCampaign` is an aggregate-admitted graph. It may contain multiple
actions in one stage and overlapping stages triggered by time, prior-stage
milestones, burn height, Stacks height, or a trusted observation. The controller
evaluates safety over the union of active mutations and rolls back partial
injection before classifying the campaign.

```bash
$ATTACKNET validate \
  --file contrib/helm/hacknet/examples/fault-campaign-minimal.yaml
$ATTACKNET submit --namespace hacknet-system \
  --file contrib/helm/hacknet/examples/fault-campaign-minimal.yaml
$ATTACKNET wait --namespace hacknet-system --for terminal \
  FaultCampaign minimal-follower-restart
```

Separate campaigns share one namespace mutation lease. Express intentionally
concurrent faults as stages/actions in one campaign so their combined signer,
miner, burnchain, target, and resource impact is visible at admission.

See the [`fault reference`](docs/reference/faults/) for every supported fault
type, parameter, invariant, assertion, and complete authoring examples.

`AttacknetRun` seals a deterministic execution DAG before creating campaigns.
It records trigger receipts, enforces aggregate budgets, supports replay and
resume, and performs removal-only minimization without claiming causal
minimality from an inconclusive attempt.

The advanced run example expects a full network named `attacknet`. Its two
catalog resources are inert templates until referenced by the run:

```bash
$ATTACKNET submit --namespace hacknet-system \
  --file contrib/helm/hacknet/examples/fault-campaign.yaml
$ATTACKNET submit --namespace hacknet-system \
  --file contrib/helm/hacknet/examples/fault-campaign-io-pressure.yaml
$ATTACKNET submit --namespace hacknet-system \
  --file contrib/helm/hacknet/examples/attacknet-run.yaml
$ATTACKNET wait --namespace hacknet-system --for terminal \
  AttacknetRun bounded-mixed-faults
```

Burn height, Stacks height, and the finite named-observation vocabulary are
collected by the run operator. Actor metric values remain self-reported, but
the controller reads them through operator-owned Services between two uncached
admitted-inventory checks and records an identity-bound source receipt.
Missing, stale, ambiguous, or replaced sources remain Pending and expire
`Inconclusive`; they never satisfy a trigger or assertion.

## Observe and retain evidence

Grafana is for human triage. Agents should query Prometheus, Loki, Kubernetes,
and the trusted event journal directly and retain the raw responses. See
[`observability/README.md`](observability/README.md) for metrics, dashboards,
logs, and evidence-source trust.

The typed client can capture either a bounded single-resource snapshot or an
identity-bound incident bundle:

```bash
$ATTACKNET evidence snapshot --namespace hacknet-system \
  --output contrib/attacknet/evidence/quickstart-run.json \
  AttacknetRun triggered-overlap

$ATTACKNET evidence incident --namespace hacknet-system \
  --output /tmp/attacknet-incident-minimal \
  minimal
```

A resource snapshot is not a complete incident bundle. `evidence incident`
uses admitted Pod names and UIDs, refuses replacement-Pod log attribution, and
captures bounded owned resources, Events, and log tails with per-artifact
digests and explicit omissions. Preserve metrics and terminal run artifacts
separately. Follow [`evidence.md`](docs/operations/evidence.md) and
[`failure-attribution.md`](docs/operations/failure-attribution.md).

For local human dashboards:

```bash
$ATTACKNET dashboard start --target grafana --namespace hacknet-system
$ATTACKNET dashboard start --target chaos
$ATTACKNET dashboard status --target grafana
$ATTACKNET dashboard stop --target grafana
```

Port-forwards bind loopback only and are tracked by exact process identity.

## Teardown

Keep the terminal run until the evidence-safe network teardown has captured
it. Complete teardown requires the network-scoped observability stack described
in [`observability/README.md`](observability/README.md); missing or incomplete
Loki evidence preserves the network. Foreground deletion waits for controller
finalizers and owned-resource cleanup.

```bash
$ATTACKNET delete --namespace hacknet-system --wait \
  FaultCampaign minimal-follower-restart
$ATTACKNET delete --namespace hacknet-system --wait BurnchainPolicy minimal
$ATTACKNET teardown --namespace hacknet-system \
  --output evidence/minimal-teardown \
  --run bounded-mixed-faults minimal
$ATTACKNET delete --namespace hacknet-system --wait \
  AttacknetRun bounded-mixed-faults
```

The teardown command captures an identity-bound incident bundle and complete
retained Loki interval before deleting the `StacksNetwork`. Any incomplete
capture preserves the network and its actor PVCs. Direct `delete
StacksNetwork` is an administrative escape hatch without this evidence
guarantee. Helm intentionally leaves CRDs installed; do not remove them while
custom resources remain.

For a network without an `AttacknetRun`, pass the retained experiment start as
`--start "$RUN_START_RFC3339"` instead of `--run`.

```bash
helm uninstall hacknet -n hacknet-system
helm uninstall chaos-mesh -n chaos-mesh
```

## Troubleshooting

| Symptom | First action |
| --- | --- |
| Doctor reports a missing API | Re-run `attacknet install local`; inspect both controller Deployments and CRDs. |
| Actor image cannot be pulled | Re-run `attacknet image build` and `attacknet image load`; Docker and each `kind` node have separate image stores. |
| Network remains Pending | Inspect its referenced `BurnchainPolicy`, actor Pods, and current `status.conditions`. |
| Campaign waits for a lease | Inspect active campaigns; do not steal or manually edit the controller-owned lease. |
| Campaign is Inconclusive | Preserve the network and evidence. Inspect identity divergence, partial rollback, effect, and recovery status before retrying. |
| Pod remains Pending after node disruption | Inspect PVC node affinity. Release 1 does not prove portable cross-node reattachment. |
| Fault is unsupported on arm64 | Use `io-pressure` or `clock-skew`; do not bypass the capability gate. |

## Public and internal boundaries

- The typed Go client and `testing.stacks.org/v1beta1` resources are the public
  interface. Use `attacknet commands --json` for the agent-readable contract.
- Controllers own admission, scheduling, mutation, rollback, recovery, and
  terminal classification. The CLI submits intent and reads status.
- Immutable, digest-verified v1alpha1 compatibility vectors live under
  [`test/fixtures/equivalence/`](test/fixtures/equivalence/). The retired
  Node/shell implementation remains available only through its pinned Git
  revisions and is not shipped as a second operator interface.
- JSON evidence and historical release machinery remain intentionally separate
  from YAML authoring.
- Actor counts and identities come from `StacksNetwork.status`; harness code
  must not hardcode signer, miner, or follower counts.

## Further reading

- [`docs/operations/`](docs/operations/README.md): runtime operations and recovery.
- [`docs/reference/go-cli.md`](docs/reference/go-cli.md): typed client contract.
- [`docs/reference/faults/`](docs/reference/faults/): supported fault types,
  parameters, safety invariants, and examples.
- [`docs/operations/evidence.md`](docs/operations/evidence.md): evidence capture, replay, and minimization.
- [`docs/development/`](docs/development/README.md): controller and image development.
- [`docs/development/roadmap.md`](docs/development/roadmap.md): deferred environments and fault mechanisms.
- [`docs/reference/instrumentation.md`](docs/reference/instrumentation.md): portable metric contracts.
- [`docs/concepts/adversarial-actors.md`](docs/concepts/adversarial-actors.md): bounded modified actors.
- [`docs/concepts/reproducibility.md`](docs/concepts/reproducibility.md): seeds and replay.
