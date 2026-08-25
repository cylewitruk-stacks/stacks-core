# Stacks Attacknet

Stacks Attacknet runs disposable, adversarial Stacks regtest networks. It can
mix node and signer versions, inject bounded faults, verify recovery, centralize
telemetry, and retain enough evidence to reproduce and triage failures.

This is test infrastructure, not a production deployment. Use only generated
regtest keys and funds with no value.

## Release 1 scope

Release 1 is qualified on a three-node, arm64 Docker Desktop Kubernetes cluster
using the `kind` provisioner. Kubernetes is the sole Attacknet runtime.

The accepted full topology contains 3 miners, 10 signers with one configured
Stacks node each, and 5 followers. Start with the 1/1/1 topology below before
attempting that 28-actor network.

Release 1 does not claim managed-cluster, x86-64, portable CSI, multi-zone, or
controller-HA qualification. Native Chaos Mesh IOChaos and TimeChaos are not
supported on arm64; use Attacknet's `io-pressure` and `clock-skew` mechanisms.
The complete capability statement is
[`release/baseline-v1.json`](release/baseline-v1.json).

## Prerequisites

Run commands from the repository root. The supported local profile requires:

| Dependency | Release 1 requirement |
| --- | --- |
| Docker | Docker Desktop with the daemon running |
| Kubernetes | Docker Desktop `kind`, Kubernetes minor reported compatible by `doctor`, one control plane and two workers |
| Node.js | 20 or newer |
| Python | 3.11 or newer |
| Helm | Major version 3 or 4 |
| `kubectl` | Within one minor version of the Kubernetes server |
| Storage | Exactly one default StorageClass and at least 8 GiB available on every node |
| Architecture | Local `arm64` or `x64`; cluster `arm64` or `amd64` |

The local access supervisors use loopback ports 3000, 2333, 8080, and 9464.
Stop anything already listening on those ports before installation. The full
topology is resource-intensive; prove the small topology first and run the
capacity preflight before scaling up.

Enable Kubernetes in Docker Desktop, select the `kind` provisioner, configure
three nodes, and verify the context before continuing:

```bash
kubectl config current-context
kubectl cluster-info
kubectl get nodes -o wide
```

Do not continue if these commands point at a shared or production cluster.

## Quickstart and command discovery

The steps below cover the human workflow and the stable command surface used by
automation. Complete them in order on a new local installation.

### Install the local control plane

#### 1. Install Chaos Mesh

Attacknet Release 1 is pinned to Chaos Mesh 2.8.3. Docker Desktop's `kind`
nodes use containerd:

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

Every listed Chaos Mesh Pod must become Ready. See the
[official Helm installation guide](https://chaos-mesh.org/docs/production-installation-using-helm/)
when using a different container runtime.

#### 2. Build the local images

The first command builds the topology operator, run operator, active probe,
I/O-pressure helper, and current Stacks node/signer image. A cold Rust build can
take tens of minutes. The second command builds the stacker bootstrap image.

```bash
BUILD_STACKS_IMAGE=1 contrib/helm/hacknet/scripts/build-local.sh
docker build -t stacks-attacknet-stacker:local contrib/attacknet/stacker
```

#### 3. Install Hacknet

The installer assigns content-derived image tags, imports them into every local
`kind` node, applies the three CRDs, and installs the two restricted controllers:

```bash
contrib/helm/hacknet/scripts/install-local.sh
kubectl get deployments -n hacknet-system
```

The topology-operator and run-operator Deployments must become Available. The
network-scoped event bridge and observability stack are created later by
`lifecycle apply`. Actor Pods never receive Kubernetes service-account
credentials.

#### 4. Run the compatibility doctor

```bash
contrib/attacknet/attacknet doctor
```

Do not start a baseline run until it reports `compatible`. For machine-readable
diagnostics, use `attacknet doctor --json`.

### First network

The `attacknet` facade is the supported public interface. Other scripts in this
directory are implementation helpers unless another document explicitly says
otherwise.

Render and start a small network with trusted active-probe sidecars:

```bash
ATTACKNET=contrib/attacknet/attacknet

$ATTACKNET render \
  --network=attacknet \
  --miners=1 \
  --signers=1 \
  --followers=1 \
  --probes=true \
  --output=contrib/attacknet/generated/quickstart

$ATTACKNET lifecycle apply contrib/attacknet/generated/quickstart

$ATTACKNET verify \
  contrib/attacknet/generated/quickstart/manifest.json snapshot
```

Cold startup includes Bitcoin bootstrap, PoX setup, signer initialization, and
an observer-enabled node rollout. Follow the lifecycle output instead of using
a fixed sleep. Success means the apply command completes and `verify` returns a
machine-readable passing snapshot.

### Observe the network

Lifecycle apply starts a rediscovering, loopback-only Grafana forward by
default. Open <http://127.0.0.1:3000> and select the `attacknet` network.

Inspect local-access state with:

```bash
contrib/attacknet/local-access.sh status
contrib/attacknet/chaos-dashboard.sh local
contrib/attacknet/chaos-dashboard.sh status
```

The Chaos Dashboard is then available at <http://127.0.0.1:2333>. Local mode
disables Dashboard authentication and must never be used for a shared or
remotely reachable cluster.

Grafana is for human triage. Agents should query Prometheus, Loki, and the
trusted event journal directly and retain the raw responses. See
[`observability/README.md`](observability/README.md) for dashboard, metric, log,
and trust-boundary details.

### Run a first fault

Plan before mutating the cluster:

```bash
$ATTACKNET campaign plan \
  contrib/attacknet/examples/follower-network-delay.json \
  contrib/attacknet/generated/quickstart/manifest.json \
  /tmp/attacknet-fault.json
```

Run the bounded delay and retain its evidence:

```bash
$ATTACKNET campaign run \
  contrib/attacknet/examples/follower-network-delay.json \
  contrib/attacknet/generated/quickstart/manifest.json \
  contrib/attacknet/evidence/quickstart-fault
```

This direct-run workflow proves Chaos Mesh resource injection, cleanup,
network recovery, and post-fault chain progress. It does not independently
prove the requested latency distribution. Evidence-grade effect assertions use
the controller-owned `FaultCampaign` and `AttacknetRun` APIs described in
[`OPERATIONS.md`](OPERATIONS.md).

Controller-managed campaigns and runs bind to the topology operator's complete
admitted-inventory digest. If an unrelated StatefulSet, Pod, or runtime image
changes after admission, the controller cleans up the owned fault, records the
identity difference, and stops rather than silently selecting the replacement.

Capture a final snapshot:

```bash
$ATTACKNET evidence capture \
  contrib/attacknet/evidence/quickstart \
  contrib/attacknet/generated/quickstart/manifest.json
```

### Tear down

Teardown deletes the `StacksNetwork` and its owned actor PVCs. Capture anything
needed for forensics first:

```bash
$ATTACKNET lifecycle delete contrib/attacknet/generated/quickstart
```

Chaos Mesh and the Hacknet controllers remain installed for later runs. Remove
them only when the whole local test installation is no longer needed:

```bash
helm uninstall hacknet -n hacknet-system
helm uninstall chaos-mesh -n chaos-mesh
```

Helm intentionally leaves Hacknet CRDs installed. Do not delete them while any
Attacknet custom resources remain.

### Common problems

| Symptom | First action |
| --- | --- |
| `doctor` reports missing images | Re-run `build-local.sh`, build the stacker image, then run `install-local.sh` to import exact tags into every node. |
| Kubernetes is unreachable or has the wrong version | Confirm Docker Desktop Kubernetes is running and inspect `kubectl config current-context`. Never work around this against another cluster. |
| Chaos Mesh checks fail | Run `helm list -n chaos-mesh` and `kubectl get pods,crd -n chaos-mesh`; confirm chart 2.8.3 and the containerd socket settings. |
| Port 3000 or 2333 is unreachable | Inspect `local-access.sh status` and `chaos-dashboard.sh status`; restart the relevant supervisor rather than creating competing forwards. |
| Apply reports an image-pull failure | Re-run `install-local.sh`; Docker's image store and each `kind` node's containerd store are separate. |
| An operation reports an environment lease | Run `contrib/attacknet/environment-lock.sh status`. Do not steal a lease until its owner is proven dead and admitted state is inspected. |
| A fault or verification fails | Preserve the network and the generated incident/evidence directory. Capture more evidence before teardown. |
| A Pod is pending after node disruption | Inspect PVC node affinity and placement. Release 1 proves local-path same-node recovery, not portable cross-node reattachment. |

More detailed recovery procedures are in [`OPERATIONS.md`](OPERATIONS.md).

### Command discovery

Read help before every mutating command:

```bash
contrib/attacknet/attacknet help
contrib/attacknet/attacknet help lifecycle apply
contrib/attacknet/attacknet help campaign run
contrib/attacknet/attacknet commands --json
```

Commands that support `--plan` or `--dry-run` emit the resolved invocation as
JSON without executing it. Exit `0` means success, `1` means an operational or
compatibility failure, and `2` means invalid arguments.

## Design boundaries

- The `attacknet` facade and its versioned command registry are the public
  interface. Actor images and internal helpers are implementation details.
- Bitcoin Core, the Stacks-blind burnchain clock, and the policy steering that
  clock are separate failure domains.
- Actor Pods receive no Kubernetes service-account credentials. Control-plane
  hardening does not constrain faults applied to the data plane.
- Actor counts and inventories come from `manifest.json`; harness logic must not
  encode fixed signer, miner, or follower counts.

> **Maintainer implementation reference.** `burnchain-policy.sh`,
> `version-matrix.mjs`, `soak-runner.sh`, `environment-lock.sh`,
> `local-access.sh`, and `capacity-preflight.sh` are not public CLIs in Release 1. Agents and
> end users must not automate against them. Use `contrib/attacknet/attacknet`
> and `attacknet commands --json`; helper arguments and environment variables
> may change without an Attacknet interface-version bump.

## Further reading

- [`OPERATIONS.md`](OPERATIONS.md): full topologies, controlled faults,
  dashboards, serialization, recovery, and teardown.
- [`EVIDENCE.md`](EVIDENCE.md): evidence trust, capture, soak qualification,
  incident handling, replay, and minimization.
- [`DEVELOPMENT.md`](DEVELOPMENT.md): images, topology rendering, version matrices,
  controller development, and offline checks.
- [`ROADMAP.md`](ROADMAP.md): unimplemented burnchain reorg, multi-Bitcoin,
  managed-cluster, storage, and controller-HA work.
- [`INSTRUMENTATION.md`](INSTRUMENTATION.md): portable metric-family contracts
  and provenance.
- [`ADVERSARIAL-ACTORS.md`](ADVERSARIAL-ACTORS.md): bounded modified actors.
- [`REPRODUCIBILITY.md`](REPRODUCIBILITY.md): run descriptors, seeds, and replay.
- [`FAILURE-ATTRIBUTION.md`](FAILURE-ATTRIBUTION.md): triage and root-cause
  evidence requirements.
