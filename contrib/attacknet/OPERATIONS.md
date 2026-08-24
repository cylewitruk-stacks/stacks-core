# Attacknet operations

This guide covers established Release 1 operations after the local control
plane has passed `contrib/attacknet/attacknet doctor`. Begin with the
[README quickstart](README.md) on a new installation.

## Public interface

Use `contrib/attacknet/attacknet` for routine human and agent workflows. Its
versioned registry is the source of truth for inputs, outputs, privileges,
side effects, execution environments, and exit codes:

```bash
contrib/attacknet/attacknet commands --json
contrib/attacknet/attacknet help COMMAND
```

Scripts such as `burnchain-policy.sh`, `version-matrix.mjs`, `soak-runner.sh`,
`environment-lock.sh`, `local-access.sh`, `capacity-preflight.sh`, and
other implementation helpers are maintainer/debugging interfaces. Their
environment variables and argument layouts may change without an Attacknet
interface-version bump.

## Network lifecycle

### Small topology

```bash
ATTACKNET=contrib/attacknet/attacknet

$ATTACKNET render \
  --network=attacknet-small \
  --miners=1 --signers=1 --followers=1 --probes=true \
  --output=contrib/attacknet/generated/small

$ATTACKNET lifecycle apply contrib/attacknet/generated/small

$ATTACKNET verify contrib/attacknet/generated/small/manifest.json snapshot
```

### Full topology

The qualified full protocol topology has 28 actors: 3 miners, 10 signers, 10
Stacks nodes configured for those signers, and 5 followers. Bitcoin Core, the
burnchain clock, and stacker bootstrap bring the total to 31 workloads.

Run the capacity preflight before the first full deployment:

```bash
contrib/attacknet/capacity-preflight.sh
```

The default stages are `1:1:1`, `2:4:2`, and `3:10:5` in
miners/signers/followers order. Every stage uses fresh PVCs because signer-count
changes alter genesis balances. The retained `operator-pressure.json` records
API request counts, reconciliation latency, and transport errors.

After it passes:

```bash
$ATTACKNET render \
  --network=attacknet \
  --miners=3 --signers=10 --followers=5 --probes=true \
  --output=contrib/attacknet/generated/full

$ATTACKNET lifecycle apply contrib/attacknet/generated/full
```

### Two-phase startup

Kubernetes startup deliberately performs initial block download without signer
event observers. The external Bitcoin clock advances until PoX and Nakamoto
state exist. After every signer proves initialization from its configured
node's live RPC view, lifecycle orchestration pauses the clock, applies the
observer-enabled resources, waits for the node rollouts, and resumes cadence.

This avoids replaying historical IBD notifications as live forks. Do not bypass
the lifecycle facade by cold-starting final generated resources directly.

## Burnchain cadence

Bitcoin Core and its Stacks-blind clock are separate failure domains. Policy
can pause, run continuously, or mine a bounded burst without restarting
Bitcoin:

```bash
contrib/attacknet/burnchain-policy.sh pause
contrib/attacknet/burnchain-policy.sh run 20 0
contrib/attacknet/burnchain-policy.sh burst 3
```

Bursts persist an absolute Bitcoin target height. Restarting the clock resumes
only the missing suffix and never replays a completed burst.

## Bounded fault execution

### Direct Chaos Mesh smoke

The facade can run a campaign that compiles directly to a Chaos Mesh resource:

```bash
$ATTACKNET campaign plan \
  contrib/attacknet/examples/follower-network-delay.json \
  contrib/attacknet/generated/full/manifest.json \
  /tmp/follower-delay.json

$ATTACKNET campaign run \
  contrib/attacknet/examples/follower-network-delay.json \
  contrib/attacknet/generated/full/manifest.json \
  contrib/attacknet/evidence/follower-delay
```

The direct runner verifies baseline health, `AllInjected`, `AllRecovered`,
resource removal, network recovery, and post-fault progress. It does not claim
independent proof of the requested packet impairment.

Controller-owned policies and one-shot kill actions are intentionally rejected
by the direct runner. Use the APIs below when the effect itself must be proven.

### Evidence-grade `FaultCampaign`

`FaultCampaign` resolves targets to exact current Ready Pod UIDs and immutable
admitted image identities. It enforces finite duration/severity limits,
signer-weight and miner-impact budgets, one active fault at a time, and
finalizer-owned cleanup.

The example template and run target the full network named `attacknet`:

```bash
kubectl apply -f contrib/helm/hacknet/examples/fault-campaign.json
kubectl apply -f contrib/helm/hacknet/examples/attacknet-run.json
kubectl get faultcampaigns,attacknetruns -n hacknet-system -w
```

Before its first fault, `AttacknetRun` seals the resolved schedule, network
identity, image digests, seed decisions, and aggregate budgets in an
owner-bound ConfigMap. Execution uses only those pinned instructions.

`AllInjected` is bookkeeping, not effect evidence. Pod faults use observed Pod
UID/readiness/restart state. Network and DNS faults use controlled
before/during/after probes. I/O and clock faults use mechanism-specific trusted
metrics. An execution without sufficient effect evidence ends `Inconclusive`,
never `Passed`.

### Architecture-specific faults

Chaos Mesh 2.8.3 native IOChaos and TimeChaos are gated to `amd64`. On the
qualified arm64 cluster:

- Use `io-pressure` / `disk-pressure` for bounded data-PVC pressure. The run
  controller owns the trusted image, command, resources, target PVC, and
  cleanup. See
  `contrib/helm/hacknet/examples/fault-campaign-io-pressure.json`.
- Use application `clock-skew` for process-visible realtime changes. Monotonic
  time remains real. The controller must observe both the requested offset and
  recovery against an independent control actor.

Neither mechanism is reported as its superficially similar Chaos Mesh fault.
Do not extend architecture allowlists without independent effect and recovery
proof.

## Environment serialization

One Kubernetes cluster may contain only one active Attacknet. Apply and delete
hold a persistent environment lease. Cadence changes, evidence capture, and
complete campaigns take a short-lived mutation lease. Read-only Prometheus,
Loki, API, and dashboard queries remain concurrent.

```bash
contrib/attacknet/environment-lock.sh status
```

Do not remove a lease because an operation is merely slow. First prove its
owner is gone and inspect admitted state. Automatic stale-lease takeover is
intentionally absent because it would hide controller or garbage-collector
failure.

Use a bounded controller-owned Pod fault for process unavailability and let its
finalizer own recovery.

## Dashboards and local access

### Grafana

Lifecycle apply maintains a rediscovering loopback forward to the sole enrolled
Grafana Service:

```bash
contrib/attacknet/local-access.sh status
```

Open <http://127.0.0.1:3000>. The network command center and actor drill-down
show chain progress, cohort divergence, fault context, admitted image identity,
role-specific metrics, and centralized logs.

Disable automatic local access for an unattended run by setting
`ATTACKNET_LOCAL_ACCESS_ENABLED=0` before lifecycle apply.

### Chaos Dashboard

For a disposable loopback-only local cluster:

```bash
contrib/attacknet/chaos-dashboard.sh local
contrib/attacknet/chaos-dashboard.sh status
```

Open <http://127.0.0.1:2333>. Restore authenticated mode with:

```bash
contrib/attacknet/chaos-dashboard.sh secure
```

Never disable Dashboard authentication on a shared or remotely reachable
cluster. The optional cluster-scoped local credential is documented in
`chaos-dashboard-cluster-access.yaml`; it can create and delete any Chaos Mesh
experiment and must never be mounted into an actor Pod.

### Headlamp

Headlamp is the preferred cluster-wide resource viewer. Installing it is
optional and independent of Attacknet:

```bash
helm repo add headlamp https://kubernetes-sigs.github.io/headlamp/
helm repo update
helm upgrade --install headlamp headlamp/headlamp \
  --namespace headlamp --create-namespace
kubectl -n headlamp port-forward service/headlamp 8080:80 \
  --address=127.0.0.1
```

Open <http://127.0.0.1:8080>. Give Headlamp a bounded viewer identity; actor
Pods remain credential-free.

## Recovery and teardown

On failure, preserve the network, admitted resources, PVCs, logs, and incident
directory until attribution is complete. Do not recreate the system under test
to make a failed check pass.

Useful first checks:

```bash
$ATTACKNET doctor --json
contrib/attacknet/environment-lock.sh status
contrib/attacknet/local-access.sh status
kubectl get stacksnetworks,faultcampaigns,attacknetruns -n hacknet-system
kubectl get pods,pvc -n hacknet-system -o wide
```

Capture before deleting:

```bash
$ATTACKNET evidence capture \
  contrib/attacknet/evidence/incident-manual \
  contrib/attacknet/generated/full/manifest.json
```

Then delete through the same generated directory that created the network:

```bash
$ATTACKNET lifecycle delete contrib/attacknet/generated/full
```

Deleting the `StacksNetwork` garbage-collects owned ConfigMaps, Services,
StatefulSets, and actor PVCs. Scaling/suspension retains PVCs so it remains
reversible. The StorageClass determines when backing storage is physically
reclaimed.

See [`EVIDENCE.md`](EVIDENCE.md) and
[`FAILURE-ATTRIBUTION.md`](FAILURE-ATTRIBUTION.md) before classifying an
incident.
