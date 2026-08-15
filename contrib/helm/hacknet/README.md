# Hacknet operator

Hacknet is the first Kubernetes-native deployment layer for disposable Stacks
regtest and adversarial test networks. The chart installs a namespaced
`StacksNetwork` controller. Creating a `StacksNetwork` causes the controller to
reconcile one Service and one single-replica StatefulSet per declared actor,
plus generated configuration and optional telemetry sidecars.

This is test infrastructure. It is not a production Stacks operator. Never use
valuable private keys, wallets, or funds in a Hacknet namespace.

## Why an operator

Helm installs and upgrades the control plane. The operator remains active after
installation and owns the domain-specific lifecycle:

- stable, independently disruptable miner, signer, companion, follower,
  burnchain, infrastructure, and adversarial actors;
- per-actor image selection for mixed-version and modified-build tests;
- Pod recreation through StatefulSets rather than unreconciled bare Pods;
- optional persistent storage without coupling actor failure domains;
- OpenTelemetry Collector sidecars colocated with their actor;
- deterministic service discovery and dependency waits;
- status reporting suitable for humans and an external agent; and
- stable labels for Chaos Mesh selectors and evidence collection.

Adaptive decisions deliberately stay outside the controller. An agent can
create or patch a constrained `StacksNetwork`, observe its status and telemetry,
and create bounded Chaos Mesh experiments without receiving unrestricted
cluster-admin access.

## Current scope

The operator deploys and reconciles actor processes. The transport-independent
topology, watch-only Bitcoin wallet setup, stacking bootstrap, runtime adapter,
and evidence harness live in `contrib/attacknet`. `examples/minimal.yaml` stays
as a small deployment smoke; generated attacknet resources are the scalable
current-main system-under-test profile.

The chart requires Kubernetes 1.27 or newer. Hacknet relies on the stable
StatefulSet PVC retention policy introduced in that release.

## Install on Docker Desktop Kubernetes

After enabling Kubernetes in Docker Desktop, verify the context before making
changes:

```sh
kubectl config current-context
kubectl cluster-info
```

From the repository root, build the controller. Set `BUILD_STACKS_IMAGE=1` to
also build the current-main node/signer image used by the smoke example.

```sh
contrib/helm/hacknet/scripts/build-local.sh
BUILD_STACKS_IMAGE=1 contrib/helm/hacknet/scripts/build-local.sh
```

With Docker Desktop's containerd image store, kind resolves locally built
images through its internal registry mirror. Keep the default
`IfNotPresent` policy: `Never` prevents that mirror lookup and produces
`ErrImageNeverPull`. Install the normal packaged controller path with:

```sh
helm upgrade --install hacknet contrib/helm/hacknet \
  --namespace hacknet-system \
  --create-namespace \
  --wait \
  --rollback-on-failure
```

If a local cluster still cannot resolve Docker Engine images, the chart has an
explicit fallback that mounts its controller source into a public Python
runtime without pushing a development image. This is not the packaged path:

```sh
helm upgrade --install hacknet contrib/helm/hacknet \
  --namespace hacknet-system \
  --create-namespace \
  --wait \
  --rollback-on-failure \
  --set operator.developmentSource.enabled=true
```

For a registry-hosted image, leave `operator.developmentSource.enabled=false`
and configure `operator.image` normally.
The operator uses an explicitly projected, rotating service-account token and
reads it from disk for every API request. For a local rotation smoke, set
`serviceAccount.tokenExpirationSeconds=600`; the packaged default is 3600.
Kubelet rotates projected tokens before their requested expiry rather than on
that exact boundary. The 600-second Docker Desktop smoke observed replacement
after roughly 543 seconds, so tests should compare token identity and continued
reconciliation instead of sleeping for a presumed fixed interval.

First apply the image-independent operator lifecycle smoke into the watched
namespace. It uses public BusyBox actors and exercises dependencies, Services,
StatefulSets, and PVCs without requiring a branch Stacks image:

```sh
kubectl apply -n hacknet-system -f contrib/helm/hacknet/examples/operator-smoke.yaml
kubectl get stacksnetworks,pods,pvc -n hacknet-system -w
kubectl describe stacksnetwork operator-smoke -n hacknet-system
```

After loading or publishing the branch Stacks image, apply the burnchain and
follower smoke network:

```sh
kubectl apply -n hacknet-system -f contrib/helm/hacknet/examples/minimal.yaml
kubectl get stacksnetworks,pods,pvc -n hacknet-system -w
kubectl describe stacksnetwork minimal -n hacknet-system
```

`examples/operator-telemetry-smoke.yaml` provides a public-image-only check of
the per-actor OpenTelemetry sidecar, generated scrape configuration, service
discovery, and bearer-token delivery to a disposable in-cluster OTLP sink. The
example comment shows how to create its non-production token Secret.

Deleting the custom resource garbage-collects its owned ConfigMaps, Services,
StatefulSets, and actor PVCs. Scaling an actor to zero—including through
`spec.suspended`—retains its PVC so the operation is reversible. This is encoded
as `whenDeleted: Delete` and `whenScaled: Retain` on every actor StatefulSet;
the underlying StorageClass still determines when the backing volume is
physically reclaimed. Helm intentionally does not delete installed CRDs during
uninstall.

## Agent-facing API

The chart installs three namespaced APIs with deliberately separate
controllers:

- `StacksNetwork` owns the system under test and has no Chaos Mesh permission.
- `FaultCampaign` is either an inert reusable template (`spec.template: true`)
  or one bounded execution with exact admitted Pod identities and a cleanup
  finalizer.
- `AttacknetRun` snapshots a finite catalog of templates by UID, generation,
  and SHA-256 digest, then creates at most one owned execution at a time under
  aggregate wall-time, fault-time, signer-impact, miner, and burnchain budgets.

The run controller has a separate namespaced service account. It can read the
network and actor Pods, manage only the two run APIs, and create/delete only
`PodChaos`, `NetworkChaos`, `DNSChaos`, `IOChaos`, and `TimeChaos`. Actor Pods
remain credential-free. Apply the examples after the referenced
`StacksNetwork` is Ready:

```sh
kubectl apply -f contrib/helm/hacknet/examples/fault-campaign.json
kubectl apply -f contrib/helm/hacknet/examples/attacknet-run.json
kubectl get faultcampaigns,attacknetruns -n hacknet-system -w
```

Chaos Mesh `AllInjected` and `AllRecovered` conditions are retained as context,
but are not effect evidence. An execution without trusted evidence of the
requested fault terminates `Inconclusive`, never `Passed`. Pod faults currently
use Kubernetes-observed UID/readiness/restart evidence. The active-probe path
for network, DNS, I/O, and time faults is the next implementation increment.

The CR contains global defaults and an explicit actor list. An actor can
override its image, command, arguments, ports, resources, storage, probes,
configuration, dependencies, labels, and telemetry settings. This supports a
current build, an old release, and a maliciously modified build in one network
without changing the chart.

Configuration has exactly one of these sources:

- `inline`, for public non-secret regtest configuration;
- `configMapRef`, for configuration managed outside the CR; or
- `secretRef`, for private keys and tokens.

Referenced node ConfigMaps/Secrets contain `Config.toml` by default; signer
references contain `signer.toml`. Set `config.key` when the mounted key differs.

The operator does not have RBAC permission to read Secrets. Kubernetes mounts a
referenced Secret directly into the actor Pod. Secret-backed config is strongly
preferred for signer and miner keys, even in a disposable environment.

Inline configuration, commands, arguments, environment values, and telemetry
endpoints support these literal substitutions:

| Placeholder | Result |
| --- | --- |
| `${NETWORK}` | `StacksNetwork.metadata.name` |
| `${NAMESPACE}` | resource namespace |
| `${ACTOR}` | current actor name |
| `${SERVICE:actor-name}` | controller-generated Service name for an actor |

Every actor Pod has the following non-overridable labels:

```text
testing.stacks.org/network=<StacksNetwork name>
testing.stacks.org/actor=<actor name>
testing.stacks.org/role=<role>
app.kubernetes.io/managed-by=hacknet-operator
```

Those labels are the supported selection surface for Chaos Mesh. For example,
a companion-only fault selects `role=companion` plus a specific actor, while a
quorum guard can calculate signer weight before allowing the experiment.

## Telemetry sidecars

When telemetry is enabled, the controller adds an OTel Collector sidecar. It
scrapes the actor on localhost (`31000` for signers, `20446` otherwise) and
exports OTLP/HTTP to `telemetry.exporterEndpoint`. The bearer token can come
from `telemetry.tokenSecretRef`; it is mounted as an environment value without
the operator reading it.

The federation's strict metric allowlist and authenticated per-actor enrollment remain
collector/federation responsibilities. The initial sidecar establishes the Pod
organization and export path without silently duplicating the evolving schema
inside the operator.

## Status and suspension

The controller reports `Pending`, `Progressing`, `Ready`, `Degraded`, or
`Suspended`, plus each actor's resolved image, resource name, and readiness.

An actor may set `runtimeExposure: reachable` to publish its headless-Service
endpoint before the pod is Ready. The default, `ready`, keeps bootstrap
deterministic. This is a discovery control: it affects new DNS lookups, not
already-established connections, and therefore is not a substitute for a
runtime fault such as Chaos Mesh network or process disruption.

```sh
kubectl get snet -n hacknet-system
kubectl get snet minimal -n hacknet-system -o jsonpath='{.status.actors}'
```

Setting `spec.suspended: true` scales all actor StatefulSets to zero while
retaining their resources and storage. Removing it reconciles them back to one
replica.

An invalid actor makes the complete desired topology invalid. The controller
validates every actor before mutating resources, leaves the last known-good
network running, and reports `Degraded`; it does not partially apply the valid
subset. Likewise, it refuses to adopt a same-named Kubernetes resource unless
that resource's controller owner UID matches the current `StacksNetwork`.

The controller reads its projected service-account token for every API request,
so kubelet token rotation does not require a restart. Readiness follows API
availability. Liveness follows controller-loop progress rather than API success,
avoiding a Pod restart storm when the Kubernetes API server is unavailable.
Its Service exposes dependency-free Prometheus metrics on `/metrics`, including
bounded method/status API-request counters, request latency, reconcile outcome
and latency, per-reconcile API volume, process start time, and managed-network
count. Capacity evidence compares snapshots from the same process and fails if
the controller restarted or observed throttling, server errors, or transport
failures during a stage.

## Development checks

```sh
contrib/helm/hacknet/scripts/check.sh
```

The check runs controller unit tests and, when Helm is installed, lints and
renders the chart. A live-cluster smoke should additionally confirm StatefulSet
recreation, status transitions, sidecar export, projected-token rotation
(use the documented 600-second smoke setting for a bounded test), CR deletion,
and that no actor PVC survives deletion.

It should also delete and immediately recreate a same-named `StacksNetwork`.
Until background garbage collection removes the old UID's children, the new
resource must report `Degraded` with an ownership-collision diagnostic; it must
then converge by creating fresh children, never adopting the old resources. If
that condition persists, inspect finalizers and garbage-collector health on the
old StatefulSets, Services, and ConfigMaps. The Role already permits deletion
of those child kinds, but the controller intentionally does not duplicate
garbage collection merely because the former owner UID is gone. Automatically
compensating would hide a cluster-level GC or finalizer fault behind an
apparently healthy network; manual removal remains an explicit operator action.

Actor Pods never receive the operator's service-account token. Ownership,
namespaced RBAC, restricted Pod security, token projection, and evidence
integrity are control-plane invariants and remain enabled even for malicious
actor scenarios. Fault realism belongs in explicit data-plane controls; it
must not depend on compromising the experiment controller itself.

## Compose-to-Hacknet migration discipline

The proven Compose topology remains authoritative while the complete 28-actor
network is ported. The port must share one topology model and, more importantly,
run the same assertion and evidence code against both backends. HTTP/RPC,
Prometheus, observer, drift, lifecycle-conservation, and released-proposal
checks must not be rewritten for Kubernetes. Only process execution, service
addressing, logs, lifecycle operations, and artifact copying belong in thin
Compose and Kubernetes adapters. Harness loops must enumerate actors, roles,
and signer/companion relationships from that model; hardcoded actor counts and
synthesized numeric service-name ranges are prohibited.

Before adding more fault APIs, bring up the full topology incrementally on the
target cluster and record admitted Pod resources, PVC/PV placement, startup
latency, reconciliation duration/API pressure, throttling, OOMs, evictions, and
probe failures. A single-node kind cluster proves control-plane and local-PVC
lifecycle behavior, but it does not prove rescheduling or CSI reattachment.

After parity is demonstrated, Hacknet becomes authoritative for long soaks,
mixed-version runs, malicious builds, and adversarial evidence. Compose remains
the short deterministic developer loop. Cutover requires the same actor IDs,
images/config hashes, shared assertions, current chaos scenarios, evidence
schema, deliberate negative-test detection, and a clean 300+ burn-block run
without cluster resource pressure.

Readiness-gated Services are a deterministic default, not a claim about the
public network. Withdrawing an endpoint affects discovery and new connections,
not established application sessions. Future dependency cycles should be detected
and reported, not prohibited; runtime degradation belongs to explicit process
or Chaos Mesh controls. TimeChaos scenarios must first inventory which code
uses wall clock versus monotonic time so the injected fault can affect the
stated hypothesis.

## Next increments

1. Extract the backend-neutral topology, assertion, scenario, and evidence
   layers; keep only a thin Compose/Kubernetes execution adapter.
2. Port the full 28-actor topology and run an incremental capacity preflight
   before adding more fault controls.
3. Port Bitcoin wallet funding, stacking, observer federation, and evidence
   archival as controlled Jobs or dedicated controllers.
4. Integrate trusted network/DNS/I/O/time proof probes with the namespaced
   `FaultCampaign`/`AttacknetRun` controller and prove each Chaos family live.
5. Add snapshot/restore and explicit evidence-preservation policy.
6. Add leader election only when multiple controller replicas are warranted.
