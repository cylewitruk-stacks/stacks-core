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
custom-resource layouts are lower-level interfaces; the versioned
`contrib/attacknet/attacknet` facade remains the Release 1 automation boundary.

## What the chart installs

Hacknet installs two namespaced controllers with separate service accounts:

- the topology operator reconciles `StacksNetwork` resources into ConfigMaps,
  Services, StatefulSets, PVCs, and optional telemetry/probe sidecars;
- the run operator reconciles `FaultCampaign` and `AttacknetRun` resources and
  has narrowly scoped permissions for supported Chaos Mesh resources; and
- both controllers expose health and Prometheus endpoints through namespaced
  Services.

The local installer applies all three CRDs before running Helm so an existing
installation receives schema updates. Helm intentionally leaves those CRDs
installed when the release is removed.

Hacknet does **not** install or configure:

- Docker Desktop or Kubernetes;
- Chaos Mesh;
- host tools such as Helm, `kubectl`, Node.js, Python, or `jq`;
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
| `jq` | Available on the host for installer and evidence helpers |
| Node.js | 20 or newer |
| Python | 3.11 or newer |
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

### 3. Build local images

Build the topology operator, run operator, active probe, I/O-pressure helper,
and the current Stacks node/signer image:

```bash
BUILD_STACKS_IMAGE=1 contrib/helm/hacknet/scripts/build-local.sh
```

A cold Stacks image build can take tens of minutes. Its Dockerfile uses Cargo
Chef and BuildKit cache mounts for subsequent revisions.

### 4. Install Hacknet

```bash
contrib/helm/hacknet/scripts/install-local.sh
kubectl get deployments -n hacknet-system
kubectl get crd \
  stacksnetworks.testing.stacks.org \
  faultcampaigns.testing.stacks.org \
  attacknetruns.testing.stacks.org
```

Both controller Deployments must become Available. The installer:

- assigns content-derived tags to the local chart-managed images;
- imports those exact images into every Docker Desktop `kind` node;
- server-side applies and waits for all three CRDs; and
- performs an atomic Helm upgrade with rollback on failure.

Set `HACKNET_KIND_IMAGE_LOAD=require` to reject a cluster that is not entirely
Docker-backed `kind`. Use `disabled` only when a registry or external image
loader already provides immutable references.

### 5. Run the compatibility doctor

```bash
contrib/attacknet/attacknet doctor
```

Do not begin an acceptance or baseline run until it reports `compatible`.
Use `contrib/attacknet/attacknet doctor --json` for automation.

## First controller smoke

The image-independent smoke uses public BusyBox actors to exercise dependency
gates, Services, StatefulSets, PVCs, status, and garbage collection:

```bash
kubectl apply \
  --namespace hacknet-system \
  --filename contrib/helm/hacknet/examples/operator-smoke.yaml

kubectl get stacksnetworks,pods,pvc --namespace hacknet-system --watch
```

Wait until the resource is Ready, then stop the watch with Ctrl-C. In another
terminal, inspect the reconciled resource:

```bash
kubectl describe stacksnetwork operator-smoke --namespace hacknet-system
kubectl get stacksnetwork operator-smoke \
  --namespace hacknet-system \
  --output=jsonpath='{.status.phase}{"\n"}'
```

Success means the phase reaches `Ready` and both actors report ready in
`.status.actors`. Remove the smoke and confirm its actor PVCs disappear:

```bash
kubectl delete stacksnetwork operator-smoke --namespace hacknet-system
kubectl get statefulsets,services,configmaps,pvc \
  --namespace hacknet-system \
  --selector=testing.stacks.org/network=operator-smoke
```

The final query should return no owned resources after Kubernetes garbage
collection completes.

## First Stacks smoke

`examples/minimal.yaml` starts Bitcoin Core, a separate burnchain clock, and a
Stacks follower. Import the locally built Stacks image into every `kind` node
before applying it:

```bash
contrib/helm/hacknet/scripts/load-kind-images.sh \
  stacks-core-attacknet:main

kubectl apply \
  --namespace hacknet-system \
  --filename contrib/helm/hacknet/examples/minimal.yaml

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
permission. The resource contains global defaults and an explicit actor list;
each actor can override its image, command, arguments, ports, resources,
storage, probes, configuration, dependencies, labels, and telemetry settings.

Configuration has exactly one source:

- `inline` for public, non-secret regtest configuration;
- `configMapRef` for externally managed configuration; or
- `secretRef` for keys and tokens.

The operator cannot read Secrets. Kubernetes mounts a referenced Secret
directly into the actor Pod. Prefer Secret-backed signer and miner
configuration even in disposable environments.

Configuration, command, argument, environment, and telemetry strings support:

| Placeholder | Expansion |
| --- | --- |
| `${NETWORK}` | `StacksNetwork.metadata.name` |
| `${NAMESPACE}` | resource namespace |
| `${ACTOR}` | current actor name |
| `${SERVICE:actor-name}` | generated Service name for the referenced actor |

Every actor Pod receives these non-overridable labels:

```text
testing.stacks.org/network=<StacksNetwork name>
testing.stacks.org/actor=<actor name>
testing.stacks.org/role=<role>
app.kubernetes.io/managed-by=hacknet-operator
```

These labels are the supported selection surface for fault injection and
evidence. The schema's legacy `companion` role identifies a configured signer
node; new prose and user-facing names should call it a signer node.

An actor may set `runtimeExposure: reachable` to publish its headless-Service
endpoint before its Pod is Ready. The default, `ready`, keeps bootstrap
deterministic. This affects DNS discovery and new connections, not established
sessions, and is not a runtime fault mechanism.

### `FaultCampaign`

`FaultCampaign` is either an inert reusable template (`spec.template: true`) or
one bounded execution. The run controller resolves exact admitted Pod
identities and owns cleanup through a finalizer.

Supported native Chaos Mesh resources are `PodChaos`, `NetworkChaos`,
`DNSChaos`, `IOChaos`, and `TimeChaos`. The controller can also create one
restricted I/O-pressure Pod from the chart-configured trusted image. Campaigns
cannot supply that image, executable, shell, or arbitrary arguments.

Apply direct examples only after the referenced network is Ready:

```bash
kubectl apply --filename contrib/helm/hacknet/examples/fault-campaign.json
kubectl apply --filename contrib/helm/hacknet/examples/fault-campaign-io-pressure.json
kubectl get faultcampaigns --namespace hacknet-system --watch
```

Chaos Mesh `AllInjected` and `AllRecovered` conditions are context, not proof
that the target experienced the requested effect. Without trusted effect and
recovery observations, a campaign terminates `Inconclusive`, never `Passed`.

### `AttacknetRun`

`AttacknetRun` resolves a finite fault catalog before the first action. It pins
template identity and generation, network identity and generation, admitted
actor image digests, seeded decisions, and aggregate budgets in a sealed,
owner-bound ConfigMap. It creates at most one owned campaign at a time.

```bash
kubectl apply --filename contrib/helm/hacknet/examples/attacknet-run.json
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
credential-free `attacknet-probe` sidecar on Pod port `18080`. The port is not
published through the actor Service. The bounded probe API can observe:

- enrolled TCP endpoints and latency;
- a selected DNS name plus a fixed cluster control;
- confined filesystem I/O under the actor data volume;
- wall and monotonic clocks; and
- bounded platform and architecture identity.

There is no shell, arbitrary hostname, or arbitrary path operation. The run
controller admits probe evidence only from an exact Ready Pod UID whose probe
container is independently Ready. Actor logs and actor-provided payloads are
not authoritative probe evidence.

For a direct, locally authored `StacksNetwork` that enables probes, import the
probe image before applying the resource:

```bash
contrib/helm/hacknet/scripts/load-kind-images.sh \
  stacks-hacknet-probe:dev
```

The public Attacknet lifecycle resolves and transports its declared probe image
as part of the rendered topology.

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
| Controller image is unavailable | Re-run `build-local.sh`, then `install-local.sh`; Docker Engine and `kind` node image stores are separate. |
| CRD schema did not update | Inspect managed fields, then use `HACKNET_FORCE_CRD_CONFLICTS=1` once only when deliberately reclaiming ownership. |
| Helm release is `failed` | Run `helm status hacknet -n hacknet-system`; set `HACKNET_RECOVER_FAILED_RELEASE=1` only after identifying the cause. |
| Upgrade reports a managed-field conflict | Do not use `kubectl set image`; inspect ownership before considering `HACKNET_FORCE_CONFLICTS=1`. |
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

For a registry deployment, publish immutable controller, run-operator, probe,
I/O-pressure, and actor image references. The development-source ConfigMap
fallback exists only for local controller debugging and must remain disabled in
packaged deployments.

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
