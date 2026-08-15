# Stacks Attacknet

This directory contains the transport-independent test harness for adversarial
Stacks regtest networks. The default profile follows the node and signer code
on current `main`; it uses the production StackerDB signer transport. A future
libp2p build can be supplied as another actor image/profile without becoming a
dependency of the harness or operator.

The Helm chart in `contrib/helm/hacknet` supplies the reliable namespaced
control plane. This directory supplies the system-under-test topology,
burnchain policy, backend adapter, assertions, and evidence capture.

## Design boundaries

- Bitcoin Core, its Stacks-blind block clock, and the policy that steers the
  clock are separate failure domains.
- Actor counts and inventories come from `manifest.json`; harness scripts do
  not encode a ten-signer assumption.
- Kubernetes is canonical for adversarial runs. Compose is the small smoke
  adapter; both renderers use the same model, manifest, and assertions.
- Baseline resources are bounded. Adversarial profiles may opt out, but the
  evidence bundle must capture the admitted Pod spec so LimitRange/Quota
  mutation cannot be mistaken for an unbounded run.
- Control-plane hardening does not constrain what actor Pods may experience.
  Actor Pods have no service-account token.

## Local images

Build current main's node and signer binaries:

```bash
docker build -f contrib/attacknet/Dockerfile -t stacks-core-attacknet:main .
docker build -t stacks-attacknet-stacker:local contrib/attacknet/stacker
```

The attacknet image uses upstream's `release-lite` profile and adds only
`curl`/CA certificates needed by delayed-start and evidence probes. It pins
`cargo-chef` and the Rust toolchain so Cargo metadata changes invalidate a
separate dependency-cook stage while ordinary source edits reuse the BuildKit
registry, git, and target caches. Release artifacts retain the repository's
fat-LTO profile; iterative experiments do not need its single-codegen-unit link
cost. Record the resolved builder/runtime image digests and recipe digest in
the run descriptor when comparing builds across machines or CI workers.

Docker Desktop's Docker image store is not the same as the containerd store in
each kind node. `contrib/helm/hacknet/scripts/install-local.sh` now detects
kind-on-Docker, imports its exact content-derived chart image tags into every
node, and verifies them before Helm runs. For independently-built actor/version
images, use `scripts/load-kind-images.sh --mode=require --output=receipt.json
IMAGE...` and retain the receipt beside the build/admission evidence. Real
clusters should use immutable registry digests rather than this local loader.

## Render and run

Start with a capacity stage before attempting the 31-workload full topology:

```bash
node contrib/attacknet/topology.mjs \
  --miners=1 --signers=1 --followers=1 \
  --output=contrib/attacknet/generated/stage-1

KUBE_NETWORK=attacknet-stage-1 \
  contrib/attacknet/lifecycle.sh apply contrib/attacknet/generated/stage-1
```

The same render includes `compose.yaml`, so a local smoke can instead use:

```bash
ATTACKNET_BACKEND=compose \
ATTACKNET_COMPOSE=contrib/attacknet/generated/stage-1/compose.yaml \
  contrib/attacknet/verify.sh \
  contrib/attacknet/generated/stage-1/manifest.json snapshot
```

Kubernetes startup is deliberately two-phase. Companion nodes first perform
IBD from `stacksnetwork.bootstrap.json` without signer event observers. Once
the pre-activation foundation is Ready, the external clock advances Bitcoin at
the bootstrap cadence so PoX/Nakamoto state can exist. After
`stacks_signer_runloop_ready` proves every signer initialized from its live
companion RPC view, `lifecycle.sh` pauses the clock with a process-level policy
acknowledgment, applies the final observer-enabled resource, waits for the
companion rollout, and resumes the requested cadence. This prevents historical
IBD notifications from being misclassified as live forks without deadlocking
signer initialization at genesis.

The renderer also emits `compose.bootstrap.yaml`. A Compose runner must follow
the same two-phase contract—start the bootstrap file, wait for signer runloop
readiness, then apply `compose.yaml` while preserving node volumes—rather than
starting the final file cold. The Kubernetes lifecycle is currently the
canonical automated implementation of this contract.

Use repeatable per-actor image overrides for an upgrade matrix or modified
adversarial binary:

```bash
node contrib/attacknet/topology.mjs \
  --miners=3 --signers=10 --followers=5 \
  --actor-image=miner-3=stacks-core:v4.0.2 \
  --actor-image=signer-10=stacks-core:malicious \
  --output=contrib/attacknet/generated/mixed
```

For a bounded, reviewable current/old/modified matrix, describe the complete
actor inventory, profiles, and ordered phases in the
[`version-matrix.schema.json`](version-matrix.schema.json) format. Compile a
planning artifact offline with:

```bash
node contrib/attacknet/version-matrix.mjs \
  contrib/attacknet/examples/version-matrix.plan.json \
  --output=contrib/attacknet/generated/version-matrix.json
```

Each compiled phase contains `actorImages` and the corresponding
`topologyArguments` (`--actor-image=ACTOR=IMAGE`) accepted by this renderer.
Source resolution never contacts a registry or remote Git server: `current`
resolves the local `HEAD` and worktree state, `releasedGitRef` resolves an
already-present ref to its commit, and `localModified` additionally records a
change ID, binary-diff/untracked-file state digest, and Dockerfile digest.

Planning mode deliberately permits mutable tags and incomplete build metadata,
but marks `acceptanceReady: false` and lists every unresolved input. Add
`--acceptance` for a fail-closed artifact: every actor image must be an OCI
digest reference; prebuilt images must carry an immutable provenance
attestation; and locally-built images must name digest-pinned builder and
runtime images plus cargo-chef recipe, build-invocation, and attestation
digests/references. The existing attacknet Dockerfile supplies the shared
`cargo-chef` dependency layer and sets `CARGO_INCREMENTAL=0`; do not fork a
second build recipe per version. Builds should use isolated BuildKit cache
namespaces keyed by Rust/Cargo.lock and target platform, then record their
resulting digest and attestation back into the matrix.

On Apple Silicon, native `linux/arm64` is the default. An amd64-only historical
image is admissible only when its profile explicitly says
`execution: emulated` and `executionPlatform: linux/amd64`. This makes the
performance and timing caveat visible in evidence instead of silently relying
on Docker Desktop emulation. Compatibility fields and phase hypotheses remain
claims to test, not proof. The first live missed-upgrade slice now runs exact
release 4.0.2 as follower-5 among current actors and binds its BuildKit OCI
index through the arm64 manifest to the exact CRI config digest and Ready Pod
UID. Broader rolling-upgrade matrices and deliberately incompatible actors
still require their own admitted run evidence and behavioral assertions.

The full protocol topology has 28 actors (3 miners, 10 signer/companion pairs,
and 5 followers) plus Bitcoin, the burnchain clock, and the stacker bootstrap:

```bash
node contrib/attacknet/topology.mjs \
  --network=attacknet --miners=3 --signers=10 --followers=5 \
  --output=contrib/attacknet/generated/full
contrib/attacknet/lifecycle.sh apply contrib/attacknet/generated/full
```

Steer cadence without restarting Bitcoin or coupling the clock to Stacks:

```bash
contrib/attacknet/burnchain-policy.sh pause
contrib/attacknet/burnchain-policy.sh run 20 0
contrib/attacknet/burnchain-policy.sh burst 3
```

Capture Kubernetes-admitted resources and runtime evidence:

```bash
contrib/attacknet/lifecycle.sh capture evidence/admitted
ATTACKNET_BACKEND=kubernetes \
contrib/attacknet/evidence-harness.sh evidence/behavior \
  contrib/attacknet/generated/full/manifest.json 1h
```

## Environment serialization

One Kubernetes cluster may contain only one active attacknet. Lifecycle apply
and delete operations hold a persistent environment lease, while cadence
changes, evidence/incident capture, and complete fault campaigns take a
short-lived mutation lease. A
blocked writer reports the current owner, purpose, network, and acquisition
time; read-only Prometheus/Loki/API queries remain concurrent.

```bash
contrib/attacknet/environment-lock.sh status
```

Do not remove or steal either lease merely because an operation is slow. First
prove that its owning process is gone and inspect the admitted network. There
is deliberately no automatic stale-lease takeover: hiding a dead controller or
wedged Kubernetes garbage collector would invalidate failure attribution. The
test-only lock bypass requires both `ATTACKNET_LOCK_DISABLED=1` and
`ATTACKNET_NEGATIVE_CONTROL=1`, and its use must be recorded as a negative
control rather than baseline evidence.

Run static and behavioral renderer checks with:

```bash
contrib/attacknet/check.sh
```

Run the clean-volume staged capacity preflight with:

```bash
contrib/attacknet/capacity-preflight.sh
```

The default stages are `1:1:1`, `2:4:2`, and `3:10:5` (miners, signers,
followers). Each stage starts from fresh PVCs because increasing the signer
count changes genesis balances; retaining the earlier chainstate would make the
capacity comparison invalid. Override `ATTACKNET_CAPACITY_STAGES` for a faster
smoke or a more gradual profile. Every stage snapshots the operator's
Prometheus endpoint before and after reconciliation and fails on an operator
restart, transport error, HTTP 429, or HTTP 5xx. The retained
`operator-pressure.json` records request counts and API/reconcile latency rather
than treating eventual Pod readiness as evidence that the control plane was
healthy.

Run one locally-admitted bounded fault against an active network with:

```bash
contrib/attacknet/campaign-runner.sh \
  contrib/attacknet/examples/companion-failure.json \
  contrib/attacknet/generated/full/manifest.json \
  evidence/companion-failure
```

The compiler requires finite typed safety limits, action-specific severity
bounds, mode-aware signer/miner impact, and explicit opt-ins for quorum loss,
majority-miner outages, extreme severity, extended duration, burnchain targets,
or unenrolled network targets. Before injection, the runner resolves each actor
to exactly one current Ready Pod UID and immutable admitted image identity.
Clearance is successful only when `AllRecovered`, resource deletion, and
resource absence are all observed; forced deletion remains a failed campaign
even when it safely removes the fault.

### Burnchain fork campaigns

`BurnchainReorg` is a planned first-class semantic fault, distinct from a
process or packet-level Chaos Mesh fault. Bitcoin Core regtest exposes
`invalidateblock` and `reconsiderblock`; a deterministic single-backend
campaign can therefore record the current branch, invalidate the first block
of a bounded suffix, mine a longer replacement suffix, and make every Stacks
actor observe a genuine Bitcoin-chain reorganization.

The campaign must not expose arbitrary Bitcoin RPC. Its admitted contract will
pin the original tip/hash sequence, fork parent, requested depth, replacement
block count and recipients, current PoX/epoch phase, exact RPC acknowledgments,
new canonical sequence, and all Stacks rollback/recovery observations. Safety
budgets must bound fork depth and duration, prohibit crossing an unspecified
epoch or reward-cycle boundary, require the environment mutation lease, and
fail closed if the observed branch differs from the sealed precondition.
`reconsiderblock` is cleanup of the local invalidity marker, not by itself proof
that the intended replacement branch remained canonical.

This one-bitcoind scenario exercises Stacks burnchain reorg handling but not a
Bitcoin network partition. A higher-fidelity topology gives every Stacks node
its own Bitcoin follower, matching the recommended deployment shape, and joins
those followers through an explicit regtest Bitcoin P2P graph. Campaigns can
then partition selected Bitcoin peers, delay or lose Bitcoin propagation, and
mine bounded competing branches under a seeded work schedule. Honest Stacks
actors can consequently hold genuinely different burnchain views until the
Bitcoin graph heals and work selection converges.

That topology needs a first-class Stacks-actor-to-Bitcoin-follower binding and
per-follower evidence: height, best-block hash, chainwork, chain tips, peer
graph, header/block receipt timing, and the Stacks node's corresponding burn
view. Effect assertions must prove the requested split occurred on both layers;
recovery must prove every Bitcoin follower selected the expected higher-work
branch and every Stacks actor converged without an unexplained canonical fork.
The harness must also distinguish an expected bounded split during injection
from a failed recovery after reconnection. Because one Bitcoin data directory
per Stacks node materially increases disk and I/O load, this is a separately
preflighted topology profile rather than an invisible expansion of the normal
baseline.

The same correlation must be visible to a human during and after the run: the
dashboard should render the admitted Bitcoin P2P graph, partition cohorts,
best-block hash and chainwork per follower, the bound Stacks actor's burn-view
hash/height, and a common time axis for divergence and convergence. The sealed
evidence bundle must retain those samples and the exact partition/mining
schedule, so a Stacks fork can be attributed to the intended burnchain split
rather than inferred from actor logs.

The local RPC-induced and distributed variants must retain different mechanism
labels so evidence never equates `invalidateblock` with Bitcoin consensus.

Flash-block cadence, epoch/reward-boundary placement, actor faults, and version
skew can later be composed with either variant by `AttacknetRun`. The resolved
schedule and run ledger must preserve their total order; an adaptive agent may
choose from bounded templates but never issue an unrecorded Bitcoin RPC.

## Dashboards

Use three separate human views, each with a distinct job:

- **Headlamp** is the preferred cluster-wide Kubernetes resource viewer.
- **Grafana** explains Stacks actors and network behavior.
- **Chaos Dashboard** displays and controls Chaos Mesh experiments.

The former upstream Kubernetes Dashboard is deprecated and unmaintained;
Headlamp is its Kubernetes SIG UI replacement. For a local cluster, install
Headlamp in-cluster from its official Helm repository and expose it only over a
loopback port-forward. Do not add it while the storage-capacity preflight is
failing, and record the admitted chart/image version in run evidence.

```bash
helm repo add headlamp https://kubernetes-sigs.github.io/headlamp/
helm repo update
helm upgrade --install headlamp headlamp/headlamp \
  --namespace headlamp --create-namespace
kubectl -n headlamp port-forward service/headlamp 8080:80 \
  --address=127.0.0.1
```

Open <http://127.0.0.1:8080>. Headlamp follows Kubernetes authentication and
RBAC; give it a bounded identity appropriate to the viewer rather than mounting
any cluster credential into an actor Pod. The Headlamp desktop/Docker Desktop
extension is an alternative that uses the existing kubeconfig and consumes no
attacknet cluster storage.

The attacknet observability renderer provisions an anonymous, read-only
Grafana instance for each network. By default, `lifecycle.sh apply` also starts
a rediscovering, loopback-only supervisor at <http://127.0.0.1:3000>. The
supervisor survives a Grafana Pod replacement and follows the sole enrolled
Grafana Service; it refuses ambiguity if more than one network is active. Its
state is available through the following command. On macOS, both the Grafana
and Chaos Dashboard supervisors are singleton launchd jobs; on other platforms
they use detached background supervisors. In both cases termination explicitly
stops the owned `kubectl` child before removing its PID record.

```bash
contrib/attacknet/local-access.sh status
```

Set `ATTACKNET_LOCAL_ACCESS_ENABLED=0` before lifecycle apply when unattended
local access is unwanted. The equivalent one-shot manual forward (the default
full-topology name is shown) is:

```bash
kubectl -n hacknet-system port-forward \
  service/attacknet-attacknet-grafana 3000:3000 --address=127.0.0.1
```

Open <http://127.0.0.1:3000>. Actor metrics are self-reported; campaign and
assertion timeline events are orchestrator-authenticated so a modified actor
cannot forge its own recovery. Grafana includes a network command center and a
single-actor drill-down with role, admitted image/version, Kubernetes placement,
role-specific metrics, fault context, and centralized logs. These dashboards
are for human triage; agents should query Prometheus, Loki, and the event journal
directly and retain the raw responses as canonical evidence. See
[`observability/README.md`](observability/README.md) for metric coverage and
trust boundaries.

For a disposable local kind/Docker Desktop cluster, the simplest option is to
disable Chaos Dashboard authentication and keep it reachable only through a
loopback port-forward:

```bash
contrib/attacknet/chaos-dashboard.sh local
```

Open <http://127.0.0.1:2333>. This updates the Helm release value, rolls out
the admitted Dashboard Deployment while preserving the installed chart version,
and starts a rediscovering loopback-only access supervisor. Subsequent
`lifecycle.sh apply` operations ensure that supervisor is running whenever the
Chaos Dashboard Service is installed, without changing its authentication mode.
Inspect or control it with:

```bash
contrib/attacknet/chaos-dashboard.sh status
contrib/attacknet/chaos-dashboard.sh start
contrib/attacknet/chaos-dashboard.sh stop
```

Set `ATTACKNET_CHAOS_DASHBOARD_LOCAL_ACCESS_ENABLED=0` before lifecycle apply
to disable that automatic local-access behavior.
Restore authenticated mode with
`contrib/attacknet/chaos-dashboard.sh secure`. Do not use the local mode for a
shared or remotely reachable cluster.

Authenticated cluster-scoped dashboard access remains available as an
explicit opt-in because it can create and delete any Chaos Mesh experiment in
the cluster:

```bash
kubectl apply -f contrib/attacknet/chaos-dashboard-cluster-access.yaml
kubectl -n chaos-mesh get secret attacknet-chaos-dashboard-token \
  -o jsonpath='{.data.token}' | base64 --decode
kubectl -n chaos-mesh port-forward \
  service/chaos-dashboard 2333:2333 --address=127.0.0.1
```

Open <http://127.0.0.1:2333>, use any descriptive label in the Name field (it
is not a Kubernetes object name; for example `local-cluster-manager`), and
paste the token. The opt-in manifest creates
a legacy service-account token Secret for local development convenience. It
does not expire while this cluster and service account exist, but resetting the
cluster invalidates it. Prefer a bounded projected token when persistence is
not needed:

```bash
kubectl -n chaos-mesh create token attacknet-chaos-dashboard --duration=8h
```

Never mount either credential into an actor Pod. Remove the optional access
objects with:

```bash
kubectl delete -f contrib/attacknet/chaos-dashboard-cluster-access.yaml
```

## Current milestone

The operator and current-main topology renderer are functional. Namespaced
`FaultCampaign` and `AttacknetRun` APIs now provide signer-weight-aware
admission, exact Ready-Pod identity resolution, one-fault-at-a-time execution,
aggregate run budgets, finalizer-backed cleanup, and immutable template
snapshots. Before the first fault, the run controller seals the complete
resolved schedule—including admitted image digests and network identity—in an
owner-bound ConfigMap and executes only those pinned instructions. A separate
restricted run controller owns only these APIs, schedule artifacts, and the
five Chaos Mesh resource kinds plus the separately labelled controller-owned
I/O-pressure Pod; the topology operator has no fault permission.

`AllInjected` is bookkeeping, not proof. Pod faults are proven from admitted
Kubernetes Pod UID/readiness/restart state. Network, DNS, I/O, and wall-clock
campaigns require controlled before/during/after active-probe evidence and
independent recovery proof. Resolved replay requires a fresh network UID with
the same manifest and images. Live proof now covers Pod failure, NetworkChaos,
DNSChaos, and the controller-owned arm64 I/O-pressure mechanism on the complete
topology. A real kind-worker outage carrying 53.33% signer weight also proved
safe quorum pause and automatic recovery. Fresh-UID replay/minimization is now
proven through one removal-only counterfactual with controller-owned
classification and evidence-before-delete. Remaining live gates are
backend-paired assertion negative controls, additional version-skew profiles,
and the final corrected 300+ burn-block soak.

IOChaos has an additional platform gate. Chaos Mesh 2.8.3 bundles an x86-64
`toda` helper whose source also hard-codes x86-64 ptrace registers and emitted
assembly. The chart therefore defaults
`runOperator.ioChaosSupportedArchitectures` to `["x64"]`. Before creating an
IOChaos resource, the controller obtains each exact target Pod's runtime
architecture from its Ready probe and fails `FaultCapabilityUnavailable` when
the installed helper profile does not support it. Do not add `arm64` merely to
bypass this gate; it means a native helper was independently verified. On an
arm64 cluster, use a separately-labelled I/O-pressure scenario or an admitted
x86-64 actor rather than claiming per-syscall IOChaos semantics.

The arm64-compatible alternative is explicitly named `io-pressure` with the
single action `disk-pressure`. It compiles structured worker, byte-count, write
size, severity, duration, and evidence-threshold fields into an internal
`IOPressurePod` descriptor. The run controller resolves exactly one admitted
actor Pod, its node, and its `/data` PVC, then creates a core/v1 Pod using only
the chart-configured trusted image, fixed entrypoint argument layout, restricted
non-root context, and severity-specific CPU/memory caps. Callers cannot provide
an image, command, shell fragment, or raw stress arguments. Its open pressure
files are unlinked before pressure starts so the campaign cannot strand named
payloads on the actor volume. The trusted
FSYNC probe must observe both the configured latency multiplier and added-ms
threshold before the result can become `IOPressureObserved=Proven`, and both
must fall below threshold after deletion for
`IOPressureRecovered=Proven`. Kubernetes-observed pressure-Pod `Running` is
required as injection evidence but is never substituted for that data-plane
evidence. Runtime evidence records the pressure Pod UID, admitted image ID,
node, phase, and claim under
`mechanism=controller-owned-io-pressure-pod`. See
`contrib/helm/hacknet/examples/fault-campaign-io-pressure.json`.

TimeChaos is also architecture-gated. On the local arm64 kind cluster, Chaos
Mesh 2.8.3 reported a successful actor injection without changing the process'
realtime clock, and a separate Node-process canary wedged the daemon before it
could detach. The chart therefore defaults
`runOperator.timeChaosSupportedArchitectures` to `["x64"]`. Extend the list
only after a known process observes the requested offset and recovery and the
Chaos resource cleans up normally; `AllInjected` alone is not capability
evidence.
