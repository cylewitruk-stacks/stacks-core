# Attacknet observability and replay scaffold

An adversarial network is only useful when a human can see the fault, its
effect, and the recovery. This subtree provides a transport-independent first
version of that instrumentation:

- Prometheus scrapes every rendered Stacks node and signer with stable network,
  actor, and role labels.
- Prometheus also scrapes the trusted run controller for bounded
  `FaultCampaign`/`AttacknetRun` phase, exact-target, assertion-outcome,
  schedule-digest, and budget-use gauges.
- Grafana Alloy tails each actor container through the Kubernetes logs API and
  sends raw stdout/stderr to a single-binary Loki instance with seven-day
  retention and a dedicated PVC.
- Grafana is provisioned with a human-facing network/fault/recovery dashboard.
- An authenticated event bridge durably journals campaign, cadence, invariant,
  actor-state, and recovery observations and projects their bounded state into
  Prometheus.
- A standalone HTML report turns the journal into a filterable incident
  timeline that remains useful after the cluster is gone.
- The canonical integrity-sealed run descriptor records the manifest, admitted
  state, ordered actions, source state, images, and deterministic experiment
  seed; this subtree does not define a second replay format.

Nothing here depends on libp2p metrics. The dashboard deliberately uses the
legacy P2P neighbor gauges exported by current `main`.

## Evidence trust boundary

Stacks node and signer Prometheus endpoints are labelled
`evidence_source="actor_self_reported"`. A malicious image can lie, omit
metrics, or serve synthetic values, so these series are evidence but not an
authority. Scrapes have sample, label, body-size, and timeout limits so a
malicious metrics endpoint cannot trivially exhaust the monitoring plane, and
actor-supplied sample timestamps are ignored in favour of scrape time.

Raw log **content** has the same limitation, more strongly: a malicious actor
controls every byte that it writes to stdout/stderr. Alloy therefore performs
no JSON, logfmt, or other content-derived label extraction. The immutable
stream identity is attached from Kubernetes discovery and includes network,
logical actor, role, namespace, Pod name and UID, node, container, requested
image, and resolved runtime container ID. Every stream is additionally marked
`log_content_trust="actor_self_reported_untrusted"` and
`metadata_trust="kubernetes_collector_attached"`. A log line claiming to be a
different actor is just untrusted text; it cannot alter those indexed labels.

The exact resolved image digest remains in the orchestrator-observed
`actor.state` event because Kubernetes service discovery exposes the requested
container image and runtime container ID, but not the Pod status `imageID` as a
target label. Correlate `resolved_container_id` in Loki with the admitted Pod
snapshot/actor-state journal when image provenance matters.

The journal accepts writes only with a 256-bit bearer token. That token is
mounted only into the trusted event bridge; campaign, cadence, and assertion
commands send prepared JSON through `kubectl exec`, and the bridge reads the
token and posts to its own loopback interface. The credential therefore never
enters a host process argument, evidence file, or actor Pod. Journal-derived metrics are labelled
`evidence_source="orchestrator_observed"`. The bridge re-reads its projected
Secret on every write, so token rotation does not require a restart.

Metrics and event history are read-only and unauthenticated inside the test
namespace. The generated Services are ClusterIP-only. Do not expose them
outside a local or access-controlled attacknet without adding a read-side
authentication proxy.

## Render and deploy

Render after the topology manifest exists:

```bash
node contrib/attacknet/observability/render.mjs \
  contrib/attacknet/generated/full/manifest.json \
  --output=contrib/attacknet/generated/full/observability.json

kubectl apply -f contrib/attacknet/generated/full/observability.json
kubectl -n hacknet-system rollout status deployment/attacknet-attacknet-events
kubectl -n hacknet-system rollout status deployment/attacknet-attacknet-prometheus
kubectl -n hacknet-system rollout status statefulset/attacknet-attacknet-loki
kubectl -n hacknet-system rollout status daemonset/attacknet-attacknet-alloy
kubectl -n hacknet-system rollout status deployment/attacknet-attacknet-grafana
```

The standard Helm release exposes these metrics at `hacknet-run:8080`. If the
release name or service differs, pass the admitted DNS endpoint explicitly as
`--run-operator-target=NAME:PORT`; the renderer rejects arbitrary/newline
targets rather than interpolating them into Prometheus configuration.

The generated file and adjacent `event-token` contain the writer credential and
are mode `0600`; treat them as runtime artifacts and do not commit them or
include them in evidence. Supplying `--event-token=...` makes token management
external and repeatable. Normal `lifecycle.sh apply` renders and deploys this
stack by default; set `ATTACKNET_OBSERVABILITY_ENABLED=0` only for a deliberately
minimal diagnostic run.

Before applying any observability or protocol workload, lifecycle runs
`storage-preflight.sh`. It records kubelet stats-summary values for the root and
image filesystem of every node and fails below 2 GiB free by default. This is
deliberately stronger than the Kubernetes `DiskPressure` condition: the local
three-node Docker Desktop cluster was observed with `availableBytes=0` on all
nodes while all three still reported `DiskPressure=False`, allowing Loki,
Alloy, and even a replacement Grafana Pod to be admitted and crash with
`ENOSPC`. Tune the floor with `ATTACKNET_OBSERVABILITY_MIN_FREE_BYTES`; disabling
the check requires both `ATTACKNET_OBSERVABILITY_STORAGE_PREFLIGHT=0` and the
conspicuous `ATTACKNET_NEGATIVE_CONTROL=1`. The resulting
`observability-storage-preflight.json` and pass/fail/skipped ledger assertion
preserve the exact decision as run evidence.

Open the dashboard locally:

```bash
kubectl -n hacknet-system port-forward service/attacknet-attacknet-grafana 3000:3000
```

Grafana provisions two complementary human-diagnostic views:

- **Network, Faults, and Recovery** is the command center. It shows trusted
  actor inventory/placement/readiness beside self-reported chain cohorts,
  signer participation, legacy P2P connectivity, the network block pipeline,
  fault/invariant timelines, sealed run state and budget use, trusted effect
  and recovery outcomes, warning/error rates, and centralized raw logs.
  Network, role, and actor variables narrow every relevant panel.
- **Actor Drill-down** follows one actor through its admitted image and
  Kubernetes node, readiness/restarts, active faults, chain state, P2P/RPC
  traffic, block pipeline, node workload, miner state, signer state and
  latency, and raw logs. Panels that do not apply to the actor's role are
  intentionally empty instead of fabricating zeroes. Links in both dashboards
  preserve the selected time range and variables.

The actor dashboard covers every metric family exported by the current-main
Stacks node and signer monitoring modules. Counters are rendered as rates,
histograms as quantiles in their native seconds, boolean lifecycle gauges as
states, cohort values as tables or distributions, and workload snapshots as
bar gauges. Panels group related families by diagnostic question rather than
placing one stat tile per metric; this keeps root-cause flow readable. The
admitted image tag is the best available version identity. Exact image digest
comes from the trusted actor-state observation. Current main does not export a
separate build/version information metric.

The dashboards also contain the complete 22-family Workstream M observation
contract: signer readiness, registration, state freshness, companion drift
inputs, pending validation backlog, exact global-state support, bounded policy
and validation outcomes, response-delivery results, legacy coordinator rounds
and response weight, proposal-to-first-response and proposal-to-threshold
latency, and Nakamoto transport boundaries. These panels intentionally show no data when the selected actor
image does not contain the corresponding instrumentation. An R1 run must record
each signal as `merged`, `attacknet-patch`, or `unavailable` for the exact
admitted image; a blank panel must never be silently interpreted as a healthy
zero. Burn-chain and Stacks-chain cohort progress are separate panels with
independent vertical scales because Nakamoto block cadence is much faster than
Bitcoin burn-block cadence.

Each actor scrape target carries only the render-time aggregate
`instrumentation_profile`, `instrumentation_provenance`, `requested_image`,
and `event_dispatch_mode` declarations. Exact family metadata is projected by
the orchestrator bridge as the bounded
`attacknet_instrumentation_family_provenance{attacknet_actor,attacknet_role,family,provenance}`
metric. This avoids copying 22 target labels onto every actor-exported series.
The dashboard capability tables surface both forms so an `unavailable` profile
cannot be read as a healthy zero. `mixed` means applicable families have more
than one of the three exact provenances. The per-family metric comes from a
digest-bound qualification plan for the exact rendered manifest, rather than
being inferred from that aggregate. The qualified capability manifest joins the build
source audit, Pod UID, runtime image identity, admitted config, and retained
runtime metric-family snapshot. Prometheus rules alert
on correlated signer participation loss, frozen signer state, validation
unavailability, and Nakamoto propagation failure. A separate two-minute
`AttacknetInstrumentationProvenanceExporterAbsent` alert detects loss of the
central provenance inventory whenever the Prometheus configuration contains at
least one node or signer scrape target. The non-empty-topology guard prevents a
deliberately actor-free render from being reported as an exporter failure;
actor unreachability remains the responsibility of the scrape-target alerts.
`AttacknetActorMetricsUnreachable` makes that boundary explicit by warning
after an enrolled node or signer target has remained `up == 0` for 30 seconds;
Pod readiness alone is not accepted as evidence that telemetry is reachable.
Family-presence rules use the exact exporter name recorded by the inventory:
Rust counters retain their declared base name in this metrics endpoint, while
histogram presence is checked through the generated `_count` child series.
The two-minute `for` interval suppresses false startup noise before the first
scrape. With the configured five-second scrape and evaluation intervals,
ordinary metric disappearance or scrape failure normally fires after roughly
two minutes plus one cycle because Prometheus records stale markers; the
five-minute lookback is only a fallback when no stale marker is available.
Each family-absence alert
selects only actors declaring that family `merged` or `attacknet-patch`; a
mixed actor cannot generate a false absence alert for an intentionally
unavailable family. The capability table must still be checked before
interpreting alert silence as health.

The **Explore actor logs** links open Grafana Explore for longer LogQL queries.
The dashboards are optimized for humans. Automated agents should query
Prometheus, Loki, and the authenticated journal API directly and retain the raw
results in the evidence bundle; screenshots and reduced Grafana values are not
canonical evidence.

Prometheus, Loki, and the event journal use PVCs. Loki requests 5 GiB, enforces
seven-day retention through its singleton compactor, limits ingestion/query
sizes, and has bounded CPU/memory. Time retention is not a substitute for disk
monitoring: filesystem Loki cannot evict based on free space, so extremely
noisy malicious actors can fill the claim before seven days and should make the
run fail visibly. Delete observability PVCs explicitly when a run is meant to
start with clean evidence; they are intentionally not owned by the
`StacksNetwork` CR in this isolated scaffold.

## Event contract

Every event has the following stable envelope:

```json
{
  "schemaVersion": 1,
  "eventId": "run-id/campaign-id/injected/miner-2",
  "instructionId": "seed-choice-0042",
  "runId": "attacknet-40c95f080c13d45cd47f",
  "network": "attacknet",
  "kind": "fault.injected",
  "phase": "fault-active",
  "campaign": "miner-delay",
  "actor": "miner-2",
  "role": "miner",
  "faultType": "network",
  "occurredAt": "2026-08-15T01:02:03.456Z",
  "details": {"delayMs": 500, "chaosResource": "NetworkChaos/miner-delay"}
}
```

`schemaVersion`, `sequence`, and `recordedAt` are assigned by the bridge.
`eventId` makes retried writes idempotent. Kind and phase are bounded enums and
all metric-bearing labels are length-limited. Arbitrary detail stays in the
journal and is never turned into a Prometheus label. Composed event IDs longer
than the label bound retain a readable prefix plus a deterministic SHA-256
suffix, preserving idempotency without rejecting legal long campaign names.

Supported kinds are:

- `run.started`, `run.finished`
- `policy.changed`
- `fault.scheduled`, `fault.injected`, `fault.cleared`
- `invariant.observed`
- `actor.state`
- `recovery.complete`
- `incident.opened`
- `note`

Lifecycle phases (`bootstrap`, `capture`, and `teardown`) and campaign phases
(`injecting`, `fault-active`, `recovering`, `verification`, and `incident`) are
separate bounded values so the durable timeline shows where an observation was
made without turning arbitrary strings into metric labels.

For a standalone port-forwarded bridge, emit a prepared JSON event without
leaking the token in process arguments:

```bash
contrib/attacknet/observability/emit-event.sh \
  http://127.0.0.1:9464 /secure/path/event-token event.json
```

The active Kubernetes harness uses `record-event.sh`. It fixes network and run
identity from the trusted orchestration context before processing caller
fields. `ATTACKNET_RUN_ID` wins when explicitly set; otherwise the helper reads
`run-id` from the lifecycle-owned `<network>-run-context` ConfigMap. A missing
identity is an error rather than an unattributed event:

```bash
KUBE_NETWORK=attacknet \
  contrib/attacknet/observability/record-event.sh \
  --kind=note --phase=baseline \
  '--details={"message":"human annotation"}'
```

Campaign integration follows these rules:

1. emit `fault.scheduled` after selector compilation, including signer-weight
   impact and the deterministic instruction ID;
2. emit one `fault.injected` per selected actor only after Chaos Mesh reports
   `AllInjected`;
3. emit one `fault.cleared` per selected actor after Chaos Mesh deletion is
   observed (the actor label must match its corresponding injected event);
4. emit every verification result as `invariant.observed`;
5. emit `recovery.complete` with the measured clear-to-pass duration.

The event bridge accepts `policy.changed` observations from trusted
orchestration extensions. Such an observation must describe an applied,
process-acknowledged policy rather than requested state. The supported
`BurnchainPolicy` controller exposes acknowledged clock generation, mode, and
cadence through its status and bounded `attacknet_burnchain_clock_*` metrics;
it does not depend on a journal write to apply policy.

`record-verification.sh RESULT SCOPE PHASE` translates stable
`verify.sh` JSON into separate bounded observations for burn and Stacks drift,
canonical-tip agreement, authenticated connectivity, minimum height, and both
progress dimensions. It deliberately excludes actor rows from Prometheus-bound
detail while those rows remain in the original evidence file.

`record-actor-states.sh PHASE` reads admitted Pod status with the orchestrator's
Kubernetes identity and records readiness, restart counts, placement, Pod UID,
and resolved container image IDs. These observations remain trustworthy even
when an adversarial actor serves fabricated application metrics.

## Durable report

With the event service port-forwarded to `9464`, the standalone exporter is:

```bash
contrib/attacknet/observability/export-report.sh \
  http://127.0.0.1:9464 evidence/run-001
```

This paginates the API into `timeline.jsonl`, generates a self-contained
`timeline.html`, and writes a machine-readable summary next to it. The HTML
uses no CDN and inserts event details with `textContent`, so untrusted actor or
campaign strings cannot inject markup.

The lifecycle and incident paths use the Kubernetes-native equivalent, which
requires no port-forward and never reads the writer token:

```bash
KUBE_NETWORK=attacknet \
  contrib/attacknet/observability/export-kubernetes-report.sh \
  evidence/run-001/timeline attacknet-run-001
```

It retains raw API pages, the complete journal JSONL, a run-filtered JSONL,
HTML/JSON summary, and export metadata. Lifecycle teardown exports this bundle
before deleting the journal PVC; incident capture does the same while the
network is deliberately left running.

## Reproduction and seed

Use the controller-owned `AttacknetRun` contract documented in
[`../docs/concepts/reproducibility.md`](../docs/concepts/reproducibility.md).
The resolved schedule, trigger receipts, admitted inventory, child campaigns,
and terminal classification are the reproducible record. The seed is an input,
not a substitute for those observations. Replay and minimization use fresh
network identities and controller-validated source schedule digests.

## Integration limits

- Lifecycle renders, applies, and waits for these resources independently of
  the actor operator. Run identity lives in a control-plane ConfigMap so later
  orchestration processes share attribution without sharing credentials.
- Campaign, policy, assertion, recovery, run-boundary, incident, and teardown
  paths use the trusted writer/export helpers. Event export is evidence; it is
  not a substitute for the integrity-sealed canonical run descriptor.
- Kubernetes readiness, restart count, placement, and resolved image state are
  sampled by the trusted runner as `actor.state`. The bridge intentionally has
  no service account and cannot inspect the cluster itself; admitted resource
  limits remain preserved in lifecycle evidence rather than metric labels.
- Render-time file discovery must be rerun if actors are added or removed.
- Dashboard queries tolerate metrics absent from older images by rendering an
  empty panel. Mixed-version evidence must record which image supplied each
  series.
- Alloy runs as a node-local DaemonSet but uses `loki.source.kubernetes` and a
  namespace-scoped Role to tail Pod logs through the Kubernetes API. This avoids
  privileged/root containers and `/var/log/pods` host mounts, works with
  Docker Desktop kind's nested container runtime, and remains compatible with
  Restricted Pod Security. The tradeoff is extra API-server/kubelet traffic;
  discovery is restricted to actor Pods on the collector's own node.
- Collector positions live in the Alloy Pod's `emptyDir`. Loki normally
  deduplicates replayed Kubernetes timestamps after a collector restart, but a
  short gap is still possible if kubelet has already rotated the source log.
  Incident capture therefore continues to retain bounded `kubectl logs`
  snapshots alongside centralized Loki evidence.
- A host-file tailer could reduce API load, but on kind it would require
  runtime-specific paths inside the Docker-hosted Kubernetes nodes and elevated
  Pod Security permissions. That is intentionally not the default; add it only
  as an explicit cluster profile with a live compatibility test.
- Prometheus and Loki retention are seven days. Export the timeline, query
  snapshots, raw incident logs, and relevant time-series data before teardown
  for longer-lived evidence.

`export-loki.sh` performs that log export for normal teardown, lifecycle
capture, and incident capture. It queries the exact network label over the
run's recorded time range, paginates with an inclusive nanosecond cursor,
de-duplicates only identical labelled entries at the page boundary, and writes
the selector, range, every page boundary, source Kubernetes objects, and file
digests alongside compressed `logs.jsonl.gz`. If a page cannot advance—such as more than one
page of entries sharing one timestamp—or the bounded page count is exceeded,
the export is marked incomplete and teardown stops before deleting Loki's PVC.
`summarize-loki-export.mjs` then streams the compressed JSONL without loading
the corpus into memory and emits bounded actor/level/error-family counts plus
an explicit suspicious-runtime family list. The summary is an index for human
and agent triage; the digest-verified JSONL remains the canonical evidence.

## Tests

```bash
python3 -m unittest discover -s contrib/attacknet/observability -p 'test_*.py'
node --test contrib/attacknet/observability/*.test.mjs
python3 -m py_compile contrib/attacknet/observability/event_bridge.py
bash -n contrib/attacknet/observability/*.sh
```
