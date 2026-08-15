# Attacknet observability and replay scaffold

An adversarial network is only useful when a human can see the fault, its
effect, and the recovery. This subtree provides a transport-independent first
version of that instrumentation:

- Prometheus scrapes every rendered Stacks node and signer with stable network,
  actor, and role labels.
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
kubectl -n hacknet-system rollout status deployment/attacknet-attacknet-grafana
```

The generated file and adjacent `event-token` contain the writer credential and
are mode `0600`; treat them as runtime artifacts and do not commit them or
include them in evidence. Supplying `--event-token=...` makes token management
external and repeatable. Normal `lifecycle.sh apply` renders and deploys this
stack by default; set `ATTACKNET_OBSERVABILITY_ENABLED=0` only for a deliberately
minimal diagnostic run.

Open the dashboard locally:

```bash
kubectl -n hacknet-system port-forward service/attacknet-attacknet-grafana 3000:3000
```

The overview shows chain-height cohorts, scrape reachability, legacy P2P
neighbors, signer proposal/vote rates and p95 response latency, current faults,
failed invariants, recovery durations, and warning/error rates. Actor filtering
provides a drilldown without changing the dashboard.

Prometheus and the event journal use PVCs. Delete their PVCs explicitly when a
run is meant to start with clean evidence; they are intentionally not owned by
the `StacksNetwork` CR in this isolated scaffold.

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

The cadence controller emits `policy.changed` after the ConfigMap generation
is observed by the external Bitcoin clock. Requested policy is insufficient:
the event describes the applied and process-acknowledged policy. A journal
failure after the policy mutation warns without encouraging a dangerous retry;
set `ATTACKNET_EVENT_STRICT=1` when evidence completeness should terminate the
caller.

`record-verification.sh RESULT SCOPE PHASE` translates backend-neutral
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

Use the canonical `../run-descriptor.mjs` contract documented in
`../REPRODUCIBILITY.md`. Agent-selected branches use its `choose` command with
stable, namespaced instruction IDs; the result records the choice index and HMAC
digest. The descriptor explicitly discloses distributed nondeterminism and can
derive an integrity-sealed failure-prefix replay without inventing a second run
identity.

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
- Prometheus retention is seven days. Export the timeline, query snapshots, and
  relevant TSDB data before teardown for longer-lived evidence.

## Tests

```bash
python3 -m unittest discover -s contrib/attacknet/observability -p 'test_*.py'
node --test contrib/attacknet/observability/*.test.mjs
python3 -m py_compile contrib/attacknet/observability/event_bridge.py
bash -n contrib/attacknet/observability/*.sh
```
