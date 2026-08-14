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
mounted into the event bridge and should be supplied only to the trusted
campaign runner, cadence controller, and assertion harness; it is never
mounted into actor Pods. Journal-derived metrics are labelled
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
journal and is never turned into a Prometheus label.

Supported kinds are:

- `run.started`, `run.finished`
- `policy.changed`
- `fault.scheduled`, `fault.injected`, `fault.cleared`
- `invariant.observed`
- `actor.state`
- `recovery.complete`
- `note`

Emit a prepared JSON event without leaking the token in process arguments:

```bash
contrib/attacknet/observability/emit-event.sh \
  http://127.0.0.1:9464 /secure/path/event-token event.json
```

The intended campaign-runner integration is:

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
the event must describe applied policy.

## Durable report

With the event service port-forwarded to `9464`:

```bash
contrib/attacknet/observability/export-report.sh \
  http://127.0.0.1:9464 evidence/run-001
```

This paginates the API into `timeline.jsonl`, generates a self-contained
`timeline.html`, and writes a machine-readable summary next to it. The HTML
uses no CDN and inserts event details with `textContent`, so untrusted actor or
campaign strings cannot inject markup.

## Reproduction and seed

Use the canonical `../run-descriptor.mjs` contract documented in
`../REPRODUCIBILITY.md`. Agent-selected branches use its `choose` command with
stable, namespaced instruction IDs; the result records the choice index and HMAC
digest. The descriptor explicitly discloses distributed nondeterminism and can
derive an integrity-sealed failure-prefix replay without inventing a second run
identity.

## Integration limits of this isolated scaffold

- Lifecycle renders, applies, and waits for these resources independently of
  the actor operator.
- The current campaign runner does not yet emit events. The five integration
  points above are required before fault/recovery panels can be acceptance
  evidence rather than empty scaffolding.
- Kubernetes readiness, restart count, placement, and admitted resource limits
  must be sampled by a trusted runner and posted as `actor.state`. The bridge
  intentionally has no service account and cannot inspect the cluster itself.
- Render-time file discovery must be rerun if actors are added or removed.
- Dashboard queries tolerate metrics absent from older images by rendering an
  empty panel. Mixed-version evidence must record which image supplied each
  series.
- Prometheus retention is seven days. Export the timeline, query snapshots, and
  relevant TSDB data before teardown for longer-lived evidence.

## Tests

```bash
python3 -m unittest discover -s contrib/attacknet/observability -p 'test_*.py'
node --test contrib/attacknet/observability/observability.test.mjs
python3 -m py_compile contrib/attacknet/observability/event_bridge.py
```
