# Attacknet evidence and qualification

Attacknet treats evidence as part of the product. A campaign is not successful
because a fault resource exists or a dashboard looks healthy; its requested
effect, safety invariants, recovery, and provenance must be retained.

## Trust model

- Actor metrics and logs are self-reported. A modified actor can lie, omit
  data, or stop reporting.
- Kubernetes state, admitted image identity, controller decisions, trigger
  receipts, and terminal status are orchestrator-observed.
- Actor Pods have no Kubernetes credentials and cannot forge controller status.

Strong conclusions correlate independent sources. Missing actor telemetry is
never treated as zero, and `AllInjected` is not proof of a data-plane effect.
See [`instrumentation.md`](../reference/instrumentation.md) and
[`failure-attribution.md`](failure-attribution.md).

## Capture a live run

Capture evidence before teardown. The typed client supports a bounded resource
snapshot and a larger admitted-identity incident bundle:

```bash
attacknet evidence snapshot --namespace hacknet-system \
  --output evidence/run.json AttacknetRun bounded-mixed-faults

attacknet evidence incident --namespace hacknet-system \
  --output evidence/bounded-mixed-faults attacknet
```

The incident bundle binds bounded Kubernetes log tails to exact admitted Pod names and UIDs, captures
bounded owned resources and Events, records per-artifact digests, and reports
omissions explicitly. It is deliberately not the complete retained log
corpus.

For normal network teardown, bind the retained run and use the evidence barrier
instead of deleting the `StacksNetwork` directly:

```bash
attacknet teardown --namespace hacknet-system \
  --output evidence/attacknet-teardown \
  --run bounded-mixed-faults attacknet
```

The run form derives the interval start from controller-observed status and
includes the complete `AttacknetRun` object. For a network without a run, use
`--start "$RUN_START_RFC3339"` instead. `teardown` first captures the incident bundle, then discovers exactly one
ready identity-labelled Loki Pod through Kubernetes, exports the full selected
interval with bounded forward pagination, and records Loki build/source
identity plus artifact digests. The CLI rechecks the exact Service and Pod UID
before the temporary export is made final and binds the source object into the
teardown manifest. The teardown manifest and nested incident manifest bind the
retained artifacts by digest; missing, truncated, or digest-mismatched data
cannot authorize deletion. Release qualification may add a recursive inventory
around this product evidence. Only a complete final export permits
foreground deletion. A source outage, pagination stall, partial file, capture
omission, or export error preserves the `StacksNetwork` and its PVCs for
forensics. The interval ends after the incident snapshot unless `--end` is
explicitly supplied.

The exported actor values and log bodies remain self-reported or untrusted.
Kubernetes stream labels, admitted identities, controller status, and export
metadata are orchestrator-observed.

Grafana correlates each protocol assertion with its exact admitted source Pod,
UID, runtime image, Service, evidence class, and observation timestamp. These
views aid diagnosis; the controller status and sealed evidence remain the
release oracle.

Failed or inconclusive campaigns must preserve their network until evidence
and attribution are complete.

## Required identities

An attributable run retains:

- source revision and local patch identity;
- qualified-tree-bound build and per-node image-admission receipts;
- requested topology plus network UID and observed generation;
- admitted actor, Pod, StatefulSet, and runtime image identities;
- campaign-template identities and the sealed schedule digest;
- seed, decision algorithm, safety budgets, and trigger receipts;
- fault effect, rollback, recovery, and cleanup results;
- metrics, logs, Kubernetes state, Events, and incident artifacts.

Replay and minimization use a fresh network UID. The source network is never
reused as its own counterfactual. See
[`reproducibility.md`](../concepts/reproducibility.md) and
[`run-scheduling.md`](../concepts/run-scheduling.md).

## Fault evidence

| Fault | Required effect evidence |
| --- | --- |
| Pod disruption | Exact target Pod UID changes readiness, restart, or existence as requested |
| Network/DNS | Controlled before/during/after probes observe impairment and recovery |
| `io-pressure` | Trusted FSYNC probe crosses both configured latency thresholds, then recovers |
| `clock-skew` | Selected process clock shifts relative to a control actor, then returns |

A campaign ends `Inconclusive` when injection is reported but trusted effect
evidence is missing. Cleanup must prove recovery and resource absence. Forced
deletion may bound amplification, but it does not convert a failed campaign to
success.

## Chain and signer invariants

Baseline and recovery evidence should cover Bitcoin and Stacks progress over a
cadence-aware window, cohort agreement, exact actor readiness, signer
registration and freshness when instrumented, unexpected Pod disruption, and
counter resets. Burn and Stacks heights are separate signals because their
cadences differ.

A terminal run is not a cleanup receipt. Consumers must also require
`status.cleanup.required=true` and `status.cleanup.completed=true` before
archiving or tearing down the experiment.

## Release baseline and review packets

[`../../release/baseline-v1.json`](../../release/baseline-v1.json) is the
Release 1 product claim. Validate its structure with:

```bash
node contrib/attacknet/release/baseline.mjs validate \
  contrib/attacknet/release/baseline-v1.json
```

Release amendments use the digest-bound review contract documented in
[`../../release/PHASE-REVIEWS.md`](../../release/PHASE-REVIEWS.md). Passing
tests without a complete, dual-approved packet is not phase completion.

Development findings belong in GitHub or an external ledger. A limitation that
constrains an advertised capability must also appear in the release baseline.
