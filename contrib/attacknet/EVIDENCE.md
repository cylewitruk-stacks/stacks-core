# Attacknet evidence and qualification

Attacknet treats evidence as part of the product. A campaign is not successful
because a fault resource existed or a dashboard looked healthy; its requested
effect, safety invariants, recovery, and provenance must be independently
observable and retained.

## Trust model

Evidence has two principal sources:

- Actor metrics and logs are self-reported. A deliberately modified actor can
  lie, omit data, or stop reporting.
- Kubernetes state, admitted image identity, campaign decisions, assertion
  results, and timeline events are orchestrator-observed. Actor Pods have no
  Kubernetes credentials and cannot forge these records through the API.

Strong conclusions correlate both sources. A missing actor series is never
treated as a zero, and `AllInjected` is never substituted for proof of a
data-plane effect.

See [`INSTRUMENTATION.md`](INSTRUMENTATION.md) for metric-family provenance and
[`FAILURE-ATTRIBUTION.md`](FAILURE-ATTRIBUTION.md) for incident classification.

## Capture a live run

Use the public facade to capture Kubernetes actor state, metrics, logs,
runtime identity, and the trusted timeline:

```bash
contrib/attacknet/attacknet evidence capture \
  contrib/attacknet/evidence/RUN/snapshot \
  contrib/attacknet/generated/full/manifest.json
```

Capture before teardown. Failed campaigns preserve their network and create an
incident bundle rather than silently rebuilding the system under test.

For a longer bounded collection window, maintainers can use:

```bash
contrib/attacknet/evidence-harness.sh \
  contrib/attacknet/evidence/RUN/behavior \
  contrib/attacknet/generated/full/manifest.json 1h
```

## Run identity and reproducibility

Every accepted run binds:

- source revision and dirty-patch digest;
- topology manifest and network UID;
- admitted Pod UIDs and image IDs;
- build and image provenance;
- seed and deterministic decision algorithm;
- resolved campaign schedule and safety budgets;
- ordered decisions, observations, assertions, and cleanup;
- raw metrics, logs, Kubernetes state, and incident artifacts.

The run controller seals its complete schedule before the first mutation. A
replay must use a fresh network UID with the same manifest and image digests;
the source system is never reused as its own counterfactual.

See [`REPRODUCIBILITY.md`](REPRODUCIBILITY.md) and
[`ATTACKNET-RUN-SCHEDULING.md`](ATTACKNET-RUN-SCHEDULING.md) for the descriptor,
seed, replay, and scheduling contracts.

## Fault evidence

Different fault mechanisms require different proof:

| Fault | Required effect evidence |
| --- | --- |
| Pod disruption | Exact target Pod UID changes readiness, restart, or existence as requested |
| Network/DNS | Controlled before/during/after probes observe the requested impairment and recovery |
| Native IOChaos/TimeChaos | Known target process observes the requested effect and clean detachment on a supported architecture |
| `io-pressure` | Trusted FSYNC probe crosses both latency multiplier and added-milliseconds thresholds, then recovers below both |
| `clock-skew` | Selected Stacks process clock shifts relative to an independent control actor, then returns |

A campaign ends `Inconclusive` when the mechanism reports injection but trusted
effect evidence is missing. Cleanup must prove `AllRecovered` where applicable,
resource deletion, and subsequent resource absence. Forced deletion safely
removes amplification but remains a failed campaign.

## Chain and signer invariants

Baseline and recovery checks include:

- Bitcoin and Stacks progress over a cadence-aware window;
- burn-height and Stacks-height cohort agreement;
- actor readiness and exact enrolled workload coverage;
- signer registration, state freshness, and node drift where instrumentation is
  available;
- no unexpected Pod disruption;
- no unexplained metric counter reset during a measured window;
- terminal `AttacknetRun` status consistent with its campaign results.

A terminal run outcome is not a cleanup receipt. Consumers must also require
`status.cleanup.required=true` and `status.cleanup.completed=true` before they
archive evidence or tear down an experiment. The run controller continues to
reconcile terminal runs until every owned campaign has proved mutation cleanup
and target recovery.

The verifier derives actor inventories from `manifest.json`; it does not assume
a fixed signer count.

## Measured soak

The measured runner pauses cadence, samples an exact starting cohort, derives
the Bitcoin target from that observation, runs the interval and optional fault
list, pauses again, and verifies the terminal cohort:

```bash
KUBE_NAMESPACE=hacknet-system \
KUBE_NETWORK=attacknet-final-soak \
contrib/attacknet/soak-runner.sh \
  contrib/attacknet/evidence/RUN/verified-soak-300 \
  contrib/attacknet/generated/manifest.json \
  300 \
  contrib/attacknet/evidence/RUN/verified-fault-run.json
```

`result.json` can pass only when:

- the observed Bitcoin-height delta meets the requested interval;
- both paused boundary cohorts agree exactly with Bitcoin and each other;
- intermediate cohort samples pass;
- Pod disruption is either an admitted active target or a run failure;
- the supplied `AttacknetRun` terminates `Passed`; and
- signer counter deltas are non-negative across the measured window.

A cumulative rejection from before the starting boundary cannot therefore be
attributed to the soak.

## Release baseline

[`release/baseline-v1.json`](release/baseline-v1.json) is the Release 1 product
claim, not a development backlog. It records the accepted source and patch
identity, 28-actor/31-workload topology, burn 503 to 803 and Stacks 302 to 597
window, evidence digests, supported capabilities, rejected arm64-native
helpers, unfinished product work, and external deferrals.

Validate its tracked structure offline:

```bash
node contrib/attacknet/release/baseline.mjs validate \
  contrib/attacknet/release/baseline-v1.json
```

When its separately retained evidence archive is available:

```bash
node contrib/attacknet/release/baseline.mjs validate \
  contrib/attacknet/release/baseline-v1.json \
  --verify-evidence --root=.
```

Development findings belong in GitHub issues or a separate external ledger.
Any finding that constrains an advertised capability must be represented in
the release baseline as `not-done`, `deferred`, or `capability-rejected` before
leaving that backlog.

## Review packets

Productization phases use the digest-bound reduced/full packet contract in
[`release/PHASE-REVIEWS.md`](release/PHASE-REVIEWS.md). A phase is complete
only when both required reviewers approve the same packet digest, source and
evidence inventories resolve, and the phase gate reports approval for the
declared release scope.

Passing tests without a complete review packet is not phase completion.

## Failure minimization

Attacknet supports bounded replay and removal-only delta debugging on fresh
networks. Minimization establishes one-minimality only within its declared
counterfactual domain; it does not establish causality.

An LLM may prioritize likely contributors, but every retained/rejected
candidate must remain machine-recorded and behaviorally tested. See
[`DDMIN-EXECUTION.md`](DDMIN-EXECUTION.md) for the execution contract.
