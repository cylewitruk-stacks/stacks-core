# Deterministic AttacknetRun scheduling

The run controller resolves and seals an `AttacknetRun` before creating its
first child `FaultCampaign`. The schedule is controller-owned JSON persisted in
an owner-bound ConfigMap and referenced from status by URI and digest.

## Inputs

An `AttacknetRun` declares:

- an opaque seed and supported decision algorithm;
- a finite catalog of `FaultCampaign` templates;
- ordered executions and explicit triggers;
- aggregate campaign, time, concurrency, signer, miner, and burnchain budgets;
- finite baseline, active-fault, and recovery protocol assertions;
- stop and attribution policies; and
- mutually exclusive replay, resume, or minimization intent.

Templates are inert while marked as templates. Resolution snapshots each
template's UID, generation, and content digest, the admitted network UID and
inventory digest, exact image constraints, and the complete budget set.

## Trigger model

Executions may trigger after run start, after another execution reaches a
controller-owned milestone, at burn or Stacks height, or from a trusted
observation. A trigger receipt records the source and observed value. Missing
or stale observations remain Pending; they are not inferred from actor logs.

Concurrent stages are admitted as an aggregate. The controller evaluates the
union of active targets and mutations against safety budgets before injection.
Separate campaigns share the namespace mutation lease and therefore do not
silently bypass aggregate admission.

## Protocol assertion gates

`baselineAssertions`, `duringAssertions`, and `recoveryAssertions` use a
finite typed vocabulary: burnchain or Stacks progress, cohort agreement,
signer registration, signer-state freshness, proposal-outcome visibility, and
telemetry completeness. Arbitrary PromQL and actor-defined predicates are not
accepted.

Each gate accepts at most 32 assertions, 64 actors per assertion, and 256
actor references in total. These bounds keep source-bound status evidence well
below Kubernetes object-size limits.

The run controller collects actor metrics directly through operator-owned
Services between two uncached admitted-inventory reads. Values remain
`actor_self_reported`; the endpoint and immutable Pod/image binding are
orchestrator-verified. Each durable result records the network UID, inventory
digest, exact actor sources, and observation time.

Heights and counters must be finite, non-negative exact integers, and signer
registration must be exactly zero or one. Non-finite, negative, fractional, or
otherwise lossy values are unavailable evidence; a finite future signer-state
timestamp is an explicit freshness violation rather than a fresh observation.

An observed out-of-bound value is `Violated` and fails the run. Missing,
stale, ambiguous, replaced, or unreachable evidence remains `Pending` until
the assertion deadline, then becomes `Inconclusive`. It can never satisfy a
gate. Baseline and recovery Pending states block progress. During assertions
are sampled only while a fault mutation is active; they may remain Pending
while that window is open, but a missed or incomplete window closes
`Inconclusive` when the campaign ends. Every successful terminal path,
including `onSuccess: Stop`, passes the recovery gate first. A successful
concurrent campaign stops new scheduling; already-running campaigns complete
their bounded recovery before that gate is sampled.

## Persistence and restart

The schedule store refuses adoption of a ConfigMap with changed ownership,
run identity, input digests, or contents. Reconciliation resumes from
controller status and the immutable schedule; it does not regenerate choices
after restart. Child resources carry the execution and schedule identities.

## Replay and minimization

Replay requires a fresh network UID, the source run and schedule digest, equal
budgets, unchanged template identities, and the same admitted images.
Minimization uses the same boundary plus one removal-only candidate digest.
See [`reproducibility.md`](reproducibility.md) and
[`minimization.md`](minimization.md).

## Operator workflow

Author YAML, then use the typed client:

```bash
attacknet validate --file contrib/helm/hacknet/examples/attacknet-run.yaml
attacknet submit --namespace hacknet-system \
  --file contrib/helm/hacknet/examples/attacknet-run.yaml
attacknet watch --namespace hacknet-system AttacknetRun bounded-mixed-faults
```

The public contract is `testing.stacks.org/v1beta1` plus controller status.
The retired Node scheduler remains available only at its reviewed Git revision;
it is not a second implementation in the current product tree.
