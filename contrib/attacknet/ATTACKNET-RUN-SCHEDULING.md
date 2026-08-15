# Deterministic AttacknetRun scheduling and minimization

`attacknet-run-schedule.mjs` is the offline instruction resolver for an
`AttacknetRun`. It does not contact Kubernetes and does not execute a fault.
Its output is intended to be persisted before the run controller creates its
first child `FaultCampaign`.

## Resolution contract

Call:

```js
resolveAttacknetSchedule(run, {
  network: {uid, generation},
  manifest,
  campaigns,
  images,
  decisionSpaces,
});
```

`run` is an `AttacknetRun` object (or its spec). `campaigns` contains the
actual `FaultCampaign` templates referenced by `spec.campaignCatalog`, with
their server-assigned UID and generation. `images` must contain admitted,
digest-qualified image references. The result:

- preserves enabled sequence order and canonicalizes the finite catalog;
- verifies every optional expected source UID, generation, and spec digest;
- uses the shared `seededChoice()` HMAC contract for optional finite campaign,
  target-set, and parameter-variant choices;
- resolves each fault through the normal `compileCampaign()` safety rules;
- records immutable source, target, parameter, image, and choice receipts; and
- rejects the whole schedule if its aggregate campaign, time, concurrency,
  signer-impact, or burnchain budget would be exceeded.

The optional `decisionSpaces` object is keyed by sequence instruction ID:

```json
{
  "delay-a-peer": {
    "campaignAliases": ["short-delay", "long-delay"],
    "targetSets": [["miner-1"], ["miner-2"]],
    "parameterVariants": [
      {"delay": {"latency": "250ms"}},
      {"delay": {"latency": "750ms"}}
    ]
  }
}
```

Options are canonically sorted before selection, so incidental JSON ordering
cannot change a choice. The canonical options digest and HMAC receipt are part
of the resolved instruction.

`consumeReplayPlan()` converts the existing run-descriptor
`failure-prefix/v1` action ledger to the same resolved schedule format. It
executes only `fault-decision: applied` events. A previously resolved schedule
can also be rebound to a separately identified fresh network, but only when
the manifest, campaign template identities/specs, and admitted image digests
still match exactly.

## Delta-debug contract

`createDdminPlan()`, `issueDdminAttempt()`, and `recordDdminOutcome()` implement
adaptive hierarchical delta debugging over campaigns, exact target sets, and
top-level fault parameters. Every issued attempt is a counterfactual schedule,
not a conclusion. The executor must admission-check the candidate and run it
on a clean network with:

- a UID different from the source network and every earlier attempt;
- the same network manifest digest; and
- the same admitted image digest set.

An outcome is exactly one of `FailureReproduced`, `FailureAbsent`, or
`Inconclusive`, and includes a durable evidence digest. A reproduced result
must name the expected failed assertion and status. Inconclusive evidence is
never treated as absence of failure.

Completion means only “one-minimal under the recorded fresh-network
counterfactuals.” The result deliberately leaves `causalMinimalityClaimed`
false. Scheduler reduction cannot prove causality in a nondeterministic
distributed system.

## CLI

All commands read one JSON input and write an atomically replaced JSON result:

```text
node attacknet-run-schedule.mjs resolve INPUT [OUTPUT]
node attacknet-run-schedule.mjs replay INPUT [OUTPUT]
node attacknet-run-schedule.mjs ddmin-init INPUT [OUTPUT]
node attacknet-run-schedule.mjs ddmin-next INPUT [OUTPUT]
node attacknet-run-schedule.mjs ddmin-record INPUT [OUTPUT]
```

The command inputs are thin wrappers around the JavaScript APIs:

- `resolve`: `{ "run": ..., "context": ... }`
- `replay`: `{ "replayPlan": ..., "run": ..., "context": ... }`
- `ddmin-init`: `{ "schedule": ..., "options": ... }`
- `ddmin-next`: `{ "plan": ... }`
- `ddmin-record`: `{ "plan": ..., "result": ... }`

The run controller integration point is the resolved `actions` array. Create
one child `FaultCampaign` at a time from
`action.resolved.campaignSpec`, and verify its source/image constraints and
schedule digest before creation. Persist the complete schedule, each issued
ddmin attempt, and each outcome beside the incident evidence bundle.
