# Fresh-network replay and minimization executor

`kubernetes-ddmin-adapter.mjs` is the bounded host-side executor for
counterfactual replay and hierarchical delta debugging. It consumes the
immutable schedule of a terminal `AttacknetRun`; it never creates a Chaos Mesh
resource or an executable `FaultCampaign` itself.

The host may create one constrained `AttacknetRun` at a time (`maxAttempts` is
exactly `1` on each attempt CR; the host-side configuration owns the aggregate
attempt budget). The run
controller reads the terminal source schedule, reconstructs the candidate as
removals from that schedule, verifies the candidate digest, binds it to a new
`StacksNetwork` UID, persists the admitted schedule, and creates the executable
children. An attempt cannot add or reorder a campaign, add a target, add or
change a fault parameter, change a source template, change an image, or change
the network manifest.

## Safety and evidence contract

Every attempt:

1. runs the storage preflight before any mutation and fails closed when
   capacity cannot be proven;
2. verifies that at most one `AttacknetRun` is active;
3. exports the terminal source run, source schedule, source campaign results,
   and source network before deleting the source network;
4. recreates the same logical network through `lifecycle.sh`, requiring a
   clean and previously unused server-assigned UID;
5. compares the admitted manifest, digest-qualified images, and campaign
   template UID/generation/spec digests with the source schedule;
6. first replays the complete source schedule and stops, preserving the
   network, unless the exact expected failure reproduces;
7. submits one removal-only `AttacknetRun` and waits for its terminal trusted
   assertion classification;
8. exports and digests the attempt run, network, campaign results, and Pods;
9. durably records the ddmin outcome; and only then
10. deletes a conclusive attempt before creating the next fresh network.

An admission mismatch, timeout, different failure, missing assertion result,
unexported evidence, or any other ambiguity is `Inconclusive`. The executor
pauses and preserves that network for triage. `FailureAbsent` requires the
expected assertion to have been explicitly evaluated with a different
conclusive outcome; silence is never absence. `FailureReproduced` requires the
exact expected assertion and status.

The final ddmin statement is only “one-minimal under the recorded fresh-network
counterfactuals.” Neither the schedule library, controller status, executor
receipt, Prometheus metric, nor Grafana dashboard claims causal minimality.

## LLM-guided, mechanically verified reduction

An agent should not enumerate candidates blindly. It may use source structure,
the causal event ledger, topology, actor bindings, timestamps, metrics, logs,
and prior counterfactuals to rank high-information removals and to exclude a
dimension whose irrelevance is structurally established. Every such decision
is recorded as a hypothesis with its evidence; it is not promoted to a causal
fact merely because an LLM considers it obvious.

The trusted boundary remains mechanical: the compiler proves the submitted
candidate is removal-only, a fresh network executes it, and controller-owned
assertions classify the outcome. Uncertain dimensions remain in the candidate
set. This makes the intended process LLM-guided delta debugging rather than
either exhaustive subset search or intuition-only incident analysis.

Parameter removal has an additional monotonicity boundary. Omitting a field is
not always a weaker fault: absent `direction` means both directions, absent
`peerTarget` removes a traffic boundary, and absent `containerNames` can select
more containers. The scheduler therefore admits only explicitly proven
monotone parameter removals (currently individual effects from a multi-effect
`network/netem` campaign). It runs the canonical compiler before issuing a
counterfactual and records malformed reductions as `structuralSkips` with
`causalEvidence=false`; they do not consume a fresh network or attempt budget.

## Running

The source `AttacknetRun` must be terminal and its network must still be
available for the initial evidence export. Referenced `FaultCampaign` templates
must remain present with their original UID, generation, and spec. Network
teardown intentionally does not delete these templates.

Create a JSON configuration:

```json
{
  "adapter": {
    "namespace": "hacknet-system",
    "network": "attacknet",
    "sourceRunRef": "failed-run",
    "generatedDirectory": "contrib/attacknet/generated",
    "timeoutSeconds": 7200,
    "pollSeconds": 5
  },
  "expectedFailure": {
    "assertion": "TargetReady",
    "status": "Failed"
  },
  "maxAttempts": 16,
  "evidenceDirectory": "contrib/attacknet/evidence/ddmin-failed-run"
}
```

Then run:

```text
node contrib/attacknet/kubernetes-ddmin-adapter.mjs CONFIG.json
```

The environment and mutation leases in `environment-lock.sh` and
`lifecycle.sh` remain authoritative. Do not run another environment controller
or lifecycle command concurrently.

## Current classification boundary

The trusted terminal classifier currently consumes `FaultCampaign`
`effectResults` and `recoveryResults`. Therefore expected statuses are exactly
`Proven`, `Failed`, or `Inconclusive`. A protocol-level invariant such as
“chain height did not advance,” signer quorum loss, or a balance violation must
first be implemented as a bounded controller-owned assertion before the
executor can minimize it. A log message, actor-supplied metric, run phase, or
campaign reason is not silently promoted into trusted failure evidence.

This is an intentional fail-closed integration boundary, not evidence that
arbitrary chain-level failures are already minimizable.

## Live validation

The complete source → fresh baseline replay → removal-only counterfactual path
has been exercised on the local three-node kind cluster. Source run 5 used an
irrelevant follower Pod kill followed by an intentionally ineffective TCP
packet-duplication campaign. Baseline UID
`909dcff4-ec7a-416a-9575-8ba337d5d6c5` reproduced the trusted
`NetworkDegraded=Failed` assertion. Candidate UID
`a6fc4529-8c0b-41de-a9df-1a0ac7b3efc8` removed only the Pod kill and reproduced
the same assertion. The original one-attempt execution stopped truthfully at
its budget. After the monotone-removal correction, `rebuildDdminPlan()`
verified the immutable baseline-attempt digest, outcome digest, and exact
candidate schedule digest, then replayed that durable outcome through the
current scheduler. The reduced single-campaign schedule is now `Complete` and
one-minimal only within the declared admitted counterfactual domain;
`causalMinimalityClaimed` remains false. Evidence is retained under
`contrib/attacknet/evidence/ddmin-live-r5-20260815T214626Z/ddmin/`.
The digest-bound reclassification is in
`policy-reclassification-v2/result.json` in that bundle.

The live sequence also exposed and closed four harness defects: noncanonical
image ordering, failure to wait for owner-CR deletion, directory-depth-derived
source evidence, and redundant teardown of an already-absent network. Detailed
development history belongs in the external issue tracker rather than this
product guide.
