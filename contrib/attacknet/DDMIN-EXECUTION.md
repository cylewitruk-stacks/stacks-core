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

## Live-validation boundary

The executor and controller admission path have offline fake-runner and fake
API coverage. The live multi-attempt path has not yet been exercised because
the local kind nodes reported zero available image/root filesystem bytes. A
live result is not claimed until storage preflight passes and a real terminal
source failure can be replayed on fresh network UIDs.
