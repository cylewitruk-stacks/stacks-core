# Attacknet failure-attribution contract

An attacknet is an experimental instrument, not just a destructive workload.
A red assertion without enough evidence to explain the first divergence is an
inconclusive experiment, not a discovered Stacks bug and not a successful test.

## Outcome and attribution are separate

Every run records two independent states:

- Experiment outcome: `Passed`, `Failed`, or `Aborted`.
- Attribution: `NotRequired`, `Untriaged`, `Triaged`, `Remediated`, or
  `Inconclusive`.

A passed experiment may use `NotRequired`. A failed or aborted experiment must
begin as `Untriaged` and may not be summarized as a finding until it becomes
`Triaged` or `Remediated`. `Inconclusive` is an honest terminal result only when
it names the missing observation and creates a concrete instrumentation action.

## Freeze, preserve, explain

On the first failed invariant the orchestrator must:

1. Stop scheduling new faults. Clear only the currently active bounded fault
   when leaving it active threatens evidence or cluster safety.
2. Preserve the actor Pods, PVCs, admitted Kubernetes objects, cadence policy,
   Chaos Mesh status, and observability journal. Do not automatically tear down
   or recreate the network.
3. Capture a bounded incident bundle. A broken or stopped actor is evidence and
   must produce an explicit capture-error marker rather than abort collection.
4. Reconstruct the first divergence from the ordered control-plane journal,
   canonical chain snapshots, actor logs, actor metrics, Kubernetes events, and
   the requested versus admitted configuration.
5. State the causal mechanism and counterfactual. Temporal proximity to a fault
   is not attribution; pre-fault evidence must be checked first.

The incident bundle is intentionally redundant. Actor metrics are self-reported
and may be malicious. Kubernetes admission/runtime state and orchestrator events
are trusted control-plane observations. Chain agreement is corroborated across
independent actors.

## Required incident evidence

`incident-capture.sh` records, at minimum:

- an incident envelope with phase, reason, source revision, and run identity;
- the topology manifest and admitted `StacksNetwork`, Pod, StatefulSet, PVC, PV,
  policy, and Chaos Mesh objects;
- `/v2/info`, `/v2/neighbors`, diagnostics responses or explicit errors for all
  nodes;
- bounded current and previous actor logs plus node/signer metrics;
- namespace events, operator logs, and the trusted event journal;
- a checksum inventory and a machine-readable completeness report.

Capture completeness does not prove causality. It proves what was available to
the analysis and makes missing evidence visible.

## Triage record

The eventual analysis should identify:

- the earliest known-good and first divergent observations and their clocks;
- affected and unaffected actors, versions, roles, and partitions;
- one classification: harness defect, topology/configuration defect,
  infrastructure failure, expected fault impact, Stacks liveness/correctness
  defect, or security finding;
- the causal chain, competing hypotheses rejected, and supporting artifact
  paths;
- whether the condition predates the injected fault;
- remediation or the exact observation needed to resolve `Inconclusive`;
- a replay descriptor or minimized failure prefix when replay is meaningful.

This contract applies equally to agent-directed, scheduled, and human-authored
campaigns. An agent may explore indefinitely, but it may not silently discard or
overwrite an unexplained failure.
