# Attacknet failure-attribution contract

An attacknet is an experimental instrument, not just a destructive workload.
A red assertion without enough evidence to explain the first divergence is an
inconclusive experiment, not a discovered Stacks bug and not a successful test.

## Outcome and attribution are separate

Every run records two independent states:

- Experiment outcome: terminal `Passed`, `Failed`, or `Inconclusive`; a run may
  instead pause for triage before reaching a terminal phase.
- Attribution: `NotRequired`, `Untriaged`, `Triaged`, `Remediated`, or
  `Inconclusive`.

A passed experiment may use `NotRequired`. A failed or inconclusive experiment
must begin as `Untriaged` and may not be summarized as a finding until it
becomes `Triaged` or `Remediated`. Attribution `Inconclusive` is honest only
when it names the missing observation and creates a concrete instrumentation
action.

## Freeze, preserve, explain

On the first failed invariant the orchestrator must:

1. Stop scheduling new faults. Clear only the currently active bounded fault
   when leaving it active threatens evidence or cluster safety.
2. Preserve the actor Pods, PVCs, admitted Kubernetes objects, cadence policy,
   Chaos Mesh status, observability journal, version descriptor, image-import
   receipt, and upgrade status. Do not automatically tear down or recreate the
   network.
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

`attacknet evidence incident` records, at minimum:

- a manifest bound to the network UID and admitted inventory digest;
- the admitted `StacksNetwork` and exactly owned controller, policy, campaign,
  Pod, StatefulSet, Service, ConfigMap, PVC, and supported fault resources;
- bounded current and previous logs for exact admitted Pod names and UIDs;
- UID-scoped Kubernetes Events and explicit collection errors or omissions; and
- a checksum inventory and machine-readable completeness report.

The bounded incident bundle does not itself contain every external metric, RPC
sample, or retained log. Preserve the complete Loki interval with `attacknet
teardown`, and retain Prometheus snapshots, protocol observations, and
host-generated version artifacts alongside it.

Capture completeness does not prove causality. It proves what was available to
the analysis and makes missing evidence visible.

## Mixed-version attribution

A profile expectation records experiment intent; it is never an observed
compatibility verdict. Apply these classifications before claiming that two
versions are incompatible:

| Observation | Initial classification | What it does not prove |
| --- | --- | --- |
| Selected source changes between planning and preparation | Source-input drift; reject before image or cluster mutation | A Stacks or protocol defect |
| Configuration smoke fails | `ConfigurationUnsupported` | Runtime protocol incompatibility |
| Assigned actor never becomes Ready by the stage deadline | `StartupIncompatible`; inspect image, config, init container, resources, and logs | Which layer caused startup failure |
| Required trusted observation is unavailable | `TelemetryUnavailable` or `ProtocolAssertionInconclusive`; terminal `Inconclusive` | Health or version incompatibility |
| A finite protocol assertion is violated | `ProtocolAssertionViolated` | Version causality without a controlled comparison |
| Network UID or an unauthorized identity changes | Harness/topology identity failure | An authorized upgrade transition |

For an incompatibility finding, retain a controlled compatible cohort, exact
source and build provenance, identical relevant configuration or an explained
version-specific difference, complete before/during/after observations, and a
fresh replay or minimized schedule. Reject infrastructure, telemetry,
configuration, and unrelated assertion hypotheses explicitly. See the
[`mixed-version guide`](../concepts/mixed-version-images.md) and
[`evidence.md`](evidence.md).

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
