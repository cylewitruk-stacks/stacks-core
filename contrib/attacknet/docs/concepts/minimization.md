# Fresh-network replay and minimization

Attacknet performs replay and minimization through `AttacknetRun`; no host-side
script is allowed to compile or inject faults independently of the controller.
The controller reads the terminal source schedule, verifies its digest and
immutable inputs, and admits one bounded removal-only counterfactual on a fresh
`StacksNetwork` UID.

## Safety contract

Before executing a candidate, the controller requires:

- a terminal source run and readable immutable schedule;
- a fresh target network with the expected admitted manifest and images;
- unchanged campaign-template identity and content;
- equal safety budgets;
- one unique attempt identity and an explicit expected assertion/status;
- an ordered non-empty subset of source executions; and
- a candidate digest equal to the schedule produced by permitted removals.

A candidate cannot add or reorder executions, stages, actions, targets, or
parameters. Parameter removal is accepted only where the compiler defines a
safe monotone reduction. Any identity drift, timeout, different failure,
missing assertion, incomplete cleanup, or ambiguous evidence is
`Inconclusive` and preserves the environment for triage.

## Workflow

1. Capture and retain the failed source run, source schedule, campaign
   children, admitted inventory, and incident evidence.
2. Recreate the logical topology as a fresh `StacksNetwork` and wait for a
   complete admitted inventory.
3. Submit a baseline replay with the source descriptor URI/digest and expected
   outcome. Stop if the exact outcome does not reproduce.
4. Build one removal-only candidate from the retained execution rules, compute
   its expected schedule digest, and submit a minimization run.
5. Wait for terminal classification and completed cleanup, then retain all
   evidence before the next attempt.

The relevant `AttacknetRun` fields are `spec.replay` and `spec.minimization`.
Use the typed client for validation, submission, observation, and evidence:

```bash
attacknet validate --file minimization-attempt.yaml
attacknet submit --namespace hacknet-system --file minimization-attempt.yaml
attacknet wait --namespace hacknet-system --for terminal \
  AttacknetRun minimization-attempt-01
attacknet evidence incident --namespace hacknet-system \
  --output evidence/minimization-attempt-01 fresh-network
```

## LLM-guided reduction

An agent may rank high-information removals using source structure, topology,
timestamps, metrics, logs, and earlier counterfactuals. The trusted boundary
remains mechanical: every candidate is controller-validated, executed on a
fresh network, and classified by bounded assertions. Hypotheses are not causal
facts, and uncertain dimensions remain in the candidate.

The final claim is only “one smaller admitted candidate reproduced the outcome
under the recorded fresh-network counterfactual.” Attacknet does not claim
causal minimality.

The retired v1alpha1 adapter is retained under
[`../../legacy/`](../../legacy/README.md) solely for historical evidence
verification.
