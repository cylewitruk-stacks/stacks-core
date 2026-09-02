# Seeded fuzz sessions

The typed client can compile a finite YAML plan into immutable run instructions,
execute those instructions through the existing controllers, retain outcomes in
a content-addressed corpus, confirm failures on fresh networks, and attempt
bounded removal-only reduction.

This is local regtest reliability testing. It does not expose arbitrary shell,
Kubernetes mutation, Bitcoin RPC, or fault parameters to an agent. The planner
selects only operator-created `FaultCampaign` and `UpgradeCampaign` templates;
their normal admission rules and safety budgets remain authoritative.

This workflow is approved for the Release 1 local three-node arm64 `kind`
profile. The exact capability and evidence binding is recorded in the
[`Release 1 baseline`](../../release/baseline-v1.json).

## Determinism boundary

The seed, immutable descriptor, admitted templates, and retained advisory input
determine byte-identical run instructions. They do not determine Kubernetes
scheduling, P2P peer selection, message ordering, network timing, block hashes,
or actor-internal random generators. Reproduction therefore means a fresh run
reached the same trusted semantic classification—not that logs, timestamps, or
packet traces matched byte-for-byte.

## Prerequisites

Use the qualified three-node local `kind` profile. Install Attacknet and Chaos
Mesh as described in the root quickstart, and run the client from the repository
root with Node.js available for the maintained observability renderer. Each
attempt provisions its own network-scoped Prometheus, Loki, Grafana, event
bridge, and Alloy resources after the network reports an admitted Ready
inventory. A fuzz plan also needs:

- one `StacksNetwork` YAML template;
- every referenced source burnchain policy, ConfigMap, and Secret already
  present; external actor configuration must declare the A11
  `expectedDigest` guard;
- every selectable campaign submitted with `spec.template: true` and no
  `spec.networkRef`; and
- enough verified local storage for the declared headroom and physical escrow.

The R1 capacity implementation accepts only the qualified local-path or Docker
Desktop host-path provisioner. An ambiguous, remote, sparse, or unprovable
storage reservation fails as `CapacityUnavailable` before a network is created.
Source burnchain policies must not contain a pending `spec.flash`; submit flash
behavior as an admitted campaign so it is scheduled, attributed, and replayed.
Advanced actor environment entries using `valueFrom` are not yet a sealed A13
input and are rejected during planning. Direct values and generated profiles
are sealed by the network-template digest.

The evidence plane is part of the journaled attempt lifecycle, not a shared
background service. Exact resource UIDs are recorded before a run starts;
capture completes while those resources are live; the network is then
suspended; and the exact evidence inventory is removed before teardown. A
replacement or partially adopted resource fails closed. Override the renderer
path with `ATTACKNET_OBSERVABILITY_RENDERER` only when the client is invoked
outside the repository root. `ATTACKNET_RUN_OPERATOR_TARGET` changes the
in-cluster run-controller metric target when a non-default release name is
intentional.

## Before running unattended

1. Run `$ATTACKNET doctor --output json` and require a clean result.
2. Verify the active kubeconfig context and confirm it is the disposable local
   cluster.
3. Verify an existing corpus with `$ATTACKNET corpus verify`; use an empty
   dedicated directory for a new corpus.
4. Submit and inspect only inert campaign templates with `spec.template: true`.
5. Compile the plan, then run `fuzz run --dry-run` and review its source
   resources, decision receipts, safety budgets, and contingent attempt bounds.
6. Confirm the declared capacity headroom is available. The run physically
   reserves storage and cold-start write-burst escrow before creating a
   network. Image-filesystem headroom is admission-gated and rechecked before
   every attempt, but is not reserved; avoid concurrent image pulls.

Keep the corpus directory. It contains the journal and immutable objects needed
for status, resume, replay, and reduction; copying only the session digest is
not sufficient.

## Run the example

Submit the source policy and the two inert templates. Planning seals the exact
policy UID, generation, and specification. Each fresh attempt receives its own
deterministically named copy rebound to that attempt's `StacksNetwork`; it does
not share the source policy or another attempt's burnchain clock.

```bash
ATTACKNET=/tmp/stacks-attacknet
NAMESPACE=hacknet-system

$ATTACKNET submit --namespace "$NAMESPACE" \
  --file contrib/helm/hacknet/examples/minimal-burnchain-policy.yaml
$ATTACKNET submit --namespace "$NAMESPACE" \
  --file contrib/attacknet/examples/fuzzing/follower-network-delay-template.yaml
$ATTACKNET submit --namespace "$NAMESPACE" \
  --file contrib/attacknet/examples/fuzzing/follower-pod-failure-template.yaml
```

Compile the plan. Planning reads the exact campaign and burnchain-policy UIDs,
generations, and specifications from Kubernetes, embeds them in the descriptor,
records the resource-materializer version, and records all seeded choices
before any experiment resource is created.

```bash
$ATTACKNET fuzz plan \
  --namespace "$NAMESPACE" \
  --file contrib/attacknet/examples/fuzzing/local-kind.plan.yaml \
  --output /tmp/local-kind-session.json
```

Inspect every unconditional source resource without constructing a runtime:

```bash
$ATTACKNET fuzz run \
  --descriptor /tmp/local-kind-session.json \
  --corpus /tmp/stacks-attacknet-corpus \
  --dry-run
```

The dry-run includes deterministic source resources and decision receipts plus
the maximum contingent confirmation and reduction bounds. Confirmation and
reduction resources depend on observed outcomes and are therefore not claimed
as resources that will necessarily be created.

The first non-dry-run `fuzz run` performs a final source preflight before it
constructs the mutation runtime. It re-reads every referenced campaign template
and burnchain policy and requires the sealed namespace, name, UID, generation,
specification digest, and network or Bitcoin-node binding to match. Drift stops
the command before an experiment resource is created. This preflight applies to
the initial run only; resume and corpus replay verify and use the retained
materialized inputs described below.

Execute or resume the finite session:

```bash
$ATTACKNET fuzz run \
  --descriptor /tmp/local-kind-session.json \
  --corpus /tmp/stacks-attacknet-corpus

$ATTACKNET fuzz resume \
  --session sha256:SESSION_DIGEST \
  --corpus /tmp/stacks-attacknet-corpus

$ATTACKNET fuzz status \
  --session sha256:SESSION_DIGEST \
  --corpus /tmp/stacks-attacknet-corpus \
  --output json
```

Resume verifies the descriptor, hash-chained journal, resource identities,
capacity reservations, and immutable report pointer. It does not infer state
from names. The session Lease and capacity escrow are created in the source
network template's namespace, independent of the kube-context default. A
completed command is idempotent.

If the client exits, do not start the descriptor as a new session. The active
`AttacknetRun` continues under its controller. Re-run `fuzz resume` with the
recorded session digest and the same corpus; it verifies the hash-chained
journal and exact Kubernetes identities before continuing.

`fuzz status` verifies the corpus before returning the decoded static report,
its immutable object reference, the capacity-admission receipt and headroom
snapshot, session entries, explicit zero-valued classification counts, and any
preservation or inconclusive-result warnings. A digest without the decoded,
verified object is not reported as operator-readable status.

## Corpus and replay

The corpus contains immutable objects, semantic entry manifests, hash-chained
session journals, static reports, and administrative audit receipts. Verify it
before reuse:

```bash
$ATTACKNET corpus verify --corpus /tmp/stacks-attacknet-corpus
$ATTACKNET corpus list --corpus /tmp/stacks-attacknet-corpus --output json
$ATTACKNET corpus show --corpus /tmp/stacks-attacknet-corpus --output json \
  sha256:FINGERPRINT
```

Replay and reduction always use a fresh network and require explicit attempt
identity. When one fingerprint has multiple entries, select the exact entry:

```bash
$ATTACKNET corpus replay --corpus /tmp/stacks-attacknet-corpus \
  --entry sha256:ENTRY_DIGEST --attempt-id operator-replay-1 \
  sha256:FINGERPRINT

$ATTACKNET reduce --corpus /tmp/stacks-attacknet-corpus \
  --entry sha256:ENTRY_DIGEST --attempt-id operator-reduce-1 \
  sha256:FINGERPRINT
```

R1 automatic reduction descends through whole executions, stages, actions,
and explicit actor targets. It does not modify fault parameters automatically.
The existing manual `RemovedParameters` API is separate; mechanism-registered
monotone parameter reducers remain future work.

For each attempt, the materializer creates deterministically named, inert
attempt-local `FaultCampaign` and `UpgradeCampaign` clones from the exact sealed
specifications. The `AttacknetRun` catalog is then bound to the observed UID,
generation, and specification digest of those clones. The clones are journaled
and removed through exact-identity teardown after evidence capture.

Resume, confirmation, corpus replay, and reduction use the retained descriptor,
materialized specifications, journal identities, and corpus objects. They do
not re-read or require the original planning-namespace campaign templates. This
makes a retained corpus portable after its source templates are retired without
turning current cluster state into a new authorization source. Missing,
substituted, or digest-mismatched retained inputs fail closed. A resumable
session must contain exactly one artifact named `session-descriptor`; advisory
objects may coexist in the planning record but are never selected by position.

An optional advisory is bounded JSON containing only known candidate IDs,
integer scores, and short rationale. It may rank an already-enumerated set; it
cannot add a candidate, change parameters, authorize an unsafe option, or decide
the outcome. Accepted advisory bytes are retained as normal corpus objects.

## Ownership recovery

The local writer lock and Kubernetes session Lease are distinct. Neither is
stolen automatically. The heartbeat retries transient Kubernetes API errors
only within the still-valid Lease window; a changed Lease identity or an
expired renewal deadline aborts the session as an apparatus failure. First
inspect the exact identity, establish externally
that its owner is stale, then provide every observed precondition and a reason:

```bash
$ATTACKNET fuzz lock status --corpus /tmp/stacks-attacknet-corpus
$ATTACKNET fuzz lock break --corpus /tmp/stacks-attacknet-corpus \
  --expected-owner sha256:SESSION_DIGEST \
  --expected-process-id 12345 \
  --expected-acquired-at 2026-08-31T12:34:56.123456Z \
  --reason "operator confirmed process 12345 no longer exists"

$ATTACKNET fuzz lease status --corpus /tmp/stacks-attacknet-corpus --namespace hacknet-system
$ATTACKNET fuzz lease break --corpus /tmp/stacks-attacknet-corpus \
  --namespace hacknet-system \
  --expected-uid LEASE_UID \
  --expected-resource-version RESOURCE_VERSION \
  --expected-holder sha256:SESSION_DIGEST \
  --reason "operator confirmed the prior session cannot resume"
```

Any identity change rejects the break. Successful local-lock breaks and Lease
break intent/completion are immutable corpus audit records.

## Reading outcomes

`Clean`, `NetworkFailureCandidate`, `ConfirmedNetworkFailure`,
`NotReproduced`, `Inconclusive`, and `HarnessFailed` are distinct. An injected
fault is not evidence that Stacks failed. Missing evidence, identity drift,
capacity loss, or apparatus failure can never become a clean or confirmed
network result.

Grafana's **Attacknet / Fuzz sessions** dashboard is a human view over bounded
session/trial labels. It separates clean, failed, inconclusive, and
harness-attributed controller runs; shows schedule attribution, admitted
immutable version cohorts, fault and reduction progress, burnchain context,
and observation-pipeline health. Pre-run capacity failures and corpus paths are
local state, so inspect them with `fuzz status` and `corpus show` rather than
expecting Prometheus labels. Semantic fingerprints, seeds, and digests remain
in the corpus and static JSON report. Actor logs are untrusted supporting
material; controller status and identity-bound evidence remain the
classification source.

## Troubleshooting

| Symptom | First action |
| --- | --- |
| Planning reports source drift | Re-read the named template or policy UID, generation, and specification. Re-plan intentionally; do not weaken the digest check. |
| Run reports `CapacityUnavailable` | Preserve the receipt, free or provision real local storage, then begin a new session. No experiment network was created. |
| Session reports an owned local lock | Run `fuzz lock status`; break it only after externally proving the exact recorded process is stale. |
| Session reports an owned Kubernetes Lease | Run `fuzz lease status`; use every observed precondition when explicitly breaking a stale Lease. |
| Resume reports identity or journal drift | Preserve the corpus and cluster. Do not reconstruct state from resource names or edit the journal. |
| Result is `NotReproduced` | Retain both source and replay evidence. Automatic reduction is deliberately not started. |
| Result is `Inconclusive` or `HarnessFailed` | Treat it as apparatus evidence, not a Stacks defect. Inspect omissions, identities, capacity, controllers, and evidence services. |
| Corpus verification fails | Stop reuse immediately and preserve the directory for forensic inspection; do not regenerate or overwrite immutable objects. |
