# R1A13: Seeded fuzzing, corpus management, and reduction

## Status

| Field | Value |
| --- | --- |
| Amendment | R1A13 |
| State | Design drafted; implementation not started |
| Expected review tier | Full |
| Product claim | Not supported until implementation and qualification complete |

## Objective

R1A13 turns the existing finite Attacknet primitives into a bounded,
unattended experiment loop. Given one immutable plan and seed, it must generate
the same ordered run instructions, execute them only through the existing
Kubernetes controllers, retain novel adverse outcomes in a portable corpus,
confirm them on fresh networks, and mechanically reduce confirmed failures.

The amendment adds orchestration around already qualified faults. It does not
add a new fault type or adversarial actor behavior. In particular, signer
equivocation, invalid miner proposals, arbitrary protocol payloads, and
misleading actor reports remain separate behavior-specific work.

R1A13 is successful only if an operator can leave a finite fuzz session
running and later answer:

1. Which immutable inputs and deterministic decisions produced each trial?
2. Did Attacknet, Stacks, Kubernetes, or the evidence apparatus fail?
3. Was an adverse Stacks outcome reproduced on a fresh network?
4. Which removal-only candidate was accepted, rejected, or inconclusive?
5. Can a human or agent replay the retained candidate without reconstructing
   hidden state?

## Existing foundation and gaps

R1A13 must extend the current implementation rather than replace it.

| Capability | Current state | A13 work |
| --- | --- | --- |
| Finite `AttacknetRun` schedule | Controller-resolved, immutable, digest-bound | Reuse unchanged as the execution authority |
| Seed | Recorded in the schedule | Make it drive a versioned deterministic generator |
| Fault and upgrade templates | UID, generation, and spec digest are sealed | Define a bounded selectable template universe |
| Replay | Rebinds an immutable schedule to a fresh network UID | Automate fresh-network provisioning and confirmation |
| Minimization | One caller-authored removal-only attempt | Add a deterministic multi-attempt planner around the existing one-attempt API |
| Terminal classification | Distinguishes expected and observed assertion outcomes | Promote only exact, trusted classifications into corpus decisions |
| Incident and Loki evidence | Fail-closed local export with identity rechecks | Store it in a content-addressed corpus and bind it to each attempt |
| Capacity check | Measures current root and image filesystems | Add session admission, preloading, cooperative reservation, and runtime headroom checks |
| Human and agent interface | Typed Go CLI and Kubernetes status | Add machine-readable fuzz, corpus, replay, and reduction commands |

The existing run controller remains the only component that seals schedules,
evaluates trusted triggers, creates child campaigns, enforces aggregate
budgets, and classifies protocol assertions. A13 must not create a second
scheduler with weaker rules.

## Scope and non-goals

R1A13 includes:

- strict YAML input for a finite fuzz plan;
- deterministic weighted selection from an immutable template universe;
- a content-addressed, append-only session ledger and failure corpus;
- resumable local orchestration with one active environment at a time;
- fresh `StacksNetwork` provisioning for confirmation and reduction attempts;
- automated hierarchical, removal-only delta debugging;
- optional agent-provided candidate ranking as sealed advisory input;
- capacity admission and cooperative reservation for the qualified local
  three-node arm64 `kind` environment;
- complete evidence, dashboards, operator documentation, and negative
  controls.

R1A13 does not include:

- new fault mechanisms or adversarial actor behaviors;
- raw Bitcoin RPC, arbitrary Kubernetes mutation, arbitrary PromQL, or
  arbitrary shell commands chosen by a fuzzer or agent;
- controller-side source checkout, image compilation, or LLM execution;
- byte-identical network traces, deterministic P2P peer selection, or
  deterministic operating-system scheduling;
- proof of causal or globally minimal failure conditions;
- a multi-cluster corpus service, cloud object store, or registry-backed
  distributed worker fleet;
- physical storage guarantees outside the dedicated local `kind` profile.

## Architecture decision

### Reuse `AttacknetRun`; do not add a fuzzing controller

R1A13 adds a resumable session engine to the typed Go CLI. The engine prepares
ordinary `StacksNetwork`, template, and `AttacknetRun` resources and observes
their controller-owned status. It never injects a fault directly.

A new fuzzing reconciler or corpus CRD is deliberately rejected for R1:

- bulk logs and evidence do not belong in the Kubernetes API;
- the existing evidence and image workflows terminate on the operator
  workstation, outside a controller Pod;
- an LLM must not run inside the mutation trust boundary;
- `AttacknetRun` already owns durable in-cluster execution and restart
  recovery; and
- a second controller would duplicate topology creation, schedule sealing,
  evidence export, and teardown semantics.

If the local session process exits, the active `AttacknetRun` continues under
the run controller. Restarting the CLI reads its append-only journal, observes
the exact resource UIDs, and resumes at the first incomplete barrier. It must
not recreate or silently skip an ambiguous operation.

### Responsibility split

| Component | Responsibility |
| --- | --- |
| Fuzz planner | Strict input, immutable resolution, deterministic decisions, and trial descriptors |
| Session engine | Capacity lease, fresh networks, run submission, evidence capture, corpus admission, replay, reduction, and teardown |
| Topology operator | Actor workloads, dependencies, policies, and admitted inventory |
| Run operator | Schedule sealing, triggers, budgets, child orchestration, assertions, and terminal classification |
| Fault operator | Identity-safe injection, effect proof, rollback, and recovery |
| Corpus store | Immutable artifacts, classifications, replay manifests, and reduction graph |
| Optional agent | Candidate ranking and triage suggestions only |

The session engine may create typed product resources through client-go. It
must not patch actor workloads, create raw Chaos Mesh objects, invoke Bitcoin
RPC directly, or bypass controller status. All such actions remain behind the
existing CRDs and their safety checks.

## Fuzz plan contract

The human-authored input uses schema `stacks-attacknet-fuzz-plan/v1`. It is a
strict YAML document decoded by the shared Go document boundary with unknown
fields rejected. It contains:

- a non-secret opaque seed and generator algorithm;
- a finite maximum trial count and session deadline;
- one `StacksNetwork` template and immutable image constraints;
- allowed `FaultCampaign` and `UpgradeCampaign` templates;
- integer selection weights, per-template usage limits, and incompatibility
  exclusions;
- a finite set of permitted run-trigger forms;
- run, fault, signer, miner, burnchain, duration, and concurrency budgets;
- baseline, during, and recovery assertion sets;
- stop, preservation, replay, reduction, and evidence policies;
- capacity requirements and corpus location.

Preparation resolves all mutable inputs before the first trial. The result is
a canonical `stacks-attacknet-fuzz-session/v1` descriptor containing exact
source document digests, template UIDs, generations and spec digests, network
template digest, resolved image identities, decision algorithm, budget set,
capacity policy, and corpus policy.

Secrets, repository credentials, raw Secret values, and private patch content
must not enter the descriptor or corpus metadata. Their immutable digests may
be referenced where already supported by A11.

### Template universe

The generator may select only templates admitted during preparation. A
template can contain a multi-stage or concurrent `FaultCampaign`; A13 does not
synthesize arbitrary fault actions from free-form parameters. This preserves
the existing validation, aggregate-impact, opt-in, and capability contracts.
Reusable templates must leave `networkRef` empty; a template pinned to one
network is rejected rather than silently rebound across trials.

Each selectable item records:

- logical ID and Kubernetes source reference;
- kind, UID, generation, and canonical specification digest;
- eligibility predicates over the declared topology;
- integer weight and maximum uses per session;
- conflict groups and prerequisite template IDs; and
- expected fault, upgrade, and assertion families.

A template change after preparation invalidates the session before a new
network or child run is created.

### Trigger selection

R1A13 selects only trigger forms already implemented by `AttacknetRun`:

- time after run start;
- exact burn height;
- exact Stacks height;
- trusted finite observation;
- dependency on an earlier execution milestone.

Height candidates may be derived from an identity-bound pre-run observation,
but the resulting absolute value and observation receipt are sealed before the
run starts. Exact tenure and protocol-message-digest triggers remain outside
A13 until the trusted trigger vocabulary or behavior policy supports them.

## Deterministic decision algorithm

The initial algorithm is `hmac-sha256-fuzz-plan/v1`. It uses domain-separated
HMAC-SHA256 decisions over:

- the session descriptor digest;
- the opaque seed;
- trial ordinal;
- decision domain and ordinal; and
- a digest of the canonically ordered candidate set.

Integer rejection sampling avoids modulo bias. Candidate order uses explicit
UTF-8 byte ordering over bounded DNS-style identifiers, not locale collation
or map iteration. Weighted choices use positive integers with a bounded total;
floating-point weights are forbidden.

Every choice produces a decision receipt with the algorithm version, domain,
counter, candidate-set digest, selected candidate, and output digest. The
receipt is appended before any corresponding Kubernetes resource is created.

This generator algorithm is distinct from
`AttacknetRun.spec.decisionAlgorithm`. Every materialized trial continues to
use the controller's qualified `dependency-trigger-scheduler/v1`; the planner
supplies an explicit execution DAG and a derived, recorded per-trial seed. A13
does not move trigger or dependency evaluation out of the run controller.

Identical descriptors, seeds, and admitted advisory inputs must produce
byte-identical run instructions. This claim does not extend to resulting block
hashes, message ordering, Kubernetes scheduling, or timing.

### Agent-assisted selection

An agent may rank the already enumerated candidate IDs. Its proposal is an
untrusted, bounded JSON artifact containing only candidate IDs, integer scores,
and optional concise rationale. The planner:

1. rejects unknown, duplicate, ineligible, or over-budget candidates;
2. canonicalizes the accepted proposal and stores its exact bytes as an
   immutable corpus object;
3. binds the proposal object digest into the decision input;
4. applies deterministic ordering and seeded tie-breaking; and
5. writes the accepted decision before execution.

The agent cannot provide fault parameters, shell commands, Kubernetes objects,
RPC requests, or a terminal verdict. Without the exact advisory artifact,
agent-assisted selection is not claimed reproducible. A digest alone is
insufficient: replay must be able to retrieve and verify the exact retained
artifact without invoking the original agent again. Advisory artifacts use a
strict size-bounded schema and must not contain credentials, private source,
or other secret material.

## Session state and serialization

Only one fuzz session may own the qualified local environment. The session
engine acquires a namespaced `coordination.k8s.io/Lease` using a unique session
digest and renews it while active. Loss, theft, or ambiguous expiry of the
lease pauses new work; it never triggers speculative cleanup.

The local journal is an immutable hash chain. Each record includes a sequence
number, prior-record digest, event kind, resource identities, artifact
digests, and timestamp. Timestamps are evidence but not deterministic decision
inputs. Records are written through a temporary file, synced, renamed, and
directory-synced before the next side effect.

The session phases are:

```text
Planned -> CapacityAdmitted -> TrialPreparing -> TrialRunning
        -> Capturing -> Classified -> Confirming -> Reducing
        -> Complete

Any phase -> Paused | PreservedForTriage | HarnessFailed
```

Each trial has its own durable ordinal and attempt ID. Resume rechecks the
network UID, run UID, schedule digest, inventory digest, and evidence state
before continuing. A missing or replaced object produces `HarnessFailed` or
`Inconclusive`; it is never assumed complete.

## Fresh-network lifecycle

Every initial trial, confirmation replay, and reduction attempt uses a newly
created `StacksNetwork` UID and clean PVC identities. Images may remain loaded
on `kind` nodes, but actor state, chainstate, run objects, and mutation objects
must not be reused.

The session engine:

1. derives a bounded name from the session digest, trial ordinal, and attempt;
2. materializes the sealed network template with only the permitted identity
   substitutions;
3. waits for `observedGeneration`, Ready state, and complete admitted inventory;
4. verifies runtime image constraints and template identities;
5. submits the already materialized `AttacknetRun`;
6. captures evidence before any teardown;
7. rechecks the exact network UID and inventory digest; and
8. deletes only through the existing evidence-safe teardown boundary.

Failed, inconclusive, or apparatus-ambiguous attempts remain preserved until
their evidence policy is satisfied or an operator explicitly disposes of
them. Clean trials may be torn down automatically after complete evidence is
sealed.

## Capacity admission and cooperative reservation

A13 closes the Release 1 `cold-start-capacity-reservation` gap for the
qualified dedicated local profile. It must not describe this as a portable
cloud-storage guarantee.

Before unattended execution, the session engine:

1. acquires the exclusive Attacknet session Lease;
2. resolves, builds, loads, and verifies every image allowed by the plan;
3. measures root and image filesystems on every `kind` node;
4. measures the local corpus filesystem;
5. computes worst-case concurrent Pod, PVC, image, log, and evidence budgets
   from the finite plan;
6. provisions and physically writes bounded capacity-escrow volumes on the
   same local storage class used by actors;
7. preallocates a bounded local evidence escrow using non-sparse allocation;
8. releases only the storage needed for the next fresh network while holding
   the configured safety reserve; and
9. rechecks capacity before every trial and evidence export.

Escrow creation, verification, release, and residual capacity are journaled.
If the platform cannot prove non-sparse allocation or the storage class does
not resolve to the qualified local backend, the session refuses unattended
mode. A failed capacity check creates no network and is classified as
`CapacityUnavailable`, not as a Stacks failure.

The exclusive Lease prevents competing Attacknet sessions, not unrelated
cluster workloads. Capacity drift from outside the session pauses execution
and is reported as apparatus interference.

## Outcome model and novelty

The session preserves the controller's terminal vocabulary. It must not turn a
successful fault injection into a successful network result.

| Session classification | Meaning | Corpus handling |
| --- | --- | --- |
| `Clean` | Run and recovery assertions passed | Retain compact summary; full evidence per policy |
| `NetworkFailureCandidate` | Trusted protocol assertion proved an adverse outcome | Capture fully and queue fresh replay |
| `ConfirmedNetworkFailure` | Required fresh replays reproduced the expected classification | Admit to failure corpus and queue reduction |
| `NotReproduced` | Fresh replay completed but did not reproduce the expected outcome | Retain both outcomes; do not reduce automatically |
| `Inconclusive` | Required evidence was unavailable or ambiguous | Preserve for triage; never call clean or failed |
| `HarnessFailed` | Attacknet, Kubernetes, capacity, or evidence machinery failed | Store separately from network failures |

Novelty uses a versioned semantic fingerprint derived only from trusted,
bounded fields:

- terminal phase, reason, and attribution;
- violated protocol assertion IDs and result classes;
- fault and upgrade mechanism families;
- identity-divergence class, when present;
- admitted version-cohort digest; and
- burnchain boundary class and network-view count, when applicable.

Raw log bytes, timestamps, Pod names, random hashes, and free-form error text
are excluded from the primary fingerprint. They remain forensic evidence and
may contribute bounded secondary similarity hints. A new raw log line alone
must not create a new corpus entry.

## Corpus format and retention

The R1 corpus is a local content-addressed directory. It uses only Go code and
portable files; no database service is required.

```text
corpus/
├── corpus.json
├── sessions/<session-digest>/journal/
├── entries/<semantic-fingerprint>/<entry-digest>.json
├── objects/sha256/<prefix>/<digest>
└── reports/<session-digest>.json
```

Objects are immutable and addressed by SHA-256. Entry manifests bind the
source and replay schedules, network inventories, exact images, run and child
statuses, incident bundle, complete Loki export, decision receipts,
classification, reduction graph, and every advisory artifact consumed by a
decision. Each advisory reference records its object digest, decision domain,
and receipt digest. Writes use create-exclusive temporary files plus sync and
rename. Existing objects are accepted only after digest verification.

An entry that used advisory input is incomplete unless every referenced
advisory object is present and verifies. Corpus verification and replay both
fail closed on an absent, substituted, non-canonical, or schema-invalid
artifact. Rejected proposals may be retained for diagnosis, but only an
accepted proposal referenced by a decision receipt is a replay input.

The index is derived from entry manifests and can be rebuilt. A single-writer
lock and the cluster session Lease prevent concurrent mutation. Stale-lock
recovery requires an explicit command and records the previous owner; it does
not silently steal ownership.

Retention policy is explicit and size-bounded. It may discard full evidence
for old clean runs only after retaining their digest-bound summary and object
inventory. Confirmed failures, inconclusive outcomes, harness failures, replay
controls, and accepted reduction attempts are never automatically deleted.

## Confirmation replay

A failure candidate enters reduction only after the configured number of
fresh-network replays reproduce the exact expected assertion status and
semantic fingerprint. R1 defaults to two confirmations and allows a bounded
`1..5`; evidence states the selected policy.

Different failures, missing evidence, identity drift, or harness failures do
not count as reproduction. They are retained as separate attempts and stop
automatic reduction unless policy explicitly permits another bounded retry.

Agent-assisted replay loads the exact advisory object from the corpus, verifies
its digest and schema, and reproduces the recorded deterministic planner
decision. It never asks an agent to regenerate or approximate the ranking.

Because Stacks and Kubernetes retain unseeded concurrency, confirmation means
that the same immutable instructions reproduced the same bounded outcome
class. It does not mean the trace is deterministic or that a failure with a
lower reproduction rate is disproven.

## Mechanical reduction

The reducer is a deterministic planner around the existing one-attempt
`AttacknetRun.spec.minimization` contract. The controller continues to admit
and execute exactly one removal-only candidate on one fresh network.

Reduction proceeds hierarchically:

1. remove partitions of whole executions;
2. remove stages from retained fault campaigns;
3. remove actions from retained stages;
4. remove explicit actors from retained targets; and
5. apply only mechanism-registered monotone parameter reducers.

Each candidate preserves source order and cannot add an execution, stage,
action, target, dependency, trigger, opt-in, or parameter. Safety budgets may
remain equal or become stricter; they cannot be relaxed. An empty candidate is
invalid.

The planner uses a versioned hierarchical ddmin algorithm, records every
partition and outcome, and submits candidates sequentially on fresh networks.
The maximum attempts, wall time, and evidence bytes are fixed in the session
descriptor. A candidate is retained only after satisfying the same bounded
confirmation policy as the source failure.

Distributed failures may be non-monotone. Therefore the output is called a
`reduced reproducer`, not a minimal or causal proof. The existing
`causalMinimalityClaimed` field remains false.

### LLM-guided reduction

An LLM may rank the mechanically generated removal candidates to reduce
obviously unhelpful attempts. Its artifact is bound like any other advisory
input. It cannot invent a candidate or mark one accepted. Every removal is
validated by the run controller and fresh-network confirmation.

## API and CLI surface

R1A13 adds no standalone fuzz CRD. It may add a bounded optional provenance
block to `AttacknetRunSpec` so the controller-owned schedule records session
digest, trial ordinal, plan digest, and decision digest. These values are
validated and sealed as provenance; they do not authorize mutations.

The typed CLI adds:

```text
attacknet fuzz plan --file PLAN.yaml --output SESSION.json
attacknet fuzz run --descriptor SESSION.json --corpus DIR
attacknet fuzz resume --session DIGEST --corpus DIR
attacknet fuzz status --session DIGEST --corpus DIR --output json
attacknet corpus list --corpus DIR --output json
attacknet corpus show --corpus DIR FINGERPRINT --output json
attacknet corpus verify --corpus DIR
attacknet corpus replay --corpus DIR FINGERPRINT
attacknet reduce --corpus DIR FINGERPRINT
```

Planning is offline except for explicit template and image resolution.
`--dry-run` prints every intended Kubernetes resource and decision without
creating it. Every mutating command emits a machine-readable receipt and uses
the existing typed client-go boundary.

## Observability and human analysis

Generated `AttacknetRun` objects carry bounded labels for session, trial, and
attempt. Run-operator metrics expose active session/trial state without using
semantic fingerprints or arbitrary seeds as Prometheus labels.

Grafana adds a fuzz-session view showing:

- clean, failed, inconclusive, and harness-failure trial counts;
- current trial, phase, schedule digest, and capacity headroom;
- selected fault, version, and boundary families;
- confirmation and reduction progress;
- links to actor drill-down, run timeline, and corpus entry; and
- preserved-environment and evidence-completeness warnings.

The CLI generates a static digest-bound session report for post-run use. Agent
interfaces consume JSON status, controller metrics, evidence manifests, and
corpus entries directly; screenshots are not evidence.

## Security and safety invariants

- The generator selects only immutable admitted templates.
- All random choices use one documented, versioned algorithm and are recorded
  before execution.
- The session engine never writes actor workloads or raw fault resources.
- Existing dangerous opt-ins, aggregate signer/miner limits, burnchain bounds,
  and mutation leases remain authoritative.
- Agents and LLMs cannot supply executable content or terminal verdicts.
- Every trial, replay, and reduction attempt uses a fresh network UID and clean
  actor storage.
- Evidence capture and exact identity rechecks precede teardown.
- Missing evidence, drift, lease loss, capacity loss, or resume ambiguity can
  never produce `Clean` or `ConfirmedNetworkFailure`.
- Corpus entries are immutable and verified before reuse.
- A run classified as a harness failure cannot be promoted to a Stacks defect
  by log similarity or agent reasoning.
- Session and attempt limits are finite; there is no unbounded reconcile or
  retry loop.

## Verification strategy

### Offline tests

- golden cross-version vectors for deterministic weighted decisions;
- input-order, locale, map-order, and restart invariance;
- strict YAML/schema rejection and secret redaction;
- template drift, image drift, and advisory-input substitution rejection;
- advisory-object retention, corpus-only replay, and missing/corrupt object
  rejection;
- session journal crash points and idempotent resume;
- corpus atomicity, digest substitution, index rebuild, and retention policy;
- novelty fingerprint stability and free-form-log exclusion;
- fresh-name derivation and exact-UID teardown checks;
- reduction partitioning, dependency repair, bounds, and no-add/no-reorder
  properties;
- capacity arithmetic, escrow verification, and fail-closed unsupported
  storage handling;
- CLI command contracts and machine-readable output;
- Go fuzz tests for decoders, journal recovery, and reducer invariants.

Native Go fuzzing supplements deterministic unit vectors; it is not the
Attacknet experiment generator and does not replace live qualification.

### Envtest and integration tests

- optional run provenance is admitted, sealed, and immutable;
- a changed template or network identity blocks before child creation;
- the session Lease excludes a second writer;
- controller restart resumes the active ordinary `AttacknetRun`;
- reduction candidates remain valid v1beta1 resources;
- RBAC remains unchanged unless a narrowly justified typed resource is added.

### Live qualification

Qualification uses a fresh three-node arm64 `kind` cluster and must include:

1. identical descriptors from two independent same-seed planning runs;
2. a finite clean multi-trial session using at least four existing fault
   families, one A11 version cohort, and one A12 behavior template;
3. an exact template-drift negative control with zero cluster mutations;
4. a capacity-insufficient control that creates no network;
5. interruption and resume during network creation, active execution,
   evidence capture, and teardown;
6. one deliberately asserted network failure admitted to the corpus only after
   fresh-network confirmation;
7. one non-reproducing failure retained but not reduced;
8. one evidence-loss or Loki-failure control classified as harness failure or
   inconclusive with the network preserved;
9. hierarchical reduction producing a smaller confirmed reproducer;
10. an out-of-universe agent proposal rejected before mutation;
11. an accepted agent-assisted decision replayed using only its retained
    advisory object, with missing and substituted object controls;
12. corpus verification from a clean checkout plus the external artifact
    root; and
13. complete final teardown with no orphaned runs, campaigns, networks, PVCs,
    policies, leases, or reservation resources.

The live session must run long enough to cross controller restarts and at least
one burnchain boundary. It need not discover an unknown Stacks defect; the
qualified failure may be a deliberate protocol-assertion control whose origin
is clearly labeled.

## Implementation phases

### Phase 1: contracts and pure planner

What: freeze the fuzz-plan, session-descriptor, decision-receipt, journal,
corpus-entry, and semantic-fingerprint schemas.

Why: deterministic planning and later evidence review require stable,
reimplementable byte-level contracts before runtime work begins.

How: implement cohesive Go packages for strict documents, deterministic HMAC
selection, and canonical receipts. Reuse the existing canonical JSON package.

Definition of done: golden vectors, ordering controls, strict bounds, drift
checks, and documentation pass without Kubernetes.

### Phase 2: capacity and resumable session engine

What: add the session Lease, capacity admission and escrow, append-only journal,
fresh-network lifecycle, and idempotent resume.

Why: unattended testing is unsafe if two drivers compete, storage exhaustion
masquerades as a node defect, or a crash duplicates a mutation.

How: keep side effects behind small injected interfaces, journal intent before
mutation and observed identity afterward, and reuse typed CLI evidence and
teardown services.

Definition of done: crash-point tests and live controls prove one active
session, no duplicate trials, no mutation on insufficient capacity, and exact
identity-safe cleanup.

### Phase 3: seeded trial execution

What: materialize deterministic ordinary `AttacknetRun` trials from the sealed
template universe and execute a bounded session.

Why: this is the multiplier that composes A9 through A12 without weakening
their individual safety contracts.

How: submit only explicit controller-valid resources, bind session provenance
into schedules, and classify outcomes from controller status and trusted
assertions.

Definition of done: same-seed plans match byte-for-byte, different seeds
produce valid bounded variation, and drift or apparatus failures cannot become
network findings.

### Phase 4: corpus and confirmation

What: add content-addressed storage, semantic novelty, complete evidence
binding, and automated fresh-network confirmation.

Why: a fuzzing loop is useful only when failures survive teardown and can be
distinguished from duplicates and harness defects.

How: use immutable objects and rebuildable indexes, retain exact replay
commands, and admit only trusted repeated classifications to the confirmed
failure corpus.

Definition of done: corruption is detected, duplicate outcomes deduplicate
semantically, non-reproduction stays visible, and a clean checkout can verify
the corpus entry with its external artifacts.

### Phase 5: deterministic reduction

What: implement bounded hierarchical ddmin and optional advisory ranking.

Why: raw schedules are expensive to diagnose; a smaller confirmed reproducer
is materially more useful to maintainers.

How: generate only removal-only candidates, delegate one attempt at a time to
the existing controller contract, require fresh networks and repeated exact
classification, and retain the full reduction graph.

Definition of done: a multi-fault failure reduces mechanically, rejected and
inconclusive candidates remain visible, an agent cannot invent a candidate,
and no output claims causal minimality.

### Phase 6: product surface and release qualification

What: examples, CLI help, operations documentation, dashboards, evidence
export, live controls, baseline update, and amendment packet.

Why: unattended experiments must remain understandable to operators and
directly consumable by agents.

How: add one maintained fuzz-plan example and one corpus/reduction walkthrough,
validate all documentation links and examples, then run the Full-tier live
qualification.

Definition of done: every live requirement passes, operator and development
documentation matches the shipped surface, external evidence is portable and
digest-bound, and the dual review gate approves the exact signed candidate.
The Release 1 baseline references a tracked
`evidence-packets/release-1-a13/gate-result.json` that binds the candidate,
packet, contract, both verdicts, and external evidence digests. It must not
reference the local corpus or an ignored evidence path.

## Definition of done

R1A13 is complete only when:

- identical immutable inputs and seeds produce identical explicit run
  instructions;
- every choice is ordered, bounded, and recorded before execution;
- existing controllers remain the only fault, topology, and upgrade mutation
  authorities;
- only admitted templates and trusted triggers can be selected;
- cold-start capacity is admitted and cooperatively reserved for the qualified
  local profile;
- session restart cannot duplicate, skip, or silently reinterpret a trial;
- every adverse outcome is separated into network failure, inconclusive, or
  harness failure before corpus admission;
- confirmed failures reproduce on the configured number of fresh networks;
- corpus entries carry replay commands, complete provenance, assertions,
  evidence digests, retained advisory inputs, and reduction history;
- agent-assisted entries replay from their verified corpus objects without
  invoking an agent again;
- reduction is mechanically removal-only, bounded, and fresh-network
  validated;
- LLM advice can reduce scheduling churn but cannot authorize or prove a
  result;
- dashboards and static reports make active and historical sessions
  understandable to a human;
- clean, failed, inconclusive, preserved, and teardown states are distinct;
- the Release 1 capability claim binds a tracked gate result rather than local
  or ignored evidence; and
- the signed candidate, portable evidence packet, and both direct-read review
  verdicts close the Full-tier amendment gate.
