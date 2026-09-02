# R1A13: Seeded fuzzing, corpus management, and reduction

## Status

| Field | Value |
| --- | --- |
| Amendment | R1A13 |
| State | Approved for Release 1 on 2026-09-02 |
| Review tier | Full |
| Product claim | Supported within the local three-node arm64 `kind` scope |

The gate approved signed commit
`82efd989d71836322286d870cdb82be49c9db364`, candidate tree
`319b06f4cc009c63d72992d36bff696970197fb5`, and packet digest
`sha256:eeb4601eec1a186edb6d69c5f7f66b3abe1f7048bc82f9036f2e28c752787727`
under review ID
`release-1-amendment-a13-seeded-fuzzing-corpus-reduction`. The tracked
[`gate-result.json`](../../../../evidence-packets/release-1-a13/gate-result.json)
binds both complete direct-read verdicts and the external evidence archive.

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

For actor configuration, A13 enforces that boundary rather than relying on
operator convention: every external ConfigMap- or Secret-backed
`ConfigSource` requires `expectedDigest`, which the existing credential-free
init verifier checks before actor startup. Generated profiles and literal
advanced environment values are sealed by the network-template digest.
Advanced `valueFrom` environment sources are rejected because their content
has no admitted digest contract in R1.

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

The initial non-dry-run command re-reads every source template and policy before
constructing the mutation runtime. Namespace, name, UID, generation,
specification digest, and declared bindings must still match the descriptor; a
change fails before an experiment resource is created. Resume and corpus replay
do not repeat this source lookup because the source namespace is not a replay
dependency. Resume requires exactly one immutable `session-descriptor` artifact
in the session's planning record; advisory artifacts are retained alongside it
and cannot make descriptor selection positional or ambiguous.

Each attempt instead creates deterministically named, inert
`FaultCampaign` and `UpgradeCampaign` clones from the descriptor's exact
specifications. The materialized `AttacknetRun` catalog binds the observed UID,
generation, and specification digest of those attempt-local resources. Their
creation and deletion are journaled by immutable identity. This preserves the
initial authorization while allowing a retained session or corpus entry to
resume and replay after the original planning templates have been removed.

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

The initial decision algorithm is `hmac-sha256-fuzz-plan/v1`, and the resource
conversion algorithm is `attacknet-resource-materializer/v1`. Both identifiers
are sealed in the descriptor and must change when their output semantics
change. The decision algorithm uses domain-separated
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

Decision artifacts stay within the ordinary JSON safe-integer range. The typed
`StacksNetwork` snapshot is the exception because valid Kubernetes `int64`
fields, including genesis balances, can exceed that range. Its template and
session descriptor use a lossless, integer-only Go canonicalization path;
independent tooling must parse those integer tokens without converting them to
JavaScript floating-point numbers.

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
4. creates exact attempt-local policy and campaign-template resources and
   records their observed identities;
5. verifies runtime image constraints and binds the run catalog to the local
   template UIDs, generations, and specification digests;
6. submits the already materialized `AttacknetRun`;
7. captures evidence before any teardown;
8. rechecks the exact network UID and inventory digest; and
9. deletes only through the existing evidence-safe teardown boundary.

Failed, inconclusive, or apparatus-ambiguous attempts remain preserved until
their evidence policy is satisfied or an operator explicitly disposes of
them. Clean trials may be torn down automatically after complete evidence is
sealed.

## Capacity admission and cooperative reservation

A13 closes the Release 1 `cold-start-storage-reservation` gap for the qualified
dedicated local profile. It physically reserves storage and the cold-start
write burst, but only admission-gates and rechecks image-filesystem headroom.
Image-filesystem bytes remain unreserved, and this must not be described as a
portable cloud-storage or image-filesystem reservation guarantee.

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

If reservation succeeds but the durable `CapacityAdmitted` journal write
fails, the engine releases the unjournaled reservation synchronously. This
prevents a corpus-capacity failure from stranding local or PVC-backed escrow.

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
- admitted version-cohort digest.

Burnchain boundary classes and network-view counts remain useful retained
evidence, but the current `AttacknetRun` status does not expose bounded trusted
fields for them. R1A13 therefore does not include either value in its novelty
fingerprint. A later amendment may add them only with a typed, identity-bound
controller status source and corresponding negative controls.

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
├── reports/<session-digest>.json
└── audit/<operation>-<digest>.json
```

Objects are immutable and addressed by SHA-256. Entry manifests bind the
source and replay schedules, exact materialized campaign specifications,
network inventories, exact images, run and child statuses, incident bundle,
complete Loki export, decision receipts, classification, reduction graph, and
every advisory artifact consumed by a decision. Each advisory reference
records its object digest, decision domain, and receipt digest. Writes use
create-exclusive temporary files plus sync and rename. Existing objects are
accepted only after digest verification.

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
4. remove explicit actors from retained targets.

Automatic parameter reduction is deferred. The pre-existing manual
`RemovedParameters` API remains available for explicitly authored
minimization candidates, but R1 does not claim that fault parameters have
mechanism-registered monotone semantics.

Each candidate preserves source order and cannot add an execution, stage,
action, target, dependency, trigger, opt-in, or parameter. Safety budgets may
remain equal or become stricter; they cannot be relaxed. An empty candidate is
invalid.

The planner uses a versioned hierarchical ddmin algorithm, records every
partition and outcome, and submits candidates sequentially on fresh networks.
The maximum attempts, wall time, and evidence bytes are fixed in the session
descriptor. A candidate is retained only after satisfying the same bounded
confirmation policy as the source failure.

The production reducer has material-candidate tests for all four hierarchy
levels. R1 live qualification exercises execution-level removal; nested stage,
action, and actor removal are qualified offline rather than claimed as live
coverage.

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
attacknet fuzz lock status --corpus DIR
attacknet fuzz lock break --corpus DIR --expected-owner OWNER \
  --expected-process-id PID --expected-acquired-at RFC3339 --reason TEXT
attacknet fuzz lease status --corpus DIR --namespace NAMESPACE
attacknet fuzz lease break --corpus DIR --namespace NAMESPACE --expected-uid UID \
  --expected-resource-version RV --expected-holder HOLDER --reason TEXT
attacknet corpus list --corpus DIR --output json
attacknet corpus show --corpus DIR --output json FINGERPRINT
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

The human and agent surface follows the evidence ownership boundary rather than
copying workstation state into controller metrics.

Grafana shows live in-cluster facts: passed, failed, inconclusive, and
harness-attributed controller runs; current trial, phase, schedule digest,
fault lifecycle, admitted immutable version cohorts, burnchain context,
confirmation and reduction progress, actor drill-down, and observation-pipeline
health. These panels are operational views, not corpus classifications.

`attacknet fuzz status` verifies the local corpus and returns the decoded,
digest-bound static report; explicit zero-valued corpus classification counts;
capacity headroom and its immutable receipt; report and corpus-entry
references; and preservation, incomplete-evidence, or inconclusive-result
warnings. `attacknet corpus show` resolves the referenced entry. Capacity and
corpus objects stay on the operator workstation, so the in-cluster collector
does not claim them as Prometheus observations.

Agent interfaces consume JSON status, controller metrics, evidence manifests,
and corpus entries directly; screenshots are not evidence.

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

Implementation status as of 2026-09-02: Phases 1 through 6 are implemented,
qualified, and approved. Focused unit, race, strict-document,
compatibility-vector, envtest, Helm, RBAC, and whole-product tests pass.
Qualification found and
remediated capacity-escrow scheduler bypass, taint placement, renderer image-ID
parsing, workload-name length, API-invalid inert run controls, unsupported run
policy defaults, actor-dependent suspension status, namespace drift, and
referenced-run teardown. The live lifecycle also exposed legitimate status
resource-version churn during UID-bound cleanup and a missing binding between
the probe's logical Prometheus endpoint and the per-attempt evidence Service;
both now use immutable identities owned by the planner. Attempt-local campaign
clones also remove the source planning namespace from the replay dependency.
Interrupted corpora are retained as apparatus evidence; none is classified as
a Stacks defect. Evidence-capture resume qualification interrupts only after
the durable network-suspension record and proves the expected one-generation
transition under the same immutable network UID. The Full-tier live
qualification also found that Kubernetes 1.36 preserves Job Pods unless
deletion propagation is explicit; capacity-reservation teardown now requests
background garbage collection before deleting its PVCs. The Full-tier live
qualification also verified that abrupt termination can strand an unpublished
atomic-write temporary. Those bytes now live in a dedicated private pending
directory and are removed only after acquiring the corpus writer lock;
unexpected pending entries still fail closed. The Full-tier live qualification
then caught a qualification-plan projection that omitted the retained
advisory's trial ordinal; one strict helper now derives both required plan
fields from the retained advisory artifact. It also caught a qualification
fixture placing an external-configuration digest inside a Secret reference;
the digest is now bound at the strict v1beta1 `ConfigSource` layer. The
qualification's advisory seal now also preserves the production Go struct's
required empty `digest` field while computing its canonical digest, eliminating
a duplicate-view mismatch. Later live passes found Kubernetes null-pruning in
optional fault parameters, a stale adversarial-policy digest, legitimate
zero-byte log artifacts, and transient capture files placed in the semantic
session namespace. Later passes also encountered a transient API-server timeout
during Lease renewal and a positional-argument ordering error in the documented
corpus inspection command. It also caught duplicated imageID validators that
disagreed on Kubernetes' `repository@sha256:...` form. The runtime now
normalizes desired objects like the API
server, binds the exact behavior policy, distinguishes empty evidence from
missing bytes, keeps capture work under the corpus pending-write namespace, and
retries transient renewal errors only within the still-valid Lease window.
Fresh-network confirmation then exposed a forensic gap: a terminal
`ChildCampaignFailed` result retained the run summary but not the child
campaign status needed to explain it after teardown. Evidence capture now
binds the exact terminal `AttacknetRun` and every UID-bound terminal child
object in the external corpus. Large child evidence is deliberately not copied
into CR status. A longer-duration diagnostic reproduced the same harness
classification, so qualification did not tune timing or reinterpret the result
as a Stacks failure. The retained child then identified the deterministic
fixture defect: reduction templates targeted Prometheus while confirmation used
the minimal topology with no Prometheus workload. Those controls now target the
enrolled Bitcoin peer present in that topology, with a regression test pinning
the binding. A later controller-restart control exposed a false atomic-patch
conflict during network suspension: `metadata.resourceVersion` changes on
ordinary status writes. The exact suspension boundary now tests immutable UID
and spec generation instead, so status churn is tolerated while concurrent
spec changes and name reuse still fail closed. That pass then proved that a
suspended source network retained the namespace-wide active-environment Lease,
making its fresh confirmation network impossible to admit. Suspension now
retains the source CR and its replay identity, waits for an uncached read to
prove that every actor Pod has terminated, and only then releases its own Lease.
A missing or foreign Lease while source actor Pods remain is an apparatus
conflict; the controller never deletes a Lease owned by another network. Once
the fresh network became Ready, replay exposed a second incompatible invariant:
the scheduler required its fresh template objects to retain the source
templates' Kubernetes names and UIDs. Replay now compares the sealed logical
kind, alias, and template-spec digest while independently binding each fresh
clone's exact UID, generation, and digest at admission. Template specification
drift still fails before child creation. Serializing the same-probe controls
then exposed an unsound planner shortcut: it compared the number of templates
selectable *now* with the remaining execution count and ignored templates that
selecting a prerequisite would unlock. The bounded completion search now
explores those dependency states, with a multi-seed exact-chain regression.
The first removal attempt then exposed a digest-contract error: the reducer's
candidate digest identified retained removal instructions, but the run
controller compared it to the independently sealed fresh-network schedule.
Those artifacts cannot share a digest because the latter includes admitted
network identity. `candidateDigest` now binds only the canonical ordered
retained instructions; the authoritative resolved schedule continues to use
`status.scheduleRef.digest`. The controller recomputes both independently, and
a changed retained instruction is rejected before schedule publication. The
next live pass proved the controller path but exposed the retired candidate
digest formula in the release-evidence validator. The validator now checks the
same retained-instruction digest directly, and its regression rejects the old
whole-candidate formula. The preserved live graph reduced three executions to
one over two fresh attempts without changing the safety budgets. The following
non-reproduction control exposed an insufficient campaign-phase heuristic: the
source policy was never proven paused and the run correctly completed cleanly.
The control now waits for the run controller's sealed
`ProtocolRecoveryPending` baseline, requires the policy's observed Bitcoin
height to remain stable for five seconds, and retains that proof. The first
acknowledged pause advanced seven blocks after the recovery baseline, proving
that a short five-block threshold could still pass during controller
convergence. The final control requires 15 blocks over 60 seconds: normal
2-second cadence has twice that budget while the bounded acknowledged pause
cannot satisfy it.
Each finding failed closed without being classified as a Stacks defect. The
final Full-tier qualification passed all ten live assertions, retained a
portable corpus with eight entries and 663 objects, and left no owned network,
run, campaign, policy, PVC, Lease, or reservation resource. Codex and Claude
Opus 5 reviewed all 109 packet inventory items directly with no omissions and
approved the exact signed candidate.

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
into schedules, clone the sealed campaign specifications into exact
attempt-local inert templates, and classify outcomes from controller status
and trusted assertions. Initial execution preflights the original sources;
resume and replay consume retained materialized inputs.

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

Each attempt provisions a separately owned, exact-identity evidence plane only
after the fresh network has an admitted Ready inventory. Evidence is captured
before suspension, then the journaled evidence resources are removed before
the run and network are exact-deleted. This keeps evidence acquisition inside
the resumable state machine rather than depending on an unrecorded shared
installation.

Definition of done: corruption is detected, duplicate outcomes deduplicate
semantically, non-reproduction stays visible, and a clean checkout can verify
the corpus entry with its external artifacts.

Qualification pauses the source attempt's cadence policy only after the run
controller records the recovery assertion's exact `ProtocolRecoveryPending`
baseline. It then requires the policy controller to acknowledge the new
generation and report a stable Bitcoin height for five seconds while Pods and
trusted probes remain ready. The fresh confirmation receives the original
unpaused policy. This barrier makes the source-only condition observable,
prevents it from invalidating fault admission, and distinguishes a missed
control from a genuine non-reproduction.

The control uses the minimal topology's enrolled Bitcoin peer as its network
probe target. A harness-service target has no valid peer baseline in that
topology and correctly fails admission as `ProbeBaselineUnavailable`; such an
apparatus failure cannot be used to demonstrate non-reproduction.

Live crash/resume qualification also established that controller-owned
evidence and capacity resources cannot use `resourceVersion` as a deletion
identity: workload and storage controllers legitimately update status between
the final read and delete request. Their release paths therefore use an
API-server-enforced UID precondition. Human teardown retains the stricter
UID-plus-`resourceVersion` check where any concurrent network change must
preserve the environment for inspection.

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

Corpus-only replay qualification also exercises the longest generated attempt
identity. Actor and controller-managed observability workload names are
bounded to 52 bytes, leaving room for Kubernetes' generated revision hashes
inside 63-byte DNS-label values.

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
