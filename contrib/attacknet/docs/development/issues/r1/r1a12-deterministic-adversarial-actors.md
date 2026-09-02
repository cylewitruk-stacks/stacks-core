# R1A12: Deterministic adversarial actors

## Status

| Field | Value |
| --- | --- |
| Amendment | R1A12 |
| State | Approved on 2026-08-31 |
| Review tier | Full |
| Product claim | Supported within the bounded behavior and trust model below |

The gate approved signed commit
`6a6ea8363012173fc614fe8ddb40daa0695feddd`, candidate tree
`fe1580785298a0382900f8aff06fc7bb79965bd8`, and packet digest
`sha256:a734ee009c8881d9acc77bad6bdb8cc849e2573523618fd8cf7d680dc82c1d96`.
The tracked [gate result](../../../../evidence-packets/release-1-a12/gate-result.json)
preserves the exact review and external-evidence bindings.

## Objective

R1A12 adds bounded signer behaviors that are deliberately compiled into a
testing-only image. A scenario must be deterministic, attributable to an
immutable actor identity, independently observable, and unable to reach the
Kubernetes control plane.

The first qualified behavior set is intentionally narrow:

- `withhold`: suppress this signer's own matching proposal response;
- `delay`: delay this signer's matching proposal response by a bounded amount;
- `suppress-peer-responses`: ignore matching responses received from other
  signers, creating a deterministic local-view divergence.

Equivocation, forged signatures, invalid miner proposals, arbitrary protocol
payloads, and fund-stealing behavior are outside R1A12. They require separate
protocol-specific amendments after the policy and evidence boundary is proven.

## Threat model and trust boundary

The modified actor, its logs, metrics, application endpoints, and filesystem
are untrusted. The actor may lie, omit events, serve fabricated telemetry, or
stop responding. It must not receive a Kubernetes service-account token or a
credential that can mutate Attacknet resources.

The trusted boundary consists of:

- the API server's admitted objects and immutable UIDs;
- the topology and run controllers using uncached identity reads at mutation
  and observation barriers;
- the sealed source, patch, build, configuration, image, and Pod identities;
- a topology-controller-owned observation workload running outside the adversarial
  actor Pod;
- corroborating signed protocol messages and honest-cohort observations.

Actor telemetry can support diagnosis but cannot prove that an attack occurred
or succeeded. Missing independent evidence produces `Inconclusive`, never
`Passed`.

## API model

### Topology policy

Each modified signer is declared through a typed adversarial policy on its
`SignerMemberSpec`. The policy contains:

- a versioned profile identifying the testing-image contract;
- exactly one behavior;
- a deterministic selector and activation window;
- a bounded match count and optional response delay;
- the expected testing-patch digest;
- the egress profile and any conspicuous escape hatch.

The topology operator validates and canonicalizes the policy, injects it into
the actor as immutable configuration, and includes its digest in the admitted
actor identity. Normal signer images have no implementation of this contract.
The API therefore cannot silently turn a production signer adversarial.

### Deterministic selectors

R1A12 supports selectors based only on proposal data already visible to the
signer:

- an inclusive Stacks-height interval;
- every Nth matching proposal with a seeded offset;
- a hexadecimal signer-signature-hash prefix.

Selectors compose conjunctively. An omitted selector matches every proposal in
the activation interval. Policy evaluation is pure and records its algorithm
version. Wall-clock-only activation is excluded because it is not replayable
across machines.

### Campaign execution

An adversarial action is represented by the `signer-behavior` fault mechanism.
It never patches a StatefulSet or changes the admitted image or policy. The
campaign instead:

1. proves the target Pod admitted the exact preconfigured policy digest;
2. verifies the requested action equals that policy;
3. waits on the existing trusted stage trigger;
4. rechecks one exact Ready signer Pod and activates a canonical, campaign-UID-
   bound session through a Pod annotation projected by a read-only Downward API
   volume;
5. records the trigger receipt and independently observes the bounded window;
6. removes the session and classifies effect and recovery without trusting
   actor logs.

This keeps the topology controller as the sole workload writer and prevents a
fault controller from converting an ordinary signer into a malicious one.

## Egress policy

Adversarial actor Pods receive a topology-owned default-deny egress
`NetworkPolicy`. The restricted profile permits only:

- DNS to the namespace's declared DNS endpoint;
- declared actor Services required by the topology;
- the admitted telemetry collector endpoint, when configured;
- controller-declared probe traffic needed for independent observation.

Raw CIDRs, the Kubernetes API, cloud metadata addresses, other namespaces, and
the public Internet remain denied. An explicit `unrestricted` profile is a
conspicuous scenario escape hatch and must be recorded in topology status,
evidence, and dashboards. It is never the default and cannot be qualified as
the strong adversarial-isolation profile.

The run controller receives no write verbs for `NetworkPolicy`, StatefulSet,
Service, PVC, or Secret resources. Its ConfigMap writes are limited to
controller-owned sealed schedules. Its existing bounded Pod patch permission
activates only the signer-session annotation after an uncached identity check.
The topology operator exclusively owns the egress policy and workload spec.

## Independent observation

The trusted observation workload is a separate Pod and network namespace, not
a sidecar in the adversarial actor Pod. It has no Kubernetes credential. Its
image and runtime Pod identity are admitted by the topology controller. The
run controller learns its ephemeral public key through a nonce challenge and
pins the key for that campaign window. Each bounded report contains a nonce,
observer identity, target identity, policy digest, observation interval,
result, and signature.

The controller verifies the report signature and rechecks the observer and
target Pod UIDs through its uncached API reader. Signed signer messages and an
honest node or signer cohort provide protocol corroboration. A valid observer
signature proves report provenance; it does not make an actor-supplied response
truthful.

The observer independently transports the testing counter, but that counter is
still actor-self-reported. It proves a policy attempt only when bound to the
admitted image, Pod, policy, nonce, and stable observer key. Network consequence
comes from identity-bound protocol assertions and honest-cohort observations.
For `suppress-peer-responses`, the target's local conclusion remains untrusted;
success requires a divergence visible from honest peers while the target
remains reachable.

## Safety invariants

- Adversarial policies may target signer actors only in R1A12.
- Every target must use an explicit image rather than the network default.
- Runtime image IDs must be immutable digests before campaign admission.
- The configured testing-patch digest must match the sealed build record.
- Delay is bounded to `1ms..120s`; longer delays require a future amendment.
- Match count is bounded to `1..1024`, evaluation count to
  `maxMatches..65536`, and selector modulus to `1..1024`.
- Aggregate affected signer weight uses the existing canonical reward-set
  resolver and campaign quorum-loss opt-in.
- Policy or Pod identity drift before or during the observation window fails
  closed and records the divergence.
- A normal image, absent policy, policy mismatch, unsigned observation,
  observer replacement, or incomplete recovery can never produce `Passed`.
- Deleting a campaign removes observation resources but never mutates actor
  configuration or adopts foreign resources.

## Evidence and replay

The sealed run descriptor records:

- source revision, dirty patch, testing-patch digest, Cargo features, build
  recipe, OCI image digest, configuration digest, and admitted Pod UID;
- canonical policy and policy digest;
- selector algorithm, seed, trigger receipt, bounded match counts, and
  actor-self-reported hash-bearing forensic logs;
- egress profile and admitted `NetworkPolicy` digest;
- observer Pod UID, runtime image ID, public key, nonce, signed reports, and
  verification result;
- honest-cohort protocol observations and terminal classification.

Replay requires the same resolved images, policy digest, seed, trigger inputs,
and observer contract. Outcome equivalence means the same bounded match count
and terminal classification; proposal hashes and wall-clock timestamps may
differ because a fresh network produces new blocks.

The seed controls the A12 policy selector and Attacknet scheduling inputs; it
does not seed the node's internal P2P or relay random generators. Operating
system scheduling, transport timing, and concurrent message ordering also
remain nondeterministic. R1A12 therefore does not claim byte-identical traces,
peer choices, block hashes, or timings. A relay-race experiment that requires
those decisions to repeat needs a future testing-only node RNG hook, recorded
decision replay, or repeated trials with a distribution-based assertion.

The Full-tier verifier applies the testing patch to the qualified source tree
and executes its five `stacks-signer` Rust tests with the `testing` feature.
Image compilation alone is not accepted as proof of the policy semantics.

## Implementation phases

### Phase 1: typed policy and pure evaluation

What: add the v1beta1 policy types, CEL and Go validation, canonical digest,
selector evaluator, and compiler support.

Why: a typed, immutable policy prevents free-form environment variables from
becoming an undocumented behavior API.

How: keep selector evaluation in a pure package, compile only normalized data
into the workload, and bind it into admitted identity.

Definition of done: schema rejection and Go validation agree; deterministic
vectors cover every behavior and selector; normal signers cannot declare the
policy implicitly.

### Phase 2: testing-only signer image

What: replace the prototype directive patch with a versioned policy evaluator
compiled only with the signer `testing` feature.

Why: Attacknet must not add runtime attack switches to production binaries.

How: retain the patch as a sealed build input, fail startup on malformed policy,
and emit bounded test metrics plus hash-bearing forensic logs.

Definition of done: all three behaviors pass Rust tests; without the testing
feature, the policy has no code path; unsupported policy versions fail startup.

### Phase 3: egress and independent observation

What: topology-owned egress policy plus separately scheduled signed observers.

Why: actor self-reporting and same-Pod probes are insufficient against a
malicious process.

How: render policies from admitted dependencies, isolate observer Pods, and
verify reports through controller-owned keys and uncached identity reads.

Definition of done: restricted actors cannot reach the API or undeclared
endpoints; permitted protocol traffic works; forged, replayed, or
identity-shifted reports are rejected.

Live qualification exposed and fixed one harness defect here: the first
restricted policy derived egress solely from startup dependencies. Because a
signer node waits for the signer's event endpoint, the reverse signer-to-node
relationship is deliberately not a startup dependency; the policy therefore
allowed DNS only and partitioned the signer from its node. The internal actor
model now represents permitted egress peers independently, deduplicates them
with startup dependencies, and binds the resulting `NetworkPolicy` digest into
admitted identity.

### Phase 4: campaign and run integration

What: add `signer-behavior` to the mechanism registry and existing staged run
scheduler.

Why: deterministic behavior must compose with A9/A10/A11 scenarios without a
second scheduler or workload writer.

How: compile an observation-only mechanism whose admission is bound to the
preconfigured actor policy, and reuse trigger receipts, leases, budgets,
identity barriers, assertions, and cleanup.

Definition of done: direct campaigns and `AttacknetRun` schedules replay;
aggregate signer-impact safety and partial-injection rollback remain enforced.

### Phase 5: product surface and qualification

What: examples, CLI validation, dashboards, evidence export, operator docs,
live positive scenarios, and negative controls.

Why: humans and agents need to distinguish attempted behavior, observed effect,
network consequence, telemetry failure, and harness failure.

How: add bounded labels and event timelines, retain raw signed reports in the
incident bundle, and qualify on the supported local three-node arm64 `kind`
profile.

Definition of done: one below-quorum behavior run recovers; one deliberate
quorum-loss run requires its opt-in; normal-image, policy-drift, egress, forged
report, and observer-replacement controls fail safely; replay reproduces the
bounded attempt count and classification.

Qualification preflight also exposed a lazy-metric initialization defect. A
configured testing signer emitted no labeled policy series until its first
proposal evaluation, so an independent observer could not distinguish a valid
zero baseline from missing instrumentation. The testing-only patch now creates
both bounded policy series at zero during process startup, before the metrics
server and signer runloop begin; a normal image still exports neither series
and therefore fails the capability check closed.

The first signed-report control exposed a second evidence-boundary defect: the
observer emitted a fractional `sampleWindowMs`, while the shared cross-runtime
canonical JSON contract deliberately admits integers only. Signer-behavior
reports now encode that elapsed duration as whole milliseconds, and the probe
contract test pins the integer representation. The verifier continues to fail
closed on fractional signed values instead of silently normalizing evidence.

The first scheduled run then exposed a second-source manifest defect. The run
controller compiled its signer-set view through the legacy actor projection,
which retained the policy digest but omitted the typed behavior. Schedule
admission therefore failed safely before creating a child campaign. The
v1beta1 scheduler now derives its canonical compiler manifest directly from
the v1beta1 network and overlays only independently observed signer weights;
the schedule and pre-injection parity check share that projection, and the
round-trip test derives rather than hand-writes the adversarial manifest.

The next run exposed a trigger timestamp ordering defect. The campaign
controller sampled its evaluation time before collecting protocol metrics, so
the trigger validator correctly rejected the newly collected Stacks height as
being in the future. The evaluator now samples `Now` after collection, a
regression test advances time inside the observation reader, and transient
observation failures retain their bounded diagnostic in campaign status.

That failed run also exposed a terminal-cleanup reconciliation defect. A
non-terminal child is deleted to invoke its cleanup finalizer, but the parent
then treated the expected absence as lost identity because its durable active
receipt had not yet been cleared. Missing active children still fail closed
while a run is active; terminal reconciliation now accepts absence after the
child cleanup barrier and can complete and release its own finalizer.

The first successful behavior campaign exposed a signer-set receipt omission.
The v1beta1 run scheduler enforced canonical reward-set weights, but its child
campaign recomputed impact from declared weights and did not persist the
canonical signer-set digest in admission status. Campaign admission now reads
the same canonical reward set independently, compiles with those weights,
records its reward cycle, total weight, digest, and observation source, and
fails closed if that signer set changes after admission.

That campaign then exposed a fixture-shaped evidence-validator defect. The
production signed report carries its nonce in the signed top-level payload,
while the unit fixture had incorrectly nested it under `attestation`; the
validator consequently rejected three genuine, distinct nonces. The fixture
now matches the production schema, the validator reads the signed top-level
nonce, and a repeated-nonce negative control proves replay detection remains
load-bearing.

The first quorum-loss run exposed an evidence-retention race. A violated
protocol assertion made the parent terminal immediately, so terminal cleanup
deleted the still-running child before it could finish bounded recovery and
retain its signed report triplet. A terminal protocol verdict is now persisted
immediately, blocks all new executions, and waits for already-running bounded
campaigns to finish recovery before finalizing the run. The run still cannot
become `Passed`; it becomes `Failed` or `Inconclusive` from the retained verdict
after the child has produced durable evidence, removed its mutation, and the
post-fault protocol-recovery assertions have completed.

The fresh-network replay exposed an unattributable admission failure at a
reward-cycle transition. One generic `AdmissionInputChanged` message covered
network, campaign, signer-set, and compiled-plan drift, making the retained
evidence insufficient to identify the changed input. Admission verification
now reports each field independently and reports signer-set drift before its
derived plan digest. Qualification also requires the current and next reward
cycles to expose the same canonical three-signer identity-and-weight digest
before submitting a run, and retains that continuity receipt for both the
primary and replay networks.

The same admission evidence exposed a safety-accounting defect: the canonical
signer-set receipt reported total weight eight while aggregate campaign impact
reported sixteen. The aggregate denominator had counted a signer and its bound
Stacks node as two weights even though they are one signer-impact unit. Shared
signer indexes are now deduplicated exactly as the single-action compiler does,
with a regression test covering the signer/node pair. This prevents the
aggregate basis-point calculation from understating quorum impact. With the
correct denominator, live schedule admission rejected the original 12.5%
scenario budget because the smallest observed signer carried one seventh
(14.3%) of canonical weight. The below-quorum qualification budget is now 20%,
which remains below the 30% quorum-loss boundary and accommodates the observed
reward-set weight variation without bypassing canonical accounting.

That early schedule rejection also exposed a runner diagnostic delay: the
parent run was already terminal without creating a child campaign, but the
runner waited ten minutes for that impossible child. It now snapshots the
terminal parent first and fails immediately with its phase, reason, and message
when no child exists.

The first fully instrumented live run then exposed a false activation model.
The controller created a `SignerBehaviorSession` evidence marker, but the
testing signer consumed only its startup policy and could exhaust its bounded
matches before the scheduled campaign. The marker therefore did not control
the behavior it claimed to observe. The policy is now inert at startup. One
exact signer per action receives a campaign-bound Pod annotation projected by
a read-only Downward API volume; signed samples prove inactive baseline,
active effect with a counter delta, and inactive recovery. Tests bind the Pod
UID, annotation payload, projection, removal, and testing-only Rust behavior.

The corrected live run then exposed a cache-ordering race during recovery. The
controller removed the watched Pod annotation before its `Recovering` status
write became visible to the informer cache, so an annotation event could be
reconciled against stale `Active` state and appear to be contract tampering.
Recovery now uses a durable two-step barrier: persist `Recovering` first, then
remove the annotation on the next reconcile. A regression test proves the
annotation remains present at the phase transition and is removed only after
the recovery phase is established.

The next qualification run exposed a post-admission classification defect.
Changing an admitted signer's policy was rejected with zero mutations, but
current-manifest compilation ran before the admission binding and reported
`CampaignInvalid` instead of identifying the changed admitted input. A
campaign that compiled successfully at admission now reports any subsequent
compilation failure as `AdmissionInputChanged`; invalid campaigns which were
never admitted continue to report `CampaignInvalid`. A regression test changes
the admitted policy digest and pins the fail-closed classification.

The following positive run exposed a projected-volume recovery bound and an
idempotency defect. The Pod annotation was removed after the durable recovery
barrier, but kubelet had not yet refreshed the Downward API file when the
90-second evidence deadline expired. Terminal cleanup then treated the already
removed session as contract tampering and could not finalize. Qualification
now allows 180 seconds for projected-volume propagation. Shared signer-session
and clock-policy cleanup accepts the expected restored contract in any
post-active phase while still rejecting contract changes during injection or
active execution; a regression test covers both sides.

The next live step exposed a qualification-fixture defect before cluster
mutation: the quorum-loss template grouped two signers into one action even
though signer-behavior attribution requires exactly one signer per action.
The template now uses two concurrent, independently attributable actions and
budgets both active faults and their cumulative duration. An offline contract
test runs every checked-in qualification resource through the production typed
CLI decoder so an invalid live fixture cannot escape normal verification.

A faster cached image build exposed a second qualification timing dependency.
The normal-image control was submitted before the configured Nakamoto/PoX-4
boundary, where `/v2/pox` first returned an opaque database-overflow response
and then correctly reported that the signer set was not yet fetchable. This
made the campaign admission timeout include deterministic protocol bootstrap.
Qualification now proves the same three-signer identity-and-weight digest for
the current and next reward cycles before submitting the control, and retains
that continuity receipt in its evidence. The same precondition is established
once immediately after admitting the primary network, before any direct
signer-attributed negative control or scheduled campaign; otherwise the
policy-drift control could encounter the identical pre-PoX-4 ambiguity.

The first two-signer quorum-loss run then exposed a recovery dependency on a
future reward-set observation. Both behavior sessions became active, the
parent detected the expected protocol violation, both sessions were removed,
and Stacks progress resumed. Before recording recovery, however, the campaign
reconciler re-read the then-current reward set. A transient
`PoXAnchorBlockRequired` response left both actions in `Recovering` even though
their bounded mutations had ended. Campaign admission now retains the
canonical actor weights in its immutable signer-set receipt. Once every action
is post-active, recovery reconstructs the compilation view from that receipt;
admission and active execution still require the live canonical resolver, and
all uncached Pod and image identity checks remain in force. Campaigns admitted
before this receipt existed retain the previous live-resolution behavior.

That run then reached recovery without the RPC loop but exposed stale actor
telemetry. The testing signer refreshed its session-active gauge only while
handling a proposal or peer response. Deliberate quorum loss stopped that very
traffic path, so the removed annotation eventually produced an empty projected
file while the last gauge sample remained `1`; bounded recovery correctly
ended `Inconclusive`. The testing-only signer now runs a named, 500 ms session
monitor that reads the projected contract independently of protocol traffic.
The production image contains neither the monitor nor the policy code. A Rust
regression vector proves that an absent projected value clears activity, and
live qualification must still prove both independently attributable signers
transition from active to inactive.

The first post-sign packet assembly then rejected the otherwise qualified
candidate because its scope allowlist omitted `.gitattributes`, which A12
changes to preserve the deterministic signer patch byte-for-byte. Packet scope
now permits that exact repository-root file and a regression test proves it is
included. This failure confirms that packet assembly must be exercised before
the final signing request; signature verification alone is not packet
qualification.

## Amendment completion

R1A12 is complete only when:

- every phase definition of done is satisfied;
- full offline, race, envtest, render, RBAC, and product checks pass;
- live evidence proves the positive and negative controls on a fresh network;
- teardown leaves no owned workload, observer, policy, or chaos resource;
- operator and development documentation match the admitted API;
- an immutable Full-tier packet binds the signed candidate, qualified tree,
  evidence archive, contract, source inventory, and complete direct-read
  verdicts from Codex and Claude Opus 5.
