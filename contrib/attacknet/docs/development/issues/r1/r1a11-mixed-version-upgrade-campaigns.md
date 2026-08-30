# R1A11 mixed-version and upgrade-boundary campaigns

| Field | Value |
| --- | --- |
| Status | Implementation in progress; offline controller and CLI verification complete |
| Release | R1 |
| Amendment | A11 |
| Product claim | Not supported until qualified and recorded in the Release 1 baseline |

## What and why

A11 makes arbitrary Stacks Core revisions reproducible network participants.
An operator can place a released version, upstream branch, exact commit, local
worktree, or fork revision into any bounded actor cohort and can exercise both
static missed-upgrade topologies and controlled in-place upgrades near protocol
boundaries.

The result must answer four different questions independently:

1. Which source and configuration was requested?
2. Which immutable image was built and loaded?
3. Which image and configuration did each admitted Pod actually run?
4. Was the observed network outcome compatible, incompatible, or unmeasurable?

Real deployments combine released, outdated, current-development, and
operator-modified binaries. Testing only a hardcoded current/previous pair
would miss the fork, branch, candidate-fix, and forgotten-upgrade combinations
that A11 exists to exercise.

## Dependencies

- Existing `StacksNetwork` per-actor image and configuration selection.
- The typed Go CLI image build, content tagging, `kind` import, and runtime
  identity verification.
- A8 identity-bound observations, protocol assertions, and evidence-safe
  teardown.
- Portable instrumentation capability declarations for revisions that do not
  expose current metrics.

A9 and A10 scenarios may compose with mixed versions, but neither is required
to implement the core A11 source, assignment, or upgrade workflow.

## Scope and non-goals

A11 includes:

- arbitrary trusted repositories, forks, tags, branches, and commit SHAs;
- clean or explicitly dirty local Git worktrees;
- immutable prebuilt images;
- explicit and seeded weighted actor assignments;
- version-specific node and signer configuration;
- static mixed-version networks and bounded rolling upgrades;
- epoch and reward-cycle boundary placement;
- exact provenance, dashboards, replay, and forensic evidence.

A11 does not make arbitrary source safe. A selected repository may contain a
malicious Dockerfile, `build.rs`, dependency, or build script. Source
preparation is an explicit operator-authorized local action and is outside the
Kubernetes controller trust boundary. Supply-chain attack simulation remains
out of scope.

## Implementation approach and boundaries

- The typed Go CLI resolves source, prepares worktrees, builds images, imports
  images, and emits provenance receipts.
- Kubernetes controllers consume immutable image references and provenance;
  they never clone repositories, resolve branches, or compile source.
- The topology operator remains the sole writer of actor StatefulSets,
  Services, ConfigMaps, and admitted inventory.
- The run operator schedules intent and observes outcomes. It must not patch
  actor StatefulSets directly.
- Mutable Git refs and image tags are never replay identities.
- Missing instrumentation is a declared image capability, not proof of
  protocol incompatibility.
- Actor logs cannot prove their own source or runtime identity.

## Source profiles

The preparation input is human-authored YAML accepted by the typed CLI. It
expresses these profile forms:

| Source kind | Required input | Sealed result |
| --- | --- | --- |
| Remote Git | Repository URL and tag, branch, or SHA | Canonical repository identity and exact commit |
| Local Git | Repository path and ref or current checkout | Exact commit, tree, dirty patch, and untracked-content digest |
| Prebuilt | Immutable OCI digest or content-addressed local image | Platform manifest, config, and runtime-resolvable identity |

The maintained example is
[`stable-with-candidate.plan.yaml`](../../../../examples/matrices/stable-with-candidate.plan.yaml).

This is a preparation document, not a Kubernetes custom resource. Its output
is a canonical JSON descriptor suitable for hashing and replay.

### Reference resolution

Preparation must:

1. canonicalize the repository locator without embedding credentials;
2. resolve the requested ref to one 40-character commit;
3. fetch or materialize only the sealed commit and required submodules;
4. refuse a ref that moves between resolution and checkout;
5. reject an unexpected commit when `expectedRevision` is supplied;
6. record whether the source was remote, local-clean, local-dirty, or prebuilt;
7. preserve a dirty patch and untracked-content digest without copying secrets
   into the public descriptor.

Replay uses the sealed commit and image. It never resolves the requested
branch or tag again.

## Build and image provenance

Each built profile records:

- canonical repository identity, requested ref, resolved commit, and tree;
- submodule revisions where applicable;
- dirty patch and untracked-content digests;
- Dockerfile scope and digest;
- one canonical build-input digest covering the selected source, build plan,
  build arguments, Cargo features or profile, submodules, and platform;
- the selected platform's runtime image-config identity and a build digest
  joining that identity to the build inputs; and
- import receipt from every target `kind` node.

The R1 descriptor does not independently inventory the builder toolchain, OCI
index, platform-manifest digest, or resolved base-image layers. Those facts
remain in the local Docker content store but are not portable release evidence
until registry-backed image publication is implemented. The output config
identity and all available input digests remain sufficient to reject stale or
substituted local bytes during this release's local-kind workflow.

Builds use isolated content-addressed worktrees and the Attacknet image
pipeline. A build failure is `BuildFailed`, not network incompatibility. The
pipeline should reuse cargo-chef and BuildKit caches by source/build key while
keeping `CARGO_INCREMENTAL=0`.

No credential value, authenticated repository URL, Secret content, or private
patch content belongs in Kubernetes status or a public evidence summary.

Build recipes may be source-scoped or explicitly host-scoped. Host scope lets
an old release use the current Attacknet Dockerfile without pretending that
the file existed in the selected revision. The trusted recipe root, scope, and
exact Dockerfile digest are sealed separately from the selected source tree.

## Assignment model

Assignments operate on the finite actor inventory produced from the intended
`StacksNetwork` topology. They support:

- exact actor names;
- bounded roles and signer sets;
- role-filtered weighted basis-point distributions;
- a default profile plus explicit overrides; and
- seeded weighted distributions.

Selection uses a versioned deterministic algorithm and canonical actor order.
The preparation result records the seed, algorithm, candidate set, decisions,
and final actor-to-profile mapping. It rejects duplicate assignments,
nonexistent actors, and invalid or overcommitted weighted distributions.
Signer and signer-node actors remain independently assignable so a scenario
can deliberately exercise mismatched versions.

A seeded assignment is resolved before the network starts. Controllers consume
the resulting explicit map; they do not make random choices during reconcile.

## Configuration compatibility

An image alone is not a runnable version profile. Each profile also binds node
and signer configuration inputs or a versioned configuration renderer.

Before deployment, preparation must run the strongest parser available in the
target image against the exact rendered configuration. If a historical binary
has no offline parser, use a bounded non-networked startup smoke and label the
weaker evidence explicitly. Configuration Secret content remains private, but
its source identity and digest are sealed.

An actor/profile assignment may instead supply a complete raw ConfigMap- or
Secret-backed configuration. This lets miners, signer nodes, and signers share
one executable profile without pretending their configuration is identical.
It is the compatibility escape hatch when an older or modified binary cannot
consume the current generated profile.
Omission preserves the actor's existing configuration. The exact config bytes
and smoke result remain digest-bound; accepting a raw config must not turn a
configuration failure into a protocol result.

Outcomes remain distinct:

| Outcome | Meaning |
| --- | --- |
| `BuildFailed` | Source could not produce the requested image |
| `ConfigurationUnsupported` | The image rejected its assigned configuration |
| `AdmissionFailed` | Kubernetes could not admit the requested immutable image or workload |
| `StartupIncompatible` | The admitted process could not initialize in the scenario |
| `ProtocolIncompatible` | Independent protocol assertions proved incompatibility |
| `TelemetryUnavailable` | Required evidence was absent or unsupported |
| `HarnessFailed` | Attacknet could not execute or observe the experiment correctly |

None may be collapsed into a generic expected failure.

## Static and transition scenarios

Static missed-upgrade scenarios use the existing per-actor image fields on
`StacksNetwork`. The topology is rendered once from the explicit resolved
assignment.

In-place upgrades use a typed `UpgradeCampaign` scheduled by `AttacknetRun`.
The upgrade reconciler owns rollout state and the topology reconciler consumes
its cumulative overlay; the topology reconciler remains the sole StatefulSet
writer. One run may execute one upgrade campaign containing multiple stages.
Deleting the campaign always restores its admitted baseline. A failed campaign
either rolls back immediately or preserves the failed state for triage,
according to `rollbackOnFailure`.

The architecture decision compared:

1. an `UpgradeCampaign` child type integrated into the run execution DAG;
2. a topology-owned version-plan resource referenced by a run; and
3. a new `StacksNetwork` generation per phase.

`UpgradeCampaign` was selected because it supports persistent cumulative
upgrades, explicit rollback, one writer for workload desired state, and
deterministic replay without turning an upgrade into a fault. A new
`StacksNetwork` generation per phase would lose one durable transition record;
a separate version-plan resource would duplicate the campaign lifecycle.
Fail-closed inventories recognize only exact actor identity changes authorized
by the sealed transition.

Transition safety includes:

- maximum simultaneous unavailable signer weight and miner count;
- maximum parallel actor replacements;
- signer and signer-node ordering policy;
- readiness, registration, and protocol gates between batches;
- explicit continue, stop, rollback, and pause-for-triage policies;
- a bounded deadline for every replacement and recovery gate.

## Boundary placement

Upgrade execution can trigger from trusted burn height, Stacks height, elapsed
time, a finite trusted observation, or a prior execution transition. Reward
cycle and epoch placement use an exact burn-height trigger derived from the
admitted `BurnchainPolicy` protocol schedule; evidence retains that policy and
the observed height. If the schedule is unknown, the scenario is
`Inconclusive`; it does not guess.

Required initial families are:

- current nodes with previous-release signers, and the inverse;
- a minority or threshold-relevant cohort missing an epoch upgrade;
- gradual signer and signer-node upgrades during a reward cycle;
- miner-first and signer-first upgrades;
- restart, IBD, registration, and state recovery around activation;
- a candidate fix or fork revision in a predominantly released or upstream
  network.

## Evidence and observability

Every actor observation joins:

- logical actor, role, signer set, and weight;
- source profile and compatibility expectation;
- resolved commit, source tree, build, and configuration digests;
- requested immutable image and admitted runtime image ID;
- Pod UID, controller revision, node, and observation time;
- current transition batch and before/after inventory digest.

Dashboards show cohort colors by profile, exact revision and runtime image on
drill-down, transition progress, unavailable signer weight, epoch/reward-cycle
position, and protocol/telemetry outcomes separately. Mutable tags may be
shown as labels but never used for joins or verdicts.

Incident evidence retains resolver, build, node-import, configuration-smoke,
assignment, trigger, transition, admitted-inventory, metrics, logs, and
terminal-classification artifacts. A missing join makes the applicable claim
`Inconclusive`.

## Verification strategy

Offline coverage includes:

- ref resolution, moved-ref rejection, expected-revision mismatch, and
  credential redaction;
- clean, dirty, fork, tag, branch, SHA, and prebuilt profiles;
- deterministic explicit and seeded assignments with negative controls;
- build and node-import identity substitution rejection;
- version-specific configuration acceptance and rejection;
- upgrade compilation, batching, budgets, rollback, resume, and replay;
- CRD/CEL, controller-runtime, RBAC, ownership, and reconciliation tests;
- dashboard and evidence contract tests.

Live qualification includes at least:

1. a fresh three-node arm64 kind cluster with the pinned Chaos Mesh dependency
   admitted and Ready before the Attacknet controllers start;
2. a compatible static matrix with one current revision in a released
   majority;
3. a compatible candidate-fork revision in an upstream-main majority;
4. a bounded rolling upgrade crossing a known reward or epoch boundary;
5. a protocol-assertion negative control that cannot be credited as compatible,
   without claiming a particular revision is incompatible unless an audited
   incompatible pair is available;
6. a configuration incompatibility control;
7. a telemetry-loss control that remains distinct from incompatibility;
8. replay on a fresh network using sealed commits and images;
9. complete incident capture and clean teardown.

## Implementation phases

### Phase 1: Source and compatibility inventory

Status: complete.

Audit supported revisions, build inputs, configuration differences,
instrumentation availability, and current image-assignment evidence. Freeze
the profile and outcome vocabularies.

### Phase 2: Preparation pipeline

Status: complete. Offline verification and live image preparation both passed.

Implement typed YAML decoding, Git resolution, content-addressed worktrees,
build/import receipts, configuration smokes, explicit assignments, and seeded
distribution. Emit one immutable canonical JSON matrix descriptor.

### Phase 3: Static mixed-version qualification

Status: complete. The admitted static cohort contained distinct released and
candidate runtime image identities.

Render `StacksNetwork` YAML from the descriptor, bind expected profiles to
admitted runtime identities, add dashboards and evidence, and qualify static
missed-upgrade scenarios.

### Phase 4: Typed upgrade orchestration

Status: complete. Live identity transitions, staged rollout, rollback, and
fresh-network replay passed.

Record the architecture decision, implement the selected topology-owned
transition API and controller, integrate it into the run DAG, and prove safety,
rollback, identity transitions, resume, and replay.

### Phase 5: Boundary scenarios and release evidence

Status: complete. The signed candidate
`f116da2964cab6e41896d27792cd74a2f9a333e0` was approved as
`release-1-amendment-a11-mixed-version-upgrades`; the review packet digest is
`sha256:03e794fdee383cbcd78eb573a5dc36880796c48cec251d22e480dc1ea2321ff7`.

Run compatible and incompatible controls at sealed boundaries, retain complete
forensics, update operator documentation and the Release 1 baseline, and
prepare the material amendment evidence packet.

## Definition of done

A11 is complete only when:

- arbitrary remote and local refs resolve to immutable source profiles;
- a user can place `main` or a fork revision into a predominantly released or
  upstream-main network without manual provenance reconstruction;
- seeded and explicit assignments replay exactly;
- build, configuration, requested image, admitted image, and runtime identity
  remain joined per actor;
- controllers never fetch or build source;
- static and in-place upgrade scenarios preserve topology ownership and
  fail-closed identity guarantees;
- expected incompatibility, configuration failure, telemetry loss, and harness
  failure are independently classified;
- epoch and reward-cycle placement is sealed and observable;
- dashboards and incident evidence explain every actor and transition;
- compatible, protocol-negative, source-drift, evidence-loss, replay, and
  teardown controls pass.
