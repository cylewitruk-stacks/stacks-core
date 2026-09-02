# Attacknet roadmap

This roadmap orders capabilities that are not part of the qualified Release 1
product. A roadmap entry is not an implemented capability merely because
Kubernetes, Chaos Mesh, Bitcoin Core, or an existing Attacknet API exposes a
related primitive.

The machine-readable source of truth for advertised capability remains
[`baseline-v1.json`](../../release/baseline-v1.json). Update that baseline only
after an amendment is implemented, qualified, and approved. Recording the
already-approved result is ordinary release bookkeeping; it does not require a
second qualification or review packet unless it expands or reinterprets the
approved claim.

## Release 1 amendment roadmap

The amendments below are ordered by expected value and dependency. Trustworthy
observations and evidence come before stronger faults; autonomous exploration
comes only after those faults are bounded, attributable, and replayable.

### A8: Trusted observations and forensic completeness

Status: approved for Release 1 on 2026-08-27. The Full-tier gate binds signed
commit `2481f75b49a44f151847b9f6a3a0139e6af3e4e0`, candidate tree
`a290da0ae24cbab58eb04dbad325dbaac51fb2e7`, review ID
`release-1-amendment-a8-trusted-observations`, and packet digest
`sha256:69211af52d11e9d01af323420ab6f39a92ca9c7582e25a382f7dda5776dd1585`.

Make the failure oracle and evidence record trustworthy before adding another
major fault mechanism. The approved A8 amendment adds direct, identity-bound
acquisition and a finite typed assertion vocabulary for height/progress, cohort
agreement, signer registration and state freshness, proposal-outcome
visibility, and telemetry completeness. It also makes complete retained Loki
export and a bounded incident capture a fail-closed network-deletion barrier.

The initial A8 vocabulary provides fresh, identity-bound observations for:

- Bitcoin and Stacks heights and progress;
- Bitcoin and Stacks cohort height agreement;
- signer registration and state freshness;
- proposal response visibility; and
- telemetry-source availability, freshness, and completeness.

The following richer protocol evidence remains future work and is not part of
the approved A8 claim. A9 subsequently added bounded Bitcoin branch-mutation
evidence, but did not retroactively expand A8's scope:

- Bitcoin height, best-block hash, chainwork, chain tips, and fork identity;
- Stacks height, index block hash, burn view, and equal-height divergence;
- signer available weight and node drift;
- proposal receipt, first response, threshold latency, rejection, and
  unavailable outcomes;
- miner and signer activity across reward-cycle and epoch boundaries;
- scenario-defined balances, supply, and transaction confirmation.

Normal teardown exports the complete retained Loki corpus and binds it to the
incident snapshot, controller status, runtime identities, run interval, and
artifact digests. Prometheus range export and a single combined archive for all
stores remain follow-up work; Grafana is a correlated human view and is never
the release oracle.

The small A8 qualification cohort deliberately remains before the configured
epoch transitions. Its follower-only actors can prove observation, progress,
cohort, failure, and recovery semantics, but cannot produce the PoX anchor
history required for a long-running Nakamoto network. Nakamoto liveness remains
a separate accepted-topology qualification and is not inferred from A8.

Definition of done:

- a missing, stale, or identity-mismatched evidence source produces
  `Inconclusive`, never `Passed`;
- the qualified assertion classes have deliberate negative controls proving
  violation and source-loss paths;
- loss of the observation bridge, metrics store, log store, or event exporter
  is detected rather than appearing healthy;
- the complete retained-log and review archives are independently
  digest-verifiable;
- live qualification proves both a clean baseline and an attributed failure.

### A9: Bounded Bitcoin reorganization campaigns

Status: approved for Release 1 on 2026-08-28. The Full-tier gate binds signed
commit `b93517c0090acfb0943789d6cf82ec40b7ce4357`, candidate tree
`fd7aecd3b979524cb1c61bb309ecdb65088e05e6`, review ID
`release-1-amendment-a9-bitcoin-reorganizations`, and packet digest
`sha256:4f647e1f459400f214b79c32a21577be15df80bfe998811fd1fa9de387f7f4f7`.
A9 is deliberately node-addressed and does not depend on A10; simultaneous
multi-follower split views remain A10 scope.

The approved A9 amendment adds `burnchain-reorg` as a first-class semantic
fault, distinct from a process or packet-level Chaos Mesh fault. It uses a
restricted Bitcoin Core regtest worker to replace a bounded suffix with a
longer, higher-work branch without exposing arbitrary RPC.

Its admitted contract seals:

- original tip, branch hashes, and chainwork;
- fork parent, depth, replacement length, and mining recipients;
- current PoX, epoch, and reward-cycle phase;
- exact RPC requests and acknowledgements;
- resulting canonical branch;
- Stacks rollback, divergence, and recovery observations.

Safety budgets bound fork depth and duration, forbid crossing an unspecified
epoch or reward boundary, require the mutation lease, and fail closed when the
observed branch differs from the sealed precondition.
`reconsiderblock` only removes a local invalidity marker; it is not proof that
the intended replacement branch remained canonical.

The approved gate establishes that:

- effect evidence proves the requested Bitcoin fork actually occurred;
- stale preconditions mutate no Bitcoin branch;
- Stacks miner, signer, and follower recovery is independently observed;
- the exact prior cadence policy is restored and a subsequent flash is proven;
- the same sealed seed and schedule reproduce the admitted outcome class on a
  fresh network; and
- complete forensic evidence and clean teardown are independently verified.

Application-specific transaction, balance, and supply invariants remain future
scenario assertions and are not part of the bounded A9 claim.

### A10: Multiple Bitcoin followers and split views

Status: approved for Release 1 on 2026-08-29. The Full-tier gate binds signed
commit `2debbcd747b4b406f6d7392515d71b3008da119b`, candidate tree
`7c46f087fd50832c976a3c0e41cdbbcaec05f8f5`, review ID
`release-1-amendment-a10-multi-bitcoin-split-views`, and packet digest
`sha256:974a46c34186702d5dbfdde13dde895e494d8b593f9c4ac424de25c8f2c7d16d`.

A single Bitcoin Core process tests Stacks reorganization handling but not
Bitcoin network partitions. Build on the typed Bitcoin-node topology and
Stacks-actor-to-Bitcoin-node bindings so cohorts can follow independent Bitcoin
nodes joined through an explicit regtest P2P graph.

Campaigns must be able to partition Bitcoin cohorts, delay propagation, or mine
bounded competing branches under a seeded work schedule. Honest Stacks actors
may hold genuinely different burnchain views until the Bitcoin graph heals and
higher-work selection converges.

Per-Bitcoin evidence must include:

- height, best-block hash, and chainwork;
- chain tips and peer graph;
- per-peer block and transaction receipt timing;
- the bound Stacks actor's burn-view hash and height.

Effect assertions must prove the requested split on both layers. Recovery must
prove every Bitcoin node selected the expected branch and every Stacks actor
converged without an unexplained canonical fork. Local RPC invalidation and a
distributed consensus split must retain different mechanism labels.

The dashboard must show Bitcoin P2P edges, partition cohorts, per-node branch
identity and chainwork, bound Stacks burn views, and a common divergence and
recovery timeline. Evidence must retain the exact partition and mining
schedule.

The approved gate establishes that:

- a small multi-Bitcoin cohort and the one-follower-per-Stacks-node topology
  both render and reconcile deterministically;
- partitions and competing branches are bounded by campaign safety policy;
- split-view effect and full recovery are proven independently on both layers;
- replay reproduces the admitted P2P graph, work schedule, and partition;
- teardown retains the complete per-node Bitcoin and Stacks evidence corpus.

### A11: Mixed-version and upgrade-boundary campaigns

Status: approved as
`release-1-amendment-a11-mixed-version-upgrades`. The hardware-signed candidate
is `f116da2964cab6e41896d27792cd74a2f9a333e0`; its approved packet digest is
`sha256:03e794fdee383cbcd78eb573a5dc36880796c48cec251d22e480dc1ea2321ff7`.
The gate qualified static mixed-version admission, boundary-aware staged
upgrades, rollback convergence, and a fresh same-seed replay on the local
three-node arm64 kind profile.

Qualify the existing per-actor image support as explicit compatibility and
missed-upgrade scenarios. Source profiles must accept arbitrary released tags,
commit SHAs, branches, local worktrees, and repositories or forks. Mutable refs
such as `main` are authoring conveniences only: preparation resolves them once
to an immutable commit and image identity before admission or replay.

Assignments may be explicit or deterministically selected from a seeded,
bounded distribution. This supports experiments such as one current-`main`
actor in a predominantly previous-release network, or one candidate fork revision in a
predominantly upstream-`main` network. The exact actor assignment is sealed
before any workload starts.

Initial scenario families should cover:

- current nodes with previous-release signers, and the inverse;
- minority and threshold-relevant cohorts that miss an epoch upgrade;
- gradual signer-set upgrades during a reward cycle;
- miner upgrades while signers remain old, and the inverse;
- restart, initial block download, and registration around activation
  boundaries;
- modified builds carrying candidate fixes alongside released binaries.

Git resolution and image building remain a client-side preparation workflow.
Kubernetes controllers must not clone arbitrary repositories or execute their
build scripts. Static matrices use existing per-actor image fields; in-place
upgrades require a typed topology-transition contract rather than direct
StatefulSet patches or an ordinary fault action.

Every run must record the complete source, build, configuration, and version
matrix and join each observation to the admitted runtime image digest rather
than to a mutable ref or image tag. See the
[`R1A11 implementation specification`](issues/r1/r1a11-mixed-version-upgrade-campaigns.md).

Definition of done:

- supported version combinations have deterministic, replayable scenarios;
- arbitrary remote or local Git refs resolve to sealed commits before build;
- explicit and seeded weighted actor assignments reproduce exactly;
- source, dirty patch, build inputs, image, configuration, and runtime identity
  remain joined for every actor;
- controllers never fetch or compile user-selected source;
- incompatibility is distinguished from telemetry loss and harness failure;
- epoch and reward-boundary placement is sealed in the run ledger;
- static missed-upgrade and bounded in-place upgrade scenarios are both
  supported without bypassing topology ownership or identity checks;
- dashboards and evidence identify every actor's exact runtime image;
- at least one expected-compatible and one expected-incompatible negative
  control are qualified.

### A12: Deterministic adversarial actors

Status: approved for Release 1 on 2026-08-31. The Full-tier gate binds signed
commit `6a6ea8363012173fc614fe8ddb40daa0695feddd`, candidate tree
`fe1580785298a0382900f8aff06fc7bb79965bd8`, review ID
`release-1-amendment-a12-deterministic-adversarial-actors`, and packet digest
`sha256:a734ee009c8881d9acc77bad6bdb8cc849e2573523618fd8cf7d680dc82c1d96`.
The bounded scope and implementation record are in the
[`R1A12 implementation specification`](issues/r1/r1a12-deterministic-adversarial-actors.md).

The approved testing-only signer behaviors are:

- selective vote withholding or delay;
- selective suppression of peer signer responses;
- deterministic selection by height, hash prefix, seeded ordinal, and bounded
  match/evaluation counts.

Conflicting or equivocating responses, stale-tenure or invalid-parent miner
proposals, malformed or oversized protocol inputs, and misleading state
reports remain future behavior-specific work. They are not implied by A12.

The approved A12 gate establishes:

- testing behavior is absent from normal signer images and inert until an
  identity-bound campaign session activates it;
- topology-owned default-deny egress permits only declared peers and DNS;
- a separately scheduled observer signs nonce-bound reports and identity drift
  or report forgery can never produce `Passed`;
- below-quorum withholding preserves progress while deliberate quorum loss is
  classified as a protocol violation despite successful fault injection; and
- fresh-network replay preserves the bounded policy outcome without claiming
  deterministic P2P selection, transport ordering, timing, hashes, or logs.

Future adversarial behavior families may include:

- conflicting or equivocating signer responses;
- stale-tenure and invalid-parent miner proposals;
- malformed, stale, or oversized protocol inputs;
- deliberately misleading local state reports;
- behavior activated at an exact burn height, tenure, actor, or message digest.

The qualified observer and restricted egress profile satisfy the initial
attribution and containment prerequisites. The actor's own counters remain
self-reported, so protocol consequences still require independent assertions;
a malicious actor is never the authority on whether its attack succeeded.

Definition of done:

- each behavior is enabled only in an explicitly modified testing image;
- image, policy, seed, trigger, and target are sealed before execution;
- independent observations prove both the attempted behavior and its effect;
- an actor cannot mutate Kubernetes or Attacknet control-plane state;
- deterministic replay reproduces the behavior without trusting actor logs;
- probe attribution and egress-policy negative controls pass.

### A13: Seeded fuzzing, corpus management, and reduction

Status: implementation and qualification in progress. The bounded scope,
architecture, implementation phases, and qualification contract are in the
[`R1A13 implementation specification`](issues/r1/r1a13-seeded-fuzzing-corpus-reduction.md).

Once burnchain faults and adversarial actors are bounded and attributable,
`AttacknetRun` can combine:

- Bitcoin reorganizations and view splits;
- flash-block cadence;
- epoch and reward-cycle boundary placement;
- mixed node and signer versions;
- Pod, network, DNS, disk, and application-clock faults;
- bounded modified actors.

Adaptive agents may choose only among admitted templates. Every decision must
be seeded, ordered, budgeted, and written to the sealed run ledger before
execution. No agent may issue an unrecorded Bitcoin RPC or raw Kubernetes
fault.

The campaign engine must retain novel failures in a corpus, replay each failure
on a fresh network, and mechanically reduce the schedule. An LLM may prioritize
likely contributors to reduce unnecessary trials, but every removal must be
validated by deterministic replay before it is accepted. Cold-start capacity
reservation must be implemented before long unattended runs so apparatus
resource exhaustion does not masquerade as a Stacks defect.

Definition of done:

- identical seeds and admitted inputs produce identical run instructions;
- safety budgets bound signer, miner, burnchain, duration, and concurrency
  impact;
- failing runs preserve their environment until forensic capture completes;
- corpus entries include a replay command, source and image provenance,
  assertion outcome, and evidence digest;
- fresh-network replay confirms a failure before reduction begins;
- mechanical reduction produces a causal candidate without claiming proof from
  LLM reasoning alone;
- clean, failed, inconclusive, and harness-failure outcomes are distinguishable.

## Backlog

These items remain valuable but are lower priority than A9 through A13 or rely
on infrastructure outside the qualified local Release 1 environment.

### Managed and x86-64 qualification

Release 1 is limited to local arm64 `kind`. Future qualification needs an
external x86-64, multi-node or multi-zone cluster with:

- immutable registry distribution and organization identity integration;
- native Chaos Mesh IOChaos and TimeChaos verification;
- autoscaler, maintenance, and worker replacement scenarios;
- Kubernetes policy and quota admission evidence;
- realistic control-plane and API-server failure modes.

This work remains deferred until that environment is available.

### Portable storage

The local profile uses node-local storage. It proves same-node recovery and
explicit stranding when a PVC cannot move. It does not prove portable or zonal
reattachment.

Future work needs a supported CSI implementation and multi-node or multi-zone
environment to test detach, reattach, node loss, delayed volume binding, and
chainstate integrity after relocation.

### Controller high availability

Both controllers are intentionally singleton and have no leader election.
Future HA work must prove lease ownership, handoff during reconciliation,
finalizer safety, schedule immutability, and absence of duplicate fault
execution before raising the replica count. This improves long-running
apparatus resilience but does not directly expand Stacks fault coverage.

### Operator experience and deployment hardening

The following remain product improvements rather than advertised capabilities:

- packaging a Kubernetes client matched to the server version;
- enterprise registry and identity-provider federation;
- managed-cluster installation and policy profiles;
- portable evidence storage and retention policies.

They should not delay the local protocol-fault roadmap unless they become a
prerequisite for truthful qualification.
