# Attacknet roadmap

This roadmap orders capabilities that are not part of the qualified Release 1
product. A roadmap entry is not an implemented capability merely because
Kubernetes, Chaos Mesh, Bitcoin Core, or an existing Attacknet API exposes a
related primitive.

The machine-readable source of truth for advertised capability remains
[`baseline-v1.json`](../../release/baseline-v1.json). Update that baseline only
after an amendment is implemented, qualified, and approved.

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
the approved A8 claim:

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

Implement `BurnchainReorg` as a first-class semantic fault, distinct from a
process or packet-level Chaos Mesh fault. Bitcoin Core regtest exposes
`invalidateblock` and `reconsiderblock`, allowing a controlled single-node
campaign to invalidate a bounded suffix and mine a longer replacement branch.

The campaign must not expose arbitrary Bitcoin RPC. Its admitted contract must
seal:

- original tip, branch hashes, and chainwork;
- fork parent, depth, replacement length, and mining recipients;
- current PoX, epoch, and reward-cycle phase;
- exact RPC requests and acknowledgements;
- resulting canonical branch;
- Stacks rollback, divergence, and recovery observations.

Safety budgets must bound fork depth and duration, forbid crossing an
unspecified epoch or reward boundary, require the mutation lease, and fail
closed when the observed branch differs from the sealed precondition.
`reconsiderblock` only removes a local invalidity marker; it is not proof that
the intended replacement branch remained canonical.

Definition of done:

- effect evidence proves the requested Bitcoin fork actually occurred;
- Stacks rollback and reprocessing are observed independently;
- miner and signer behavior during the reorganization is classified;
- scenario-defined transaction, balance, and supply invariants are checked;
- recovery proves convergence on the intended Bitcoin and Stacks branches;
- the same sealed seed and schedule reproduce the campaign on a fresh network.

### A10: Mixed-version and upgrade-boundary campaigns

Qualify the existing per-actor image support as explicit compatibility and
missed-upgrade scenarios. Initial scenario families should cover:

- current nodes with previous-release signers, and the inverse;
- minority and threshold-relevant cohorts that miss an epoch upgrade;
- gradual signer-set upgrades during a reward cycle;
- miner upgrades while signers remain old, and the inverse;
- restart, initial block download, and registration around activation
  boundaries;
- modified builds carrying candidate fixes alongside released binaries.

Every run must record the complete version matrix and join each observation to
the admitted runtime image digest rather than to a mutable image tag.

Definition of done:

- supported version combinations have deterministic, replayable scenarios;
- incompatibility is distinguished from telemetry loss and harness failure;
- epoch and reward-boundary placement is sealed in the run ledger;
- dashboards and evidence identify every actor's exact runtime image;
- at least one expected-compatible and one expected-incompatible negative
  control are qualified.

### A11: Multiple Bitcoin followers and split views

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
- header and block receipt timing;
- the bound Stacks actor's burn-view hash and height.

Effect assertions must prove the requested split on both layers. Recovery must
prove every Bitcoin node selected the expected branch and every Stacks actor
converged without an unexplained canonical fork. Local RPC invalidation and a
distributed consensus split must retain different mechanism labels.

The dashboard must show Bitcoin P2P edges, partition cohorts, per-node branch
identity and chainwork, bound Stacks burn views, and a common divergence and
recovery timeline. Evidence must retain the exact partition and mining
schedule.

Definition of done:

- a small multi-Bitcoin cohort and the one-follower-per-Stacks-node topology
  both render and reconcile deterministically;
- partitions and competing branches are bounded by campaign safety policy;
- split-view effect and full recovery are proven independently on both layers;
- replay reproduces the admitted P2P graph, work schedule, and partition;
- teardown retains the complete per-node Bitcoin and Stacks evidence corpus.

### A12: Deterministic adversarial actors

Add testing-only, deterministic behaviors beyond process and network outages.
Candidate behaviors include:

- selective vote withholding or delay;
- conflicting or equivocating signer responses;
- stale-tenure and invalid-parent miner proposals;
- selective relay and message suppression;
- malformed, stale, or oversized protocol inputs;
- deliberately misleading local state reports;
- behavior activated at an exact burn height, tenure, actor, or message digest.

Cryptographically attributable active probes and per-scenario actor egress
policy are prerequisites for strong claims about malicious actors. Egress
should be restricted by default with an explicit, recorded scenario escape
hatch. A malicious actor must never be the authority on whether its own attack
succeeded.

Definition of done:

- each behavior is enabled only in an explicitly modified testing image;
- image, policy, seed, trigger, and target are sealed before execution;
- independent observations prove both the attempted behavior and its effect;
- an actor cannot mutate Kubernetes or Attacknet control-plane state;
- deterministic replay reproduces the behavior without trusting actor logs;
- probe attribution and egress-policy negative controls pass.

### A13: Seeded fuzzing, corpus management, and reduction

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
