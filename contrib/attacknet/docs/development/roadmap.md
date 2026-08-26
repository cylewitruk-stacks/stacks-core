# Attacknet roadmap

This document lists capabilities that are intentionally not part of the
qualified Release 1 product. They must not be presented as implemented merely
because Kubernetes or Bitcoin Core exposes a related primitive.

The machine-readable source of truth is
[`baseline-v1.json`](../../release/baseline-v1.json). Update that baseline
when roadmap work changes an advertised capability.

## Bounded Bitcoin reorganization campaigns

`BurnchainReorg` is planned as a first-class semantic fault, distinct from a
process or packet-level Chaos Mesh fault. Bitcoin Core regtest exposes
`invalidateblock` and `reconsiderblock`, allowing a controlled single-node
campaign to invalidate a bounded suffix and mine a longer replacement branch.

The campaign must not expose arbitrary Bitcoin RPC. Its admitted contract must
seal:

- original tip, branch hashes, and chainwork;
- fork parent, depth, replacement length, and mining recipients;
- current PoX, epoch, and reward-cycle phase;
- exact RPC requests and acknowledgments;
- resulting canonical branch;
- Stacks rollback, divergence, and recovery observations.

Safety budgets must bound fork depth and duration, forbid crossing an
unspecified epoch/reward boundary, require the mutation lease, and fail closed
when the observed branch differs from the sealed precondition.
`reconsiderblock` only removes a local invalidity marker; it is not proof that
the intended replacement branch remained canonical.

## Multiple Bitcoin followers

A single Bitcoin Core process tests Stacks reorg handling but not Bitcoin
network partitions. The higher-fidelity planned topology gives every Stacks
node its own Bitcoin follower and joins those followers through an explicit
regtest P2P graph.

Campaigns can then partition Bitcoin cohorts, delay propagation, or mine
bounded competing branches under a seeded work schedule. Honest Stacks actors
may hold genuinely different burnchain views until the Bitcoin graph heals and
higher-work selection converges.

This requires first-class Stacks-actor-to-Bitcoin-node bindings and per-Bitcoin
evidence:

- height, best-block hash, and chainwork;
- chain tips and peer graph;
- header/block receipt timing;
- the bound Stacks actor's burn-view hash and height.

Effect assertions must prove the requested split on both layers. Recovery must
prove every Bitcoin node selected the expected branch and every Stacks actor
converged without an unexplained canonical fork. Local RPC invalidation and a
distributed consensus split must retain different mechanism labels.

The dashboard must show Bitcoin P2P edges, partition cohorts, per-node branch
identity/chainwork, bound Stacks burn views, and a common divergence/recovery
timeline. Evidence must retain the exact partition and mining schedule.

## Fault composition and fuzz mode

Once burnchain faults are bounded and attributable, `AttacknetRun` can combine:

- Bitcoin reorganization or view splits;
- flash-block cadence;
- epoch/reward-cycle boundary placement;
- mixed node/signer versions;
- Pod, network, DNS, disk, and application-clock faults;
- bounded modified actors.

Adaptive agents may choose among admitted templates, but every decision must be
seeded, ordered, budgeted, and written to the sealed run ledger before
execution. No agent may issue an unrecorded Bitcoin RPC or raw Kubernetes fault.

## Managed and x86-64 qualification

Release 1 is limited to local arm64 `kind`. Future qualification needs an
external x86-64, multi-node or multi-zone cluster with:

- immutable registry distribution and organization identity integration;
- native Chaos Mesh IOChaos/TimeChaos verification;
- autoscaler, maintenance, and worker replacement scenarios;
- Kubernetes policy and quota admission evidence;
- realistic control-plane/API-server failure modes.

This work is externally dependent and remains deferred until such an
environment is available.

## Portable storage

The local profile uses node-local storage. It proves same-node recovery and
explicit stranding when a PVC cannot move. It does not prove portable or zonal
reattachment.

Future work needs a supported CSI implementation and multi-node/multi-zone
environment to test detach, reattach, node loss, delayed volume binding, and
chainstate integrity after relocation.

## Controller high availability

Both controllers are intentionally singleton and have no leader election.
Future HA work must prove lease ownership, handoff during reconciliation,
finalizer safety, schedule immutability, and absence of duplicate fault
execution before raising the replica count.

## Additional product gaps

The Release 1 baseline also records these unfinished items:

- cold-start capacity reservation beyond current filesystem observation;
- per-scenario actor egress NetworkPolicy;
- cryptographically attributable probes against a malicious same-Pod actor;
- complete Loki corpus export during normal teardown;
- packaging a Kubernetes client matched to the server version.

These are product work, not claims that the harness already satisfies.
