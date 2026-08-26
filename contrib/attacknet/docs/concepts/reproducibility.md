# Attacknet reproducibility contract

Reproducibility is controller-owned. An `AttacknetRun` records the caller's
opaque seed and decision algorithm, snapshots campaign templates, resolves an
immutable schedule, binds the admitted network inventory and runtime image
identities, and stores the schedule behind a digest-bearing status reference.
The requested YAML is intent; controller status and admitted Kubernetes state
are the resolved truth.

The contract does not claim that Kubernetes scheduling, packet timing,
proof-of-work, or wall-clock interleavings are deterministic. Evidence must
retain those observations rather than reconstructing them from the seed.

## Create and observe a run

Author a v1beta1 `AttacknetRun` with a stable `spec.seed`, a supported
`spec.decisionAlgorithm`, explicit campaign catalog, executions, safety
budgets, and stop policy. Validate and submit through the typed client:

```bash
attacknet validate --file contrib/helm/hacknet/examples/attacknet-run.yaml
attacknet submit --namespace hacknet-system \
  --file contrib/helm/hacknet/examples/attacknet-run.yaml
attacknet wait --namespace hacknet-system --for terminal \
  AttacknetRun bounded-mixed-faults
attacknet get --namespace hacknet-system \
  AttacknetRun bounded-mixed-faults
```

Retain the terminal resource, its referenced schedule, the exact
`StacksNetwork.status` admitted inventory, campaign children, Pod identities,
Events, metrics, and logs. A bounded incident bundle can be captured with:

```bash
attacknet evidence incident --namespace hacknet-system \
  --output evidence/bounded-mixed-faults attacknet
```

The incident collector records digests and explicit omissions. It does not
replace metrics or external observability exports.

## Replay

Replay uses a fresh network UID and the immutable source run/schedule identity.
Set `spec.replay.enabled`, `sourceRunRef`, `descriptorURI`,
`descriptorDigest`, and a unique `attemptId`. When expected-failure checking is
enabled, also set the expected assertion and status. The controller rejects
changed templates, budgets, image identities, or source schedule content.

The same seed is not sufficient evidence of equivalence. A replay is valid
only when its controller status proves the source schedule and admitted image
constraints were preserved.

## Minimization

Minimization is one bounded, removal-only `DeltaDebug` attempt on a fresh
network. It names the source schedule digest, attempt ID, expected outcome, and
the retained executions, stages, actions, and targets. The controller reseals
the candidate and rejects reordering, additions, an empty candidate, or a
candidate digest that does not match the permitted removals.

A minimized reproducer demonstrates that one smaller instruction set retained
the outcome. It does not prove causal minimality; inconclusive attempts remain
inconclusive.

## Historical descriptors

Release evidence created before v1beta1 used a standalone Node descriptor.
That implementation is frozen under
[`../../legacy/v1alpha1/`](../../legacy/v1alpha1/README.md) for historical
verification only. New runs must use `AttacknetRun` status and the typed Go CLI.
