# Controller architecture

The module contains two controller-runtime managers and three reconcilers. Each
custom resource has one authoritative reconciler and one durable status state
machine.

```text
topology-operator
└── StacksNetwork reconciler
    ├── topology rendering
    ├── workload apply and prune
    └── admitted actor inventory

run-operator
├── AttacknetRun reconciler
│   ├── immutable schedule store
│   ├── replay and minimization
│   └── child FaultCampaign orchestration
└── FaultCampaign reconciler
    ├── admission and identity barriers
    ├── fault-mechanism registry
    ├── mutation lease and lifecycle
    ├── trusted observations
    └── effect and recovery classification
```

## Package ownership

| Package | Responsibility |
| ---- | ---- |
| `api/v1alpha1` | Typed custom-resource specifications and statuses. |
| `internal/topology` | Pure workload rendering and `StacksNetwork` convergence. |
| `internal/fault` | Fault compilation, admission, mutation, observation, and recovery. |
| `internal/run` | Immutable schedules and sequential campaign orchestration. |
| `internal/inventory` | Reproducible admitted identity and uncached live reads. |
| `internal/signerset` | Canonical signer-set and weight resolution. |
| `internal/canonical` | Bounded canonical JSON and artifact digests. |
| `internal/ownership` | Controller owner references. |

Reconcilers coordinate durable transitions. Pure compilation, rendering,
schedule construction, and evidence evaluation remain callable without an API
server. Kubernetes clients, uncached readers, clocks, signer resolvers, and
probe clients are injected at the reconciler boundary.

## Durable state machines

`FaultCampaign` advances at most one durable transition per reconciliation:

```text
Pending -> Admitted -> Injecting -> Active -> Recovering
    |          |           |          |            |
    +----------+-----------+----------+----------> Failed
                                             +--> Passed
                                             +--> Inconclusive
```

`AttacknetRun` admits and persists its complete schedule before creating a
campaign. It runs at most one child campaign, records its terminal decision,
then advances to the next immutable action or a terminal run phase.

`StacksNetwork` renders the complete desired object set before applying any
object. Its status inventory digest is absent until every declared actor has a
Ready Pod with immutable runtime identity.

## Adding a fault mechanism

The closed registry in `internal/fault/mechanism.go` is the extension point.
One registration declares the fault type, Kubernetes mutation kind, mutation
backend, capability contract, probe/effect family, allowed actions, and bounded
parameter validator. Registry construction rejects incomplete, duplicate type,
and duplicate mutation-kind entries.

Use an existing mutation backend when its lifecycle semantics match. A new
backend requires explicit injection, observation, contract, and cleanup support
plus unit, envtest, equivalence, and live evidence. Never move generic target
selection, signer/miner safety accounting, leases, identity enforcement, or
status transitions into a mechanism.

## Invariants

- Only one reconciler writes each custom resource's status.
- Informer-cached reads may drive ordinary reconciliation; admission barriers,
  mutation identity, and terminal identity checks use the uncached API reader.
- A campaign never silently retargets after its admitted inventory changes.
- A mutation is neither adopted nor deleted without its expected owner and UID.
- Schedule ConfigMaps are immutable, owner-bound, and verified on every read.
- Fault mechanisms return evidence to the common classifier; they do not select
  their own terminal campaign phase.
- Adding extensibility must not weaken bounded labels, bounded payloads,
  namespace-scoped RBAC, or credential-free actor Pods.

Do not introduce a shared base reconciler or one controller per phase. Those
patterns split ownership of a durable workflow and make retries harder to
reason about. Extract a collaborator only when it owns a cohesive policy or
external-system boundary with independent tests.
