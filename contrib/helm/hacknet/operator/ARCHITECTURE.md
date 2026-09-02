# Controller architecture

The module contains two controller-runtime managers and four authoritative
reconcilers. Each custom resource owns one durable state machine; shared
packages provide policy, compilation, storage, identity, and observation
boundaries without becoming additional state owners.

```text
topology-operator
├── StacksNetwork reconciler
│   ├── domain topology compilation
│   ├── workload apply and prune
│   └── admitted actor inventory
└── BurnchainPolicy reconciler
    ├── immutable Bitcoin identity admission
    ├── clock policy rendering
    └── clock health and progress status

run-operator
├── AttacknetRun reconciler
│   ├── immutable schedule store
│   ├── trigger and dependency evaluation
│   ├── replay and removal-only minimization
│   └── child FaultCampaign orchestration
└── FaultCampaign reconciler
    ├── aggregate admission and identity barriers
    ├── staged fault-mechanism execution
    ├── mutation lease and partial rollback
    └── trusted effect and recovery classification
```

## Package ownership

| Package | Responsibility |
| ---- | ---- |
| `api/v1beta1` | Public domain custom-resource specifications and statuses. |
| `internal/topology` | Pure domain compilation, workload rendering, and `StacksNetwork` convergence. |
| `internal/burnchain` | Stacks-blind Bitcoin cadence policy engine and RPC boundary. |
| `internal/burnchainpolicy` | `BurnchainPolicy` admission, clock workload, and status reconciliation. |
| `internal/fault` | Fault compilation, aggregate admission, mutation, observation, rollback, and recovery. |
| `internal/run` | Immutable schedules, trusted triggers, replay, resume, minimization, and campaign orchestration. |
| `internal/trigger` | Pure deterministic trigger evaluation and receipts. |
| `internal/inventory` | Reproducible admitted identity and uncached live reads. |
| `internal/signerset` | Canonical signer-set and weight resolution. |
| `internal/canonical` | Bounded canonical JSON and artifact digests. |
| `internal/document` | Strict YAML/JSON decoding at human and machine boundaries. |
| `internal/ownership` | Controller owner references. |

The deprecated `api/v1alpha1` package is an internal behavior reference for
conversion and equivalence tests only. New resources and controller watches
use `testing.stacks.org/v1beta1`.

Reconcilers coordinate durable transitions. Pure compilation, rendering,
schedule construction, trigger evaluation, and evidence evaluation remain
callable without an API server. Kubernetes clients, uncached readers, clocks,
signer resolvers, probes, and Bitcoin RPC are injected at process boundaries.

Public campaign and run invariants have two deliberate enforcement layers.
Bounded CEL rules reject structural mistakes at Kubernetes admission, while
shared pure Go validators serve the CLI and the compilers. Inventory-dependent
selection and aggregate safety remain compiler responsibilities. A bounded LRU
cache retains only successful campaign compilations keyed by the complete
campaign generation, specification, and admitted manifest; terminal and
deleted campaigns evict their entries. The cache is an optimization, never an
admission authority, and callers receive defensive copies.

## Durable state machines

One `FaultCampaign` may contain multiple stages and actions. An omitted trigger
is immediate; later stages may wait for campaign time, chain height, a trusted
observation, or a prior stage reaching `Injected`, `Effective`, `Recovered`, or
`Terminal`.

```text
Campaign: Pending -> Admitted -> Running -> Recovering -> terminal
                                |              |
                                +-- rollback --+

Stage:    Pending -> Injecting -> Active -> Recovering -> terminal
                         |           |
                         +-- partial injection -> rollback -> Inconclusive
```

Actions eligible in the same stage are admitted as one aggregate safety set.
Stages may overlap only when their immutable schedule, aggregate signer/miner/
burnchain budgets, and target identities permit it. One namespace mutation
lease serializes separate campaigns; concurrency is expressed inside a
campaign so the controller can reason about the union of mutations.

`AttacknetRun` seals its complete execution DAG before creating children. It
evaluates triggers from trusted recorded observations and persists a receipt
for every decision. Eligible children may be created according to run budgets;
the campaign mutation lease remains the final cross-campaign serialization
barrier. Replay and resume never reconstruct a different schedule silently.

`StacksNetwork` compiles its complete domain topology before applying any
object. Its inventory digest is absent until every actor has a Ready Pod with
immutable runtime identity. A referenced `BurnchainPolicy` is a readiness
barrier but not an actor-creation dependency, avoiding a bootstrap cycle.

`BurnchainPolicy` admits one selected Bitcoin actor identity, renders a
credential-free clock workload, and reports the applied policy and Bitcoin
height. Bitcoin Core remains a separate durable StatefulSet. Clock retries do
not restart, pause, or interpret Stacks.

## Adding a fault mechanism

The closed registry in `internal/fault/mechanism.go` is the extension point.
One registration declares the fault type, Kubernetes mutation kind, mutation
backend, capability contract, probe/effect family, allowed actions, and bounded
parameter validator. Registry construction rejects incomplete registrations,
duplicate fault types, and duplicate mutation kinds.

Use an existing mutation backend when its lifecycle semantics match. A new
backend requires explicit injection, observation, contract, and cleanup support
plus unit, envtest, equivalence, and live evidence. Never move target selection,
aggregate safety accounting, leases, identity enforcement, or terminal status
policy into an individual mechanism.

## Invariants

- Only one reconciler writes each custom resource's status.
- Informer-cached reads may drive ordinary reconciliation; admission barriers,
  mutation identity, and terminal identity checks use the uncached API reader.
- A campaign never silently retargets after its admitted inventory changes.
- Concurrent actions are authorized over their aggregate impact, never one at
  a time against an otherwise invisible active set.
- Partial injection is rolled back and cannot produce `Passed`.
- A mutation is neither adopted nor deleted without its expected owner and UID.
- Schedules and policy ConfigMaps are immutable, owner-bound, and verified on
  every read.
- Trigger decisions are deterministic over a sealed schedule and recorded
  observation snapshot.
- Fault mechanisms return evidence to the common classifier; they do not pick
  their own terminal phase.
- Adding extensibility must not weaken bounded labels, payloads, namespace RBAC,
  credential-free actor Pods, or Secret isolation.

Do not introduce a shared base reconciler or one controller per phase. Those
patterns split ownership of a durable workflow and make retries harder to
reason about. Extract a collaborator only when it owns a cohesive policy or
external-system boundary with independent tests.
