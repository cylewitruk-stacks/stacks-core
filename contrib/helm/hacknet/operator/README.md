# Hacknet controllers

The two Go binaries in this module use Kubernetes `controller-runtime`:

- `topology-operator` reconciles `StacksNetwork` declarations and admitted
  actor inventory;
- `run-operator` reconciles `FaultCampaign` and `AttacknetRun` resources.

Both managers watch one namespace, expose controller-runtime metrics on 8080,
serve liveness/readiness on 8081, and run as singletons. Readiness performs an
uncached Kubernetes API read; liveness only proves that the process can answer.
The run manager requires an uncached API reader for schedule admission,
post-admission network/Pod identity barriers, recovery classification, and the
final mutation-disappearance check. These direct reads narrow informer-cache
staleness windows; they are not an atomic Kubernetes snapshot.

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for package ownership, durable state
machines, invariants, and the supported fault-mechanism extension process.

## Development

Go 1.26 and `controller-gen` 0.21 are the pinned development versions.
The generator runs from the isolated `tools/go.mod` module, so no ambient
`controller-gen` installation is required and its dependencies cannot alter
the controller runtime dependency graph.

```bash
cd contrib/helm/hacknet/operator
make test
make test-race
make generate
```

The authored CRDs under `../crds/` remain the API source of truth because they
contain bounded schemas and CEL policies not yet expressed as Go markers.
`controller-gen` generates typed-object deep-copy methods only. Any API field
change must update the Go type, authored CRD, CRD contract tests, and envtest.

Run the API-server integration suite with Kubernetes 1.36 envtest assets:

```bash
KUBEBUILDER_ASSETS=/path/to/kubebuilder/bin make test-integration
```

Envtest installs the authored CRDs and synthetic Chaos Mesh CRDs. It exercises
topology reconciliation, admitted-inventory publication/withdrawal, immutable
run scheduling, one-shot fault injection, identity transition, cleanup, and
terminal classification through real API-server validation and informer
caches. Live `kind` qualification is still required for StatefulSet/PVC,
container runtime, Chaos Mesh daemon, scheduling, and probe behavior. The
migration was qualified on a three-node kind cluster with a real one-shot
`PodChaos` run, exact identity-transition evidence, recovery, and cleanup.

## Coverage boundary

The Go suites preserve the legacy behavior by responsibility rather than by
transliterating implementation-shaped tests:

- topology rendering tests cover actor configuration, dependencies, security,
  persistence, suspension, probes, stable names, and invalid declarations;
- topology reconciler and envtest coverage exercises ownership, collision
  refusal, pruning, API-defaulted immutable fields, rollout readiness, and
  admitted-inventory publication and withdrawal;
- compiler, parameter, capability, and effect tests cover bounded target
  selection, canonical signer weight, every supported fault contract, trusted
  helper restrictions, and effect-versus-recovery evidence;
- run tests cover immutable schedules, replay, resume, minimization, budgets,
  terminal classification, and status-copy isolation; and
- API-server integration drives a complete `AttacknetRun` through an owned
  one-shot campaign, expected Pod identity transition, cleanup, and terminal
  evidence using real informer caches and status subresources.

The chart check additionally runs CRD/CEL, RBAC, probe, helper-image, Helm,
`go vet`, race, and 31-workload offline-render contracts. Live kind remains the
release gate for behavior that envtest cannot emulate.
