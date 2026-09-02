# Release 1 Amendment A2 evidence packet

Amendment A2 replaces both legacy controllers with one Go module built on
`controller-runtime`. It remains two separately privileged Deployments. The
review is Full-tier because workload rendering, fault execution, run state,
Kubernetes identity, packaging, and evidence interpretation all change.

The offline equivalence suite executes the approved A1 Python resource builder
and the production Go renderer against the same representative topology. It
compares the complete Service, StatefulSet, ConfigMap, storage, security,
dependency, telemetry, and trusted-probe contract after applying Kubernetes API
defaults. The only normalized implementation changes are the documented
dependency-init hardening, internal ownership label, and probe Service endpoint.

## Candidate boundary

The candidate must be one hardware-signed, non-merge commit whose direct parent
is approved Amendment A1 commit
`f8a853a0f21c9edebec92398fb56500ae10e1a22`. Do not combine unrelated changes
or rewrite the candidate after either verdict.

The committed binary diff must include every deleted Python and JavaScript
controller artifact. The packet separately inventories every added or modified
file and the versioned legacy-to-Go equivalence matrix.

## Required verification

Run and archive all of the following against the signed candidate:

1. `make verify` in `contrib/helm/hacknet/operator`.
2. controller-runtime envtest with the repository's CRDs and required Chaos
   test CRDs.
3. `contrib/attacknet/check.sh` and
   `contrib/helm/hacknet/scripts/check.sh` with machine-readable results.
4. Helm lint and render with the exact candidate image configuration.
5. A fresh topology reaching a complete admitted inventory.
6. A reversible network fault proving injection, effect, recovery, and cleanup.
7. A one-shot Pod replacement proving only the permitted Pod identity changes.
8. A controller restart while work is active, followed by idempotent resume.
9. Clean teardown proving no candidate-owned workloads, PVCs, leases, or Chaos
    resources remain.

Identity divergence, signer-budget enforcement, unsupported capabilities,
malformed evidence, replay resealing, and terminal classification are required
deterministic unit or envtest contracts. They are not mandatory live races: a
live corroboration may be archived, but it cannot replace the fail-closed tests
or delay production reconciliation merely to make an intermediate state easier
to observe.

Produce the command-derived offline artifacts with one fail-closed invocation:

```bash
node contrib/attacknet/release/release-1-a2-verify.mjs \
  --candidate="$(git rev-parse HEAD)" \
  --output=.docs/evidence/attacknet-release-1-a2/raw \
  --envtest-assets=/path/to/kubebuilder/assets \
  --kubernetes-version=1.36.2
```

The producer requires a clean, hardware-signed candidate directly based on A1.
It records stdout, stderr, exit status, duration, and a combined output digest
for every required command. It also runs both product-wide check scripts and
captures the candidate's binary diff. Failed or unavailable checks cannot be
recorded as passed.

The `go-verify.json`, `envtest.json`, and `helm-render.json` artifacts must use
`stacks-attacknet-release-1-a2-result/v1`, pin the candidate revision, and
record each required check as `{id, status: "passed", command}`. The assembler
requires these exact check IDs:

| Artifact | Required check IDs |
| ---- | ---- |
| `go-verify.json` | `go-build`, `go-format`, `go-generate-clean`, `go-vet`, `go-unit`, `go-race` |
| `envtest.json` | `kubernetes-1.36-envtest`, plus the exact `kubernetesVersion` |
| `helm-render.json` | `helm-lint`, `helm-render`, `crd-contracts`, `rbac-security-contracts` |

Do not create a generic passed result after running only a subset. Reviewers
must be able to reproduce every recorded command against the signed revision.

The live summary uses
`stacks-attacknet-release-1-a2-live-evidence/v1`. Every artifact path must be
relative to one packet evidence root and must also appear in the portable
archive index. The archive, index, candidate diff, and all required artifacts
are SHA-256 bound by the packet.

After capturing the fixed raw artifact set, assemble and validate it with:

```bash
node contrib/attacknet/release/release-1-a2-evidence.mjs \
  --candidate="$(git rev-parse HEAD)" \
  --input=.docs/evidence/attacknet-release-1-a2/raw \
  --output=.docs/evidence/attacknet-release-1-a2/live \
  --archive-location=ARCHIVE_URI
```

The assembler checks the semantics of topology withdrawal, fault effect and
cleanup, Pod identity replacement, controller restart/resume, and teardown
before it emits passed assertion records. Deterministic safety controls are
bound through the Go, envtest, equivalence, and whole-product evidence. The
assembler does not convert raw command success into a product claim.

## Review

The equivalence matrix is a review map, not proof by itself. Each reviewer must
read the production implementation, legacy reference, tests, and live evidence
for every matrix entry. Targeted implementation reviews do not count as a
complete verdict.

The gate must identify
`release-1-amendment-a2-controller-runtime-migration` and requires complete,
direct-read approvals from Codex and Claude Opus 5 over the same signed packet.
