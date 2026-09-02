# Release 1 Amendment A4 evidence packet

Amendment A4 is a behavior-preserving internal refactor of the approved Go
controllers. It decomposes large source files, gives every fault mechanism one
closed registration point, extracts immutable schedule persistence, and
documents the controller extension boundaries. It does not change the CRDs,
rendered workloads, safety policy, identity barriers, status state machines, or
evidence interpretation.

The review is Full-tier because the refactor crosses topology rendering, fault
mutation, and durable run orchestration even though its intended compatibility
effect is none.

## Candidate boundary

The candidate must be one hardware-signed, non-merge commit whose direct parent
is approved A3 commit `5b6d3018374d24946c12ec46406ee6abed10ca56`.
The verifier rejects dirty worktrees, unsigned commits, other parents, and
unavailable required tools.

Run the candidate-bound offline checks:

```bash
node contrib/attacknet/release/release-1-a4-verify.mjs \
  --candidate="$(git rev-parse HEAD)" \
  --output=.docs/evidence/attacknet-release-1-a4/raw \
  --envtest-assets=/path/to/kubebuilder/assets \
  --kubernetes-version=1.36.2
```

This runs Go generation/build/vet/unit/race checks, Kubernetes 1.36 envtest,
all seven legacy fault-compiler comparisons, four topology render profiles,
Helm lint/render, the structural RBAC validator, and both whole-product check
scripts. It also captures the exact binary diff from A3.

## Live compatibility proof

Build and load operator, run-operator, and probe images from the signed
candidate. Repeat the A2 controller qualification against the supported local
three-node arm64 kind profile. Capture these candidate-bound compatibility
artifacts under the raw evidence directory:

- `topology-live.json`: admitted identity withdrawal and restoration across a
  mutable topology reconciliation;
- `reversible-fault-live.json`: environment-lease refusal, injection, proven
  effect, recovery, and cleanup;
- `pod-kill-live.json`: one-shot Pod replacement with immutable image identity;
- `restart-resume-live.json`: immutable schedule resume after replacing the run
  controller Pod; and
- `clean-teardown.json`: zero remaining CRs, workloads, leases, mutations, and
  controller-owned fault resources.

The artifacts retain the established
`stacks-attacknet-release-1-a2-result/v1` compatibility schema deliberately.
A4 imports the one shared validator for those semantics rather than maintaining
a second interpretation.

## Archive and review

Assemble the portable evidence root:

```bash
node contrib/attacknet/release/release-1-a4-evidence.mjs \
  --candidate="$(git rev-parse HEAD)" \
  --input=.docs/evidence/attacknet-release-1-a4/raw \
  --output=.docs/evidence/attacknet-release-1-a4/live \
  --archive-location=ARCHIVE_URI
```

Build the packet next to its `live/` evidence root:

```bash
node contrib/attacknet/release/release-1-a4-packet.mjs \
  --live-summary=.docs/evidence/attacknet-release-1-a4/live/live-summary.json \
  --output=.docs/evidence/attacknet-release-1-a4/packet.json
```

The gate requires complete, direct-read verdicts from Codex and Claude Opus 5
over the same packet digest and the review ID
`release-1-amendment-a4-controller-composability`.
