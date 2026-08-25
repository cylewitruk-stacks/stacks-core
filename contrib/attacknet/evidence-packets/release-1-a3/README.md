# Release 1 Amendment A3 evidence packet

Amendment A3 closes three non-blocking findings from the complete A2 review:

- clock-skew admission again requires every shared clock-policy entry to be at
  zero and the actor mount to be backed by the expected policy ConfigMap;
- rendered operator RBAC is decoded and compared with an exact structural
  least-privilege contract; and
- topology equivalence covers multi-actor ordering, disabled probes, and
  disabled actor storage.

The review is Full-tier because the clock-skew change affects fault admission.

## Candidate boundary

The candidate must be one hardware-signed, non-merge commit whose direct parent
is approved A2 commit `7765c308a761acb9e73bfc7893761904ede0caf1`.
The verifier rejects dirty worktrees, unsigned commits, other parents, and
unavailable required tools.

Run the candidate-bound offline checks:

```bash
node contrib/attacknet/release/release-1-a3-verify.mjs \
  --candidate="$(git rev-parse HEAD)" \
  --output=.docs/evidence/attacknet-release-1-a3/raw \
  --envtest-assets=/path/to/kubebuilder/assets \
  --kubernetes-version=1.36.2
```

This runs Go build/generation/vet/unit/race checks, envtest, all four topology
equivalence profiles, Helm lint/render, the structural RBAC validator, and both
whole-product check scripts. It also captures the exact binary diff from A2.

## Live clock-policy proof

Build the `run-operator` image from the signed candidate, load that exact image
into every kind node, and deploy it with
`testing.stacks.org/build-index: <local image index>` on the run-operator Pod.
Record the immutable runtime image ID after rollout. The candidate operator
context tree is:

```bash
git rev-parse HEAD:contrib/helm/hacknet/operator
```

Against a Ready network with at least two clock-capable actors and an active
environment lease, run:

```bash
node contrib/attacknet/release/release-1-a3-clock-live.mjs \
  --candidate="$(git rev-parse HEAD)" \
  --namespace=hacknet-system \
  --network=attacknet \
  --run-deployment=RELEASE-hacknet-run \
  --target=follower-1 \
  --control=miner-1 \
  --expected-runtime-image-id=sha256:RUNTIME_IMAGE_ID \
  --expected-image-index=sha256:LOCAL_IMAGE_INDEX \
  --operator-context-tree="$(git rev-parse HEAD:contrib/helm/hacknet/operator)" \
  --output=.docs/evidence/attacknet-release-1-a3/raw/clock-policy-live.json
```

The runner deliberately gives the non-target control actor a non-zero shared
policy entry. It requires `FaultCapabilityUnavailable`, negative capability
evidence, no policy mutation by the controller, mutation-lease cleanup, campaign
deletion, and restoration of both entries to zero. It also binds the admitted
run-operator Pod to the expected image IDs and the candidate source tree, and
requires the supported three-node arm64 kind profile.

## Archive and review

Assemble the portable evidence root:

```bash
node contrib/attacknet/release/release-1-a3-evidence.mjs \
  --candidate="$(git rev-parse HEAD)" \
  --input=.docs/evidence/attacknet-release-1-a3/raw \
  --output=.docs/evidence/attacknet-release-1-a3/live \
  --archive-location=ARCHIVE_URI
```

Build the packet next to its `live/` evidence root:

```bash
node contrib/attacknet/release/release-1-a3-packet.mjs \
  --live-summary=.docs/evidence/attacknet-release-1-a3/live/live-summary.json \
  --output=.docs/evidence/attacknet-release-1-a3/packet.json
```

The gate requires complete, direct-read verdicts from Codex and Claude Opus 5
over the same packet digest and the review ID
`release-1-amendment-a3-controller-hardening`.
