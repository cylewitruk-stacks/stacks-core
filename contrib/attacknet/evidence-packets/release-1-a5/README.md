# Release 1 Amendment A5 evidence

This directory is the stable home for the Full-tier A5 review packet after the
hardware-signed candidate is qualified. The packet is generated only after a
clean candidate-bound verification and a fresh three-node kind run.

Required live artifacts prove immutable local installation, burnchain policy,
overlapping faults, run restart/replay/minimization, accepted-scale chain
convergence, bounded incident capture, and clean teardown. Evidence archives
are portable and digest-indexed; local `.docs` development evidence is not a
release artifact.

Run the candidate-bound tools in this order from the repository root. Replace
the example paths with the local envtest installation and evidence archive
location used by the reviewer:

```text
candidate_revision=$(git rev-parse HEAD)
review_root=.docs/reviews/attacknet-release-1-a5

node contrib/attacknet/release/release-1-a5-verify.mjs \
  --candidate="$candidate_revision" \
  --output="$review_root/verification" \
  --envtest-assets=/path/to/kubebuilder/assets

# Perform the fresh live qualification and place the inputs listed below in
# "$review_root/live-input". Copy verification.json, offline-result.json,
# hacknet-result.json, and candidate.patch from the verification directory.

node contrib/attacknet/release/release-1-a5-evidence.mjs \
  --candidate="$candidate_revision" \
  --input="$review_root/live-input" \
  --output="$review_root/live" \
  --archive-location=file:///absolute/reviewer-visible/release-1-a5-evidence.tar.gz

node contrib/attacknet/release/release-1-a5-packet.mjs \
  --output="$review_root/review-packet.json" \
  --live-summary="$review_root/live/live-summary.json" \
  --evidence-root=live
```

The verifier requires a clean, hardware-signed, non-merge commit directly on
approved A4. The live inputs must be generated again from that exact candidate;
the pre-signing development evidence under `.docs/evidence` is intentionally not
reusable. The generated review packet stays under the ignored `.docs/reviews`
tree so producing evidence does not dirty the signed candidate.

The evidence assembler expects the candidate verification directory plus these
candidate-bound live results:

| Input | Proof |
| --- | --- |
| `local-install.json` | Exact operator and actor images loaded on all three kind nodes |
| `burnchain-policy.json` | Fresh policy snapshot plus pause, resume, cadence, and exact-flash assertions |
| `concurrent-fault.json` | Overlap, aggregate admission, unsafe-union refusal, restart, effect, recovery, and cleanup |
| `run-overlap-restart.json` | Trigger DAG overlap and controller restart/resume on bound identities |
| `replay-minimization.json` | Fresh-network replay and removal-only minimization |
| `accepted-network.json` | Candidate-bound 30/30 admitted `StacksNetwork` snapshot |
| `accepted-cohort.json` | All 18 Stacks nodes at one nonzero height and tip hash |
| `accepted-incident/` | Complete bounded incident directory with no errors or omissions |
| `clean-teardown.json` | Zero remaining managed resources |

`release-1-a5-evidence.mjs` validates these schemas, joins network UID,
inventory digest, actor runtime image, policy, cohort, and incident identities,
then writes the portable indexed archive. A development run under `.docs` is
useful diagnostic evidence but cannot substitute for a clean signed-candidate
rerun.
