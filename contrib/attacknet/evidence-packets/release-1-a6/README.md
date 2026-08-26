# Release 1 Amendment A6 Evidence

A6 is a Reduced-tier repository-hygiene amendment. It changes ownership and
locators, not Kubernetes APIs, controller behavior, fault semantics, or evidence
interpretation. Generate its candidate-bound packet only after the single
hardware-signed commit exists.

```bash
candidate="$(git rev-parse HEAD)"
raw=".docs/evidence/release-1-a6/raw"
evidence=".docs/reviews/attacknet-release-1-a6/evidence"
packet=".docs/reviews/attacknet-release-1-a6/review-packet.json"

node contrib/attacknet/release/amendments/a6/verify.mjs \
  "--candidate=${candidate}" \
  "--output=${raw}"

node contrib/attacknet/release/amendments/a6/evidence.mjs \
  "--candidate=${candidate}" \
  "--input=${raw}" \
  "--output=${evidence}" \
  "--archive-location=file://${PWD}/${evidence}/archive/release-1-a6-evidence-${candidate:0:12}.tar.gz"

node contrib/attacknet/release/amendments/a6/packet.mjs \
  "--output=${packet}" \
  "--summary=${evidence}/summary.json"
```

Both required reviewers independently verify the signed candidate, every packet
digest, the exact binary diff, the archive contents, and all inventory entries.
Their direct-read verdicts then close the gate through
`contrib/attacknet/release/phase-review.mjs`.
