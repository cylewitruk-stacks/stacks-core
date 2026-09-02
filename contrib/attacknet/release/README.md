# Attacknet release records

This directory contains the Release 1 baseline, review contracts, packet
builders, schemas, and the A1–A13 amendment history. These artifacts bind exact
historical revisions and paths; they are intentionally not rearranged by
repository-hygiene changes.

The latest approved amendment is A13, `seeded fuzzing, corpus, and reduction`,
at signed commit `82efd989d71836322286d870cdb82be49c9db364`.
Its Full-tier gate closed against packet digest
`sha256:eeb4601eec1a186edb6d69c5f7f66b3abe1f7048bc82f9036f2e28c752787727`.

The baseline points to small tracked gate records rather than ignored live
evidence directories. The Release 1 foundation record binds the historical
Phase 0 evidence inventory; amendment records bind their external archives and
both reviewer verdicts. Large raw evidence remains external and
content-addressed.

New gated-amendment contracts, packet builders, verifiers, and tests live under
`amendments/<id>/`; A6 establishes that convention without rewriting the
approved history. Gated amendments must use a unique `reviewId`, bind a signed
candidate revision, and preserve portable evidence locators. Routine
post-approval documentation and baseline bookkeeping use ordinary review and
must remain within the exact approved claim. See
[`PHASE-REVIEWS.md`](PHASE-REVIEWS.md).
