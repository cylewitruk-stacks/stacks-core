# Attacknet release records

This directory contains the Release 1 baseline, review contracts, packet
builders, schemas, and the A1–A12 amendment history. These artifacts bind exact
historical revisions and paths; they are intentionally not rearranged by
repository-hygiene changes.

The latest approved amendment is A12, `deterministic adversarial actors`, at
signed commit `6a6ea8363012173fc614fe8ddb40daa0695feddd`.
Its Full-tier gate closed against packet digest
`sha256:a734ee009c8881d9acc77bad6bdb8cc849e2573523618fd8cf7d680dc82c1d96`.

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
