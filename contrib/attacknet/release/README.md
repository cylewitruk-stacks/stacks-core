# Attacknet release records

This directory contains the Release 1 baseline, review contracts, packet
builders, schemas, and the A1–A9 amendment history. These artifacts bind exact
historical revisions and paths; they are intentionally not rearranged by
repository-hygiene changes.

The latest approved amendment is A9, `bounded Bitcoin reorganization`, at
signed commit `b93517c0090acfb0943789d6cf82ec40b7ce4357`.
Its Full-tier gate closed against packet digest
`sha256:4f647e1f459400f214b79c32a21577be15df80bfe998811fd1fa9de387f7f4f7`.

New gated-amendment contracts, packet builders, verifiers, and tests live under
`amendments/<id>/`; A6 establishes that convention without rewriting the
approved history. Gated amendments must use a unique `reviewId`, bind a signed
candidate revision, and preserve portable evidence locators. Routine
post-approval documentation and baseline bookkeeping use ordinary review and
must remain within the exact approved claim. See
[`PHASE-REVIEWS.md`](PHASE-REVIEWS.md).
