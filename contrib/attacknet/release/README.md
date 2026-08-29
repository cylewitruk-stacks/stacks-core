# Attacknet release records

This directory contains the Release 1 baseline, review contracts, packet
builders, schemas, and the A1–A10 amendment history. These artifacts bind exact
historical revisions and paths; they are intentionally not rearranged by
repository-hygiene changes.

The latest approved amendment is A10, `multi-Bitcoin split views`, at signed
commit `2debbcd747b4b406f6d7392515d71b3008da119b`.
Its Full-tier gate closed against packet digest
`sha256:974a46c34186702d5dbfdde13dde895e494d8b593f9c4ac424de25c8f2c7d16d`.

New gated-amendment contracts, packet builders, verifiers, and tests live under
`amendments/<id>/`; A6 establishes that convention without rewriting the
approved history. Gated amendments must use a unique `reviewId`, bind a signed
candidate revision, and preserve portable evidence locators. Routine
post-approval documentation and baseline bookkeeping use ordinary review and
must remain within the exact approved claim. See
[`PHASE-REVIEWS.md`](PHASE-REVIEWS.md).
