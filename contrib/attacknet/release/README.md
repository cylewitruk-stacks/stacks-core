# Attacknet release records

This directory contains the Release 1 baseline, review contracts, packet
builders, schemas, and the A1–A8 amendment history. These artifacts bind exact
historical revisions and paths; they are intentionally not rearranged by
repository-hygiene changes.

The latest approved amendment is A8, `trusted-observation and
forensic-completeness`, at signed commit `2481f75b49a44f151847b9f6a3a0139e6af3e4e0`.
Its Full-tier gate closed against packet digest
`sha256:69211af52d11e9d01af323420ab6f39a92ca9c7582e25a382f7dda5776dd1585`.

New amendment-specific contracts, packet builders, verifiers, and tests live
under `amendments/<id>/`; A6 establishes that convention without rewriting the
approved history. New amendments must use a unique `reviewId`, bind a signed
candidate revision, and preserve portable evidence locators. See
[`PHASE-REVIEWS.md`](PHASE-REVIEWS.md).
