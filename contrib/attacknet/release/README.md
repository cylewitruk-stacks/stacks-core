# Attacknet release records

This directory contains the Release 1 baseline, review contracts, packet
builders, schemas, and the A1–A7 amendment history. These artifacts bind exact
historical revisions and paths; they are intentionally not rearranged by
repository-hygiene changes.

New amendment-specific contracts, packet builders, verifiers, and tests live
under `amendments/<id>/`; A6 establishes that convention without rewriting the
approved history. New amendments must use a unique `reviewId`, bind a signed
candidate revision, and preserve portable evidence locators. See
[`PHASE-REVIEWS.md`](PHASE-REVIEWS.md).
