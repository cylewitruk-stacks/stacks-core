# Release 1 development issues

Release 1 issue documents are grouped by amendment and listed in recommended
implementation order. Amendment status remains authoritative in the
[`roadmap`](../../roadmap.md).

## Planned

### R1A13: Seeded fuzzing, corpus management, and reduction

- [`r1a13-seeded-fuzzing-corpus-reduction.md`](r1a13-seeded-fuzzing-corpus-reduction.md):
  implementation-ready design for deterministic planning, resumable sessions,
  capacity admission, portable failure corpora, fresh-network confirmation,
  and mechanical reduction.

## Approved

### R1A12: Deterministic adversarial actors

- [`r1a12-deterministic-adversarial-actors.md`](r1a12-deterministic-adversarial-actors.md):
  approved threat model, bounded signer behavior, egress and observer
  boundaries, campaign integration, qualification, and review record.

### R1A11: Mixed-version and upgrade-boundary campaigns

- [`r1a11-mixed-version-upgrade-campaigns.md`](r1a11-mixed-version-upgrade-campaigns.md):
  approved umbrella requirements and end-to-end implementation record.

Add narrower R1A11 issue documents only when a phase is independently
implementable or reviewable. Use the same `r1a11-` prefix so related work stays
discoverable.
