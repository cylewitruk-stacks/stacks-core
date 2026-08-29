# Attacknet phase review packets

Material Attacknet productization phases close through a digest-bound packet
and two complete approvals. This is a risk control for consequential product
changes, not a replacement for ordinary code review or a requirement for every
commit. The machine gate proves that both recorded verdicts name the same
declared source, evidence, and complete inventory. It does not pretend that a
digest proves what a human or model actually inspected.

Later commits do not invalidate an approval bound to an earlier revision. A
later material expansion or reinterpretation of an approved release claim uses
a new contract and packet. Such amendments carry a stable `reviewId` in both
artifacts so they cannot be confused with the numbered phase they follow.

## When a packet is warranted

Use the formal gate when a change materially affects one or more of:

- controller runtime behavior, fault semantics, safety budgets, or recovery;
- public CRDs, admission rules, RBAC, identity, or another security boundary;
- evidence acquisition, trust classification, interpretation, or teardown;
- a supported deployment profile or capability that needs new qualification;
  or
- another behavior where a false positive could conceal a network failure.

Ordinary review is sufficient for:

- roadmap status and release README updates;
- registering an already-approved packet and its exact capability scope in the
  baseline;
- wording, links, examples, and other non-behavioral documentation fixes;
- repository organization that preserves runtime and evidence behavior; and
- tests that only pin such bookkeeping.

Bookkeeping must not broaden an approved capability. If an edit adds a claim
that the approved packet did not establish, it is material and requires a new
gate. A documentation-only follow-up does not require renewed qualification,
new verdicts, or another review packet merely because it changes the later Git
tree.

Material candidates must update documentation in the same change. Review the
complete affected surface rather than only the roadmap:

- release status, scope, limitations, and ordering in the roadmap and baseline;
- maintainer-facing architecture and development guidance;
- operator-facing README, operations guides, commands, and troubleshooting;
- CRD, CLI, and scenario examples affected by the behavior; and
- observability and evidence guidance needed to interpret a run.

The packet inventory must include the affected documentation. When no
documentation changes are needed, the review record should state why. A gate
does not close while supported behavior and operator instructions disagree.

The approved Phase 0–2 artifacts retain the v1 contract and packet schemas.
They are the only grandfathered checkpoints without `reviewId`. Schema v2
requires `reviewId` in both artifacts, and all new phases and amendments must
use v2.

## Packet lifecycle

1. For a gated change, freeze the candidate commit. The packet builder derives the exact `HEAD`,
   tracked diff, and untracked-file digest directly from Git. There is no
   `--committed` override: a packet with `candidate.commitPending=true` can be
   inspected, but the machine gate refuses to approve its phase.
2. Populate the phase contract's complete, non-empty `requiredInventory` in a packet that
   follows `review-packet.schema.json`. Hash files byte-for-byte and build the
   packet's `sourceDigest` and `evidenceDigest` from their respective immutable
   inventories. Each scoped inventory is projected to
   `{id, kind, path, digest}`, sorted by `id` in ascending UTF-16 code-unit
   order (not locale collation), encoded as the canonical JSON described
   below, and hashed as UTF-8 bytes with SHA-256.
   The local schema validator deliberately implements a finite JSON Schema
   subset and rejects every keyword outside that subset. Structural keywords
   such as `properties`, `items`, and `pattern` also require their explicit
   compatible `type`; unsupported or ambiguous schema changes therefore stop
   packet validation instead of silently weakening it.
3. Bind `contractDigest` to the exact contract and set `binding.digest` to the
   SHA-256 digest of canonical packet JSON with the entire `binding` member
   omitted. Canonical JSON preserves array order; sorts object keys in
   ascending UTF-16 code-unit order; uses JSON string escaping and JSON's
   finite-number, Boolean, and null spellings; and inserts no insignificant
   whitespace. `phase-review.mjs` performs this same calculation.
   The packet also records `toolingDigest`, a canonical digest over
   `phase-review.mjs`, `schema-validator.mjs`, and the three review schemas.
   Before evaluating a packet, compare it with
   `node contrib/attacknet/release/phase-review.mjs tooling-digest`. A mismatch
   means the reviewer must use the verifier from the packet's candidate
   revision; it is not evidence that the packet was tampered with.
4. Give each reviewer the complete packet and every inventory item. A reduced
   packet records non-applicable full-tier material explicitly in its matrix;
   it does not silently omit it.
   Before review, validate the packet against its declared contract with the
   verifier from the candidate revision:

   ```bash
   node contrib/attacknet/release/phase-review.mjs verify-packet \
     --contract=/path/to/contract.json --packet=/path/to/packet.json
   ```

   This checks the packet structure and bindings. Reviewers still independently
   recompute inventory and archive digests from the referenced material.
5. Record each result using `review-verdict.schema.json`. A reviewer must list
   every inspected inventory ID and any omission. Silence, a scoped approval,
   or a review of another digest cannot close a phase.
6. Evaluate the records:

   ```bash
   node contrib/attacknet/release/phase-review.mjs gate \
     contrib/attacknet/release/phase-0-contract.json \
     /path/to/packet.json /path/to/codex.json /path/to/opus.json
   ```

Only `{"status":"Approved for Release 1 scope",...}` closes the Release 1
checkpoint. Store the immutable
packet and both review records in an external review archive after the signed
candidate commit exists. The examples below use the locally ignored
`.docs/reviews/attacknet-phase-N/` scratch path; those files are not repository
artifacts. Until then, use `In review`; never mint a placeholder approval.

For Phase 0, first record the actual successful offline run, then generate the
immutable review packet outside the candidate commit. This avoids both a
commit-hash self-reference and a hand-authored test claim:

```bash
ATTACKNET_OFFLINE_RESULT=/tmp/phase-0-offline-result.json \
  contrib/attacknet/test/check.sh
node contrib/attacknet/release/phase-zero-packet.mjs \
  --offline-result=/tmp/phase-0-offline-result.json \
  --output=.docs/reviews/attacknet-phase-0/packet.json
```

The builder fails if the offline result or any historical evidence is absent.
The unit suite injects a synthetic inventory, so clean-clone CI does not need
the gitignored historical archive merely to test packet semantics.

Phase 1 uses a Full packet. Its live summary must pin the signed candidate,
the externally archived evidence plus archive index, each load-bearing live
artifact, and every required passed assertion. Generate it only after the
post-commit baseline and negative controls complete:

```bash
node contrib/attacknet/release/phase-one-packet.mjs \
  --live-summary=.docs/reviews/attacknet-phase-1/live-summary.json \
  --offline-result=.docs/reviews/attacknet-phase-1/offline-result.json \
  --output=.docs/reviews/attacknet-phase-1/packet.json
```

The builder rejects a dirty candidate, a live run pinned to another commit,
artifact or archive drift, and any missing/failed live assertion. An archive
path without a verified digest is not evidence custody.

Phase 2 was planned as Reduced, but its final candidate also hardens review
evidence semantics and corrects the post-chaos progress window. Its packet is
therefore truthfully upgraded to Full by the compatibility rules. The builder
requires compatible-doctor evidence, complete live human and agent facade
workflows, a bounded fault and evidence capture through that facade, the
cadence-aware progress artifact, and clean teardown:

```bash
node contrib/attacknet/release/phase-two-packet.mjs \
  --live-summary=.docs/reviews/attacknet-phase-2/live-summary.json \
  --offline-result=.docs/reviews/attacknet-phase-2/offline-result.json \
  --output=.docs/reviews/attacknet-phase-2/packet.json
```

Release 1 amendment A1 follows Phase 2 without reusing the plan's Phase 3,
which remains reserved for portable deployment profiles. A1 removes the
unreleased Compose runtime and narrows the Release 1 baseline to Kubernetes.
It is Full-tier because runtime behavior and evidence interpretation change.
The packet requires a single signed amendment commit, the exact binary diff,
both offline suite results, and a live Kubernetes apply, verify, bounded fault,
capture, and clean teardown:

```bash
node contrib/attacknet/release/release-1-a1-packet.mjs \
  --live-summary=.docs/reviews/attacknet-release-1-a1/live/live-summary.json \
  --offline-result=.docs/reviews/attacknet-release-1-a1/live/offline-result.json \
  --hacknet-result=.docs/reviews/attacknet-release-1-a1/live/hacknet-result.json \
  --output=.docs/reviews/attacknet-release-1-a1/packet.json
```

See `contrib/attacknet/evidence-packets/release-1-a1/README.md` for the complete
evidence procedure. The gate result must identify
`release-1-amendment-a1-compose-retirement`.

## Evidence preservation

Every packet inventory `path` is a portable, forward-slash relative locator.
The path a packet builder uses to read local bytes is deliberately separate:
tracked-source locators resolve against the candidate checkout, and external
evidence and test locators resolve against `evidenceRoot`, itself relative to
the directory containing the packet. Phase 2 requires this explicit root;
Phase 0 and Phase 1 packets predate the field and retain their approved v1
layout. Absolute
workstation paths and parent traversal are rejected.

`baseline.mjs validate --verify-evidence` reads reference artifacts and checks
their byte digests. A mutation negative control changes fixture bytes and proves
that validation fails. The evidence directory is intentionally outside the ordinary
tracked source surface because it can be large; the baseline manifest is the
tracked integrity and capability index. Archive the referenced bundles before
discarding a local cluster or workstation.

## Trust boundary

Each verdict states whether material was read directly or relayed, but the
review gate cannot establish that a reviewer fetched bytes, understood a
security argument, or used the named model. It prevents accidental digest
drift, incomplete inventory, silence-as-consent, and partial-review promotion.
Human custody of the relayed Claude Opus 5 review remains part of the Release 1
process.
