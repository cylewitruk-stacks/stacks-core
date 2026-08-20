# Attacknet phase review packets

Attacknet productization phases close only through a digest-bound packet and
two complete approvals. The machine gate is intentionally narrower than a
code-review system: it proves that both recorded verdicts name the same
declared source, evidence, and complete inventory. It does not pretend that a
digest proves what a human or model actually inspected.

## Packet lifecycle

1. Freeze the candidate commit. The packet builder derives the exact `HEAD`,
   tracked diff, and untracked-file digest directly from Git. There is no
   `--committed` override: a packet with `candidate.commitPending=true` can be
   inspected, but the machine gate refuses to approve its phase.
2. Populate the phase contract's complete, non-empty `requiredInventory` in a packet that
   follows `review-packet.schema.json`. Hash files byte-for-byte and build the
   packet's `sourceDigest` and `evidenceDigest` from their respective immutable
   inventories.
   The local schema validator deliberately implements a finite JSON Schema
   subset and rejects every keyword outside that subset. Structural keywords
   such as `properties`, `items`, and `pattern` also require their explicit
   compatible `type`; unsupported or ambiguous schema changes therefore stop
   packet validation instead of silently weakening it.
3. Bind `contractDigest` to the exact contract and set `binding.digest` to the SHA-256 digest of canonical packet JSON with the
   entire `binding` member omitted. `phase-review.mjs` performs this same
   calculation.
4. Give each reviewer the complete packet and every inventory item. A reduced
   packet records non-applicable full-tier material explicitly in its matrix;
   it does not silently omit it.
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
  contrib/attacknet/check.sh
node contrib/attacknet/release/phase-zero-packet.mjs \
  --offline-result=/tmp/phase-0-offline-result.json \
  --output=.docs/reviews/attacknet-phase-0/packet.json
```

The builder fails if the offline result or any historical evidence is absent.
The unit suite injects a synthetic inventory, so clean-clone CI does not need
the gitignored historical archive merely to test packet semantics.

## Evidence preservation

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
