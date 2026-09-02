# Phase 2 review evidence

Phase 2 uses the shared digest-bound review contract rather than a hand-authored
packet template. The tracked contract is
`contrib/attacknet/release/phase-2-contract.json`; the packet builder is
`contrib/attacknet/release/phase-two-packet.mjs`.

The candidate changes both evidence interpretation and the post-chaos progress
window, so the builder truthfully upgrades the planned Reduced review to Full.
It requires a clean signed commit, an externally archived live evidence bundle,
portable archive-relative artifact locators, a compatible `doctor` report, and
complete human and agent workflow evidence. Read-only plans from a dirty tree
are developer diagnostics, not release evidence, and are not checked in.

After the signed commit exists:

1. Run `contrib/attacknet/attacknet doctor --json` and retain the result.
2. Have both a human and an agent use only the public facade to render, start,
   inspect, inject a bounded fault, capture evidence, and delete disposable
   networks.
3. Record the cadence-aware progress-window artifact and prove clean teardown.
4. Archive the evidence with a relative-path digest index and build a live
   summary matching `stacks-attacknet-phase-2-live-evidence/v1`.
5. Generate a canonical offline result from the exact candidate and build the
   packet:

   ```bash
   node contrib/attacknet/release/phase-two-packet.mjs \
     --live-summary=.docs/reviews/attacknet-phase-2/live-summary.json \
     --offline-result=.docs/reviews/attacknet-phase-2/offline-result.json \
     --output=.docs/reviews/attacknet-phase-2/packet.json
   ```

Before reviewing, compare the packet's `toolingDigest` with:

```bash
node contrib/attacknet/release/phase-review.mjs tooling-digest
```

A mismatch means the verifier is from another revision. It is not, by itself,
evidence of packet tampering.
