# Release 1 amendment A1 review evidence

Amendment A1 retires the unreleased Compose runtime and narrows Release 1 to
Kubernetes. It is a new revision-bound review checkpoint; it does not rewrite
or invalidate the approved Phase 0, 1, or 2 packets.

The tracked contract is
`contrib/attacknet/release/release-1-a1-contract.json`. The review packet and
live evidence remain outside Git in the review archive.

The packet builder enforces this portable shape; every packet evidence path
resolves through the single `live/` root. Artifact filenames are the safe
relative entries declared by the live summary:

```text
attacknet-release-1-a1/
├── packet.json
└── live/
    ├── archive/<archive>.tar.gz
    ├── <archive-index>.json
    ├── <candidate-diff>
    ├── <doctor-artifact>
    ├── <lifecycle-apply-artifact>
    ├── <verification-artifact>
    ├── <fault-run-artifact>
    ├── <evidence-capture-artifact>
    ├── <clean-teardown-artifact>
    ├── hacknet-result.json
    ├── live-summary.json
    └── offline-result.json
```

## Evidence procedure

After creating the single hardware-signed amendment commit:

1. Confirm it descends from approved Phase 2 commit
   `7d4a734077bb7216a813b9e8de0ade65fa7b5ec6` and has exactly one parent.
2. Generate the exact candidate diff:

   ```bash
   git diff --binary HEAD^ HEAD >.docs/reviews/attacknet-release-1-a1/live/candidate.patch
   ```

3. Generate source-bound offline results:

   ```bash
   ATTACKNET_OFFLINE_RESULT=.docs/reviews/attacknet-release-1-a1/live/offline-result.json \
     contrib/attacknet/check.sh

   HACKNET_OFFLINE_RESULT=.docs/reviews/attacknet-release-1-a1/live/hacknet-result.json \
     contrib/helm/hacknet/scripts/check.sh
   ```

4. On the supported local three-node arm64 `kind` profile, use only the public
   facade to run a small topology through apply, verification, one bounded
   reversible fault, evidence capture, and deletion. Retain `doctor` output,
   lifecycle output, verification JSON, fault evidence, capture evidence, and
   proof that the `StacksNetwork`, actor Pods, and actor PVCs are gone.
5. Build a portable relative-path archive index, archive the complete evidence,
   and write a live summary using schema
   `stacks-attacknet-release-1-a1-live-evidence/v1`. Its required assertions are:
   `supported-environment-doctor`, `kubernetes-apply-complete`,
   `kubernetes-verification-passed`, `bounded-fault-effect-and-recovery`,
   `evidence-capture-complete`, and `clean-teardown`.
6. Generate the packet:

   ```bash
   node contrib/attacknet/release/release-1-a1-packet.mjs \
     --live-summary=.docs/reviews/attacknet-release-1-a1/live/live-summary.json \
     --offline-result=.docs/reviews/attacknet-release-1-a1/live/offline-result.json \
     --hacknet-result=.docs/reviews/attacknet-release-1-a1/live/hacknet-result.json \
     --output=.docs/reviews/attacknet-release-1-a1/packet.json
   ```

Both Codex and Claude Opus 5 must directly read the signed candidate, packet,
archive, and complete inventory. Evaluate their verdicts against
`release-1-a1-contract.json`. The gate must return the review ID
`release-1-amendment-a1-compose-retirement`; a Phase 0–2 approval cannot
substitute for this amendment review.
