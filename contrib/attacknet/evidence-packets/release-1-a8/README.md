# Release 1 Amendment A8 evidence

This directory is the packet root for the Full-tier trusted-observation and
forensic-completeness amendment.

Qualification is bound to the exact staged Git tree before the final commit.
The expensive checks and live run execute once. Afterward, one hardware-signed
commit must contain that exact tree; packet assembly only binds the signature
and commit identity to the already-sealed evidence.

Place the generated files under this gitignored layout:

```text
release-1-a8/
├── review-packet.json
└── evidence/
    ├── candidate-attestation.json
    ├── summary.json
    ├── archive-index.json
    ├── artifacts/
    └── archive/
```

Stage the final product tree, generate offline verification, run the three-node
`kind` qualification, and seal the evidence archive with:

```bash
REVIEW_ROOT="$PWD/.docs/reviews/attacknet-release-1-a8"
RAW="$REVIEW_ROOT/raw"
QUALIFIED_TREE="$(git write-tree)"

node contrib/attacknet/release/amendments/a8/verify.mjs \
  --qualified-tree="$QUALIFIED_TREE" --output="$RAW" \
  --envtest-assets="$KUBEBUILDER_ASSETS"

node contrib/attacknet/release/amendments/a8/qualification/live.mjs \
  --qualified-tree="$QUALIFIED_TREE" --output="$RAW"

node contrib/attacknet/release/amendments/a8/evidence.mjs \
  --qualified-tree="$QUALIFIED_TREE" --input="$RAW" \
  --output="contrib/attacknet/evidence-packets/release-1-a8/evidence" \
  --archive-location="file://$PWD/contrib/attacknet/evidence-packets/release-1-a8/evidence/archive"
```

Create or amend the one final hardware-signed commit without changing the
index. Confirm that `git show -s --format=%T HEAD` equals `$QUALIFIED_TREE`,
write the small commit-to-evidence attestation, then assemble the review
manifest. Neither command reruns qualification or rebuilds its archive:

```bash
test "$(git show -s --format=%T HEAD)" = "$QUALIFIED_TREE"

node contrib/attacknet/release/amendments/a8/attest.mjs \
  --candidate="$(git rev-parse HEAD)" \
  --verification="$RAW/verification.json" \
  --summary="contrib/attacknet/evidence-packets/release-1-a8/evidence/summary.json" \
  --output="contrib/attacknet/evidence-packets/release-1-a8/evidence/candidate-attestation.json"

node contrib/attacknet/release/amendments/a8/packet.mjs \
  --output="contrib/attacknet/evidence-packets/release-1-a8/review-packet.json" \
  --summary="contrib/attacknet/evidence-packets/release-1-a8/evidence/summary.json" \
  --attestation="contrib/attacknet/evidence-packets/release-1-a8/evidence/candidate-attestation.json"
```

The qualification runner requires a three-node arm64 kind cluster with the
Attacknet dependencies installed. It re-executes from an object-database
materialization of the qualified tree, builds its own CLI and controller
images, installs and verifies those immutable images on all three nodes, and
records a qualified-tree-bound build receipt. It then
creates the fixed resources under `qualification/`, renders and installs the
network-scoped observability stack, runs all four controls, and refuses to
overwrite existing live evidence in the shared raw directory. The verifier's
offline artifacts remain intact. The source-loss control observes a proven
data-plane fault, pauses the topology reconciler, withdraws one actor metrics
Service, and requires the run to terminate `Inconclusive`; it then restores a
new topology-owned Service while proving the network UID and admitted inventory
did not change. This separates observation-source failure from the active fault
oracle. The failed-export control deliberately scales only the A8 Loki
StatefulSet to zero and proves the exact network UID and inventory digest remain
unchanged before restoring Loki. The final teardown must export a complete
non-empty retained log corpus before network deletion.

The raw qualification input must contain every path declared by
`A8_ARTIFACTS` in `evidence.mjs`. The assembler verifies the terminal run
outcomes, trusted trigger receipt, complete Loki corpus and source identity,
failed-export network preservation, source-loss control identities, qualified
runtime image, and clean teardown before it can emit a passing summary. Packet
build evidence retains the local OCI index digest separately from the arm64
platform runtime digest verified uniformly across all three kind nodes; these
identities are intentionally not required to be equal. Packet
assembly verifies the hardware signature and proves that both the signed tree
and committed binary diff equal the qualified tree and diff; it does not rerun
or regenerate qualification evidence.
