# Deliberately modified actors

Attacknet adversaries are separately built artifacts, never runtime switches in
a production image. The control plane records their source patch, Cargo feature
set, OCI provenance, admitted Pod UID, and runtime image ID before treating an
experiment as attributable.

The first bounded fixture is `adversaries/rejecting-signer.patch`. It adds an
environment-controlled directive only when the existing `stacks-signer/testing`
Cargo feature is compiled:

- `STACKS_SIGNER_TEST_DIRECTIVE=reject-all` emits signed
  `TestingDirective` rejections for every proposal;
- `STACKS_SIGNER_TEST_DIRECTIVE=ignore-all` remains silent for every proposal;
- any other value terminates at startup instead of silently running honestly.

This fixture exercises Byzantine availability and negative-vote behavior. It
does not create signatures for another signer, weaken the 70% threshold,
renormalize weight, or contain a fund-stealing implementation. Start with a
below-threshold signer and require the current cohort to continue; quorum-loss
experiments require the existing explicit safety opt-in.

Build it from a dedicated worktree so the normal source tree remains unchanged:

```bash
git worktree add /tmp/stacks-attacknet-rejecting-signer HEAD
git -C /tmp/stacks-attacknet-rejecting-signer apply \
  "$PWD/contrib/attacknet/adversaries/rejecting-signer.patch"
```

Point a `localModified` image-build profile at that worktree and set
`cargoFeatures` to `monitoring_prom`, `slog_json`, and `testing`. The image
pipeline hashes the patch-bearing source state and passes the normalized feature
set to both Cargo Chef and the final build. Assign the resulting image and
directive to one actor while rendering:

```bash
node contrib/attacknet/topology.mjs \
  --signers=4 \
  --actor-image=signer-1=stacks-core-attacknet:content-REPLACE \
  --actor-env=signer-1:STACKS_SIGNER_TEST_DIRECTIVE=reject-all \
  --output=contrib/attacknet/generated/adversarial-signer
```

The directive is not accepted by a normal image: without the testing feature it
has no effect. Acceptance must therefore verify both the immutable build record
and an attributable `TestingDirective` response from the selected signer. Logs
and metrics remain actor-self-reported and must be corroborated by the miner,
other signers, Kubernetes identity, and canonical chain progress.
