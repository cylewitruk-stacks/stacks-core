# Deliberately modified actors

Attacknet adversaries are separately built artifacts, never runtime switches in
a production image. The control plane records their source patch, Cargo feature
set, OCI provenance, admitted Pod UID, and runtime image ID before treating an
experiment as attributable.

The first bounded fixture is
[`../../test/fixtures/adversaries/rejecting-signer.patch`](../../test/fixtures/adversaries/rejecting-signer.patch).
It adds an
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
  "$PWD/contrib/attacknet/test/fixtures/adversaries/rejecting-signer.patch"
```

Build the patched worktree with the `monitoring_prom`, `slog_json`, and
`testing` features, retain its source/build provenance, and give it a distinct
content-derived tag. Assign the image and directive to exactly one actor in a
v1beta1 `StacksNetwork`, then validate the resource:

```bash
attacknet validate --file adversarial-network.yaml
attacknet submit --namespace hacknet-system --file adversarial-network.yaml
```

The directive is not accepted by a normal image: without the testing feature it
has no effect. Acceptance must therefore verify both the immutable build record
and an attributable `TestingDirective` response from the selected signer. Logs
and metrics remain actor-self-reported and must be corroborated by the miner,
other signers, Kubernetes identity, and canonical chain progress.
