# Deliberately modified actors

Attacknet adversaries are separately built artifacts, never runtime switches in
a production image. The control plane records their source, patch, Cargo
features, build recipe, OCI image, configuration, admitted Pod identity, and
policy digest before accepting an experiment as attributable.

## Deterministic signer fixture

The Release 1 fixture is
[`../../test/fixtures/adversaries/deterministic-signer.patch`](../../test/fixtures/adversaries/deterministic-signer.patch).
It is compiled only with the existing `stacks-signer/testing` Cargo feature and
implements the versioned `stacks-signer-testing/v1` policy contract:

- `withhold` omits this signer's matching proposal response;
- `delay` waits a bounded `1ms..120s` before the first matching outgoing
  response; and
- `suppress-peer-responses` ignores matching responses from other signers.

Height, hash-prefix, seeded every-Nth, maximum-evaluation, and maximum-match
selectors are deterministic and conjunctive. The evaluation bound also caps
retained retry decisions. Unknown policy fields, versions, behaviors, or unsafe
bounds terminate at startup. Without the testing feature the policy code path
and its testing metric are absent.

The seed applies to this testing policy, not to the node's internal P2P and
relay random generators. Replay establishes the same bounded policy outcome
under the same sealed inputs; it does not promise identical peer selection,
transport ordering, timings, block hashes, or logs. See
[`Reproducibility`](reproducibility.md) for the product-wide boundary.

Build from a dedicated source worktree so the ordinary source remains clean:

```bash
git worktree add /tmp/stacks-attacknet-adversarial-signer HEAD
git -C /tmp/stacks-attacknet-adversarial-signer apply \
  "$PWD/contrib/attacknet/test/fixtures/adversaries/deterministic-signer.patch"
```

Build with `monitoring_prom`, `slog_json`, and `testing`; retain the source and
patch digests; and give the result a content-derived image tag. In the
`StacksNetwork`, assign the image explicitly to each adversarial signer and
declare its typed `adversarial` policy. The topology operator injects only the
canonical policy and its digest. The policy remains inert until a campaign
activates an identity-bound session through the signer Pod's read-only
Downward API channel.

## Isolation and evidence

The restricted profile gives the actor a topology-owned default-deny egress
policy with only declared protocol peers and cluster DNS. Startup dependencies
and permitted egress peers are distinct: a signer may contact its declared
Stacks node without waiting for that node at startup, avoiding a signer/node
bootstrap cycle. Its admitted policy-spec digest is part of network identity.
`unrestricted` is an explicit, recorded escape hatch, not the default.

Each adversarial signer receives a separate observer Pod and network namespace.
The observer has no service-account token and signs nonce-bound reports with an
ephemeral Ed25519 key. The run controller learns that key through its first
nonce challenge, pins it for the observation window, and rechecks target and
observer image and Pod identity through its uncached reader. Trust comes from
the admitted observer image and live Pod identity, not from a self-asserted key.

The testing counter is still actor-self-reported. A signed observer report
proves who transported it, not that the signer told the truth or harmed the
network. The observer also transports the session-active gauge: baseline must
be inactive, effect must be active with an increasing match counter, and
recovery must return inactive. Pair `SignerBehaviorObserved` with protocol
assertions and honest cohort observations. Missing or ambiguous corroboration
is `Inconclusive`, never `Passed`.

Retained raw reports can be independently checked with
`attacknet evidence verify-signer-report`. The verifier binds the observer,
target, policy digest, nonce, optional key identity, observation interval, and
signed payload; it does not elevate actor-self-reported content to trusted
protocol evidence.

See [`signer-behavior`](../reference/faults/signer-behavior.md) for the topology
and campaign API, bounds, assertions, and a complete example.
