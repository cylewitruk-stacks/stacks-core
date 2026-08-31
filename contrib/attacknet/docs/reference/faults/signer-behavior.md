# Deterministic signer-behavior observations

| Contract | Value |
| --- | --- |
| Fault type | `signer-behavior` |
| Mutation kind | `SignerBehaviorSession` |
| Backend | Identity-bound signer Pod session annotation |
| Actions | `withhold`, `delay`, `suppress-peer-responses` |
| Effect assertion | `SignerBehaviorObserved` |
| Recovery assertion | `SignerBehaviorWindowClosed` |

This mechanism activates a bounded observation window for behavior already
compiled into a testing-only signer image. It cannot turn a normal image
adversarial. The requested action and policy digest must match the signer's
admitted topology identity.

## Required topology

Declare `adversarial` on a v1beta1 signer member. The signer must have an
explicit image and an isolated observer image:

```yaml
signerSets:
  - name: signers
    members:
      - name: signer-1
        nodeName: signer-node-1
        index: 1
        weight: 1
        signerImage: local/stacks-signer-adversarial:r1a12
        adversarial:
          profile: stacks-signer-testing/v1
          behavior: withhold
          maxMatches: 2
          maxEvaluations: 32
          patchDigest: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          selector:
            everyNth: 2
            seedOffset: 0
          observer:
            image: local/attacknet-probe:r1a12
            imagePullPolicy: IfNotPresent
          egress:
            profile: restricted
```

Selectors are conjunctive. `minStacksHeight` and `maxStacksHeight` are
inclusive; `everyNth` is `1..1024`; `seedOffset` must be smaller than it;
`proposalHashPrefix` is 2–32 lowercase hexadecimal characters; and
`maxMatches` is `1..1024`; `maxEvaluations` is
`maxMatches..65536` and bounds retained match and non-match decisions. `delay`
additionally requires a duration of `1ms..120s`.
`suppress-peer-responses` accepts only hash-prefix selection because peer
responses do not carry a Stacks height or publication ordinal.

The default `restricted` egress profile permits declared protocol peers and
cluster DNS. A signer-to-node permission is recorded separately from startup
dependencies so the node-to-signer bootstrap relationship cannot deadlock.
Its admitted `NetworkPolicy` spec digest participates in the network
inventory. `unrestricted` requires the conspicuous
`allowUnrestricted: true` escape hatch and is recorded in admitted evidence.

## Campaign shape

```yaml
apiVersion: testing.stacks.org/v1beta1
kind: FaultCampaign
metadata:
  name: signer-withhold-window
spec:
  networkRef: adversarial-demo
  safety:
    maxUnavailableSignerBasisPoints: 3400
    maxUnavailableMinerBasisPoints: 0
    maxConcurrentFaults: 1
  stages:
    - id: observe
      faults:
        - id: signer-1-withhold
          target:
            actors: [signer-1]
            mode: all
          fault:
            type: signer-behavior
            action: withhold
            mode: all
            duration: 45s
            signerBehavior:
              policyDigest: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          effectAssertions:
            - type: SignerBehaviorObserved
              actor: signer-1
          recoveryAssertions:
            - type: SignerBehaviorWindowClosed
              actor: signer-1
```

Each action must name exactly one signer actor. `fault.mode` and `target.mode`
must both be `all`; role selectors, values, and raw parameters are forbidden.
Use separate actions to activate multiple independently attributable signers,
including concurrent actions in one stage. The duration is positive and no
more than 10 minutes. Existing aggregate signer-weight limits and the
quorum-loss opt-in still apply.

The policy is inert at startup. At injection, the controller rechecks the
exact Ready Pod through its uncached reader and writes a canonical session to
the bounded `testing.stacks.org/adversarial-session` Pod annotation. A
read-only Downward API volume presents that session to the signer. The session
binds the campaign UID, actor, action, policy digest, and schema version. The
controller removes it during recovery; it never patches the StatefulSet or
changes the admitted image or policy.

Kubelet updates Downward API projections asynchronously. Set the recovery
assertion timeout high enough to cover the cluster's projected-volume refresh
bound plus signer sampling. An expired recovery remains `Inconclusive`, and
cleanup remains idempotent after the annotation has already disappeared.
Post-active recovery uses the canonical signer weights sealed in campaign
admission rather than depending on a newer reward-cycle RPC observation. Live
reward-set resolution remains mandatory before and during activation.
The testing-only signer refreshes the session-active metric every 500 ms from
the projected contract, independently of proposals and peer responses. This
keeps recovery observable even when the requested behavior stalls the protocol
traffic that would otherwise refresh the metric.

## Evidence and interpretation

Before, during, and after samples come from a separately scheduled observer
Pod. Each report binds a fresh nonce, observer identity, target actor, policy
digest, observation time, and Ed25519 signature. The controller reads the
observer Pod through its uncached API reader, learns the ephemeral key through
the first nonce challenge, and requires that key to remain stable throughout
the window. The admitted observer image and Pod—not the self-asserted key
alone—establish the observer boundary.

The observer independently transports the sample, but the policy-match counter
and session-active gauge are actor-self-reported. Baseline requires the policy
to be inactive; effect requires an active bound session and an increasing
match counter; recovery requires the signer to report the session inactive.
`SignerBehaviorObserved` therefore proves a bounded testing policy attempt,
not network harm. Pair it with run-level protocol assertions and honest-cohort
observations before concluding that the behavior changed liveness or
consensus. Missing, forged, replayed, identity-shifted, or non-increasing
evidence is `Inconclusive`, never a successful effect.

Verify an exported report independently:

```bash
attacknet evidence verify-signer-report \
  --file signer-1-during.json \
  --actor signer-1-observer \
  --target signer-1 \
  --policy-digest sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --nonce 0123456789abcdef0123456789abcdef \
  --key-id sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd
```

Use the exact nonce and key identity retained by the campaign. Optional
`--not-before` and `--not-after` RFC3339 bounds enforce the admitted observation
interval. Verification failure returns non-zero and cannot produce evidence.
