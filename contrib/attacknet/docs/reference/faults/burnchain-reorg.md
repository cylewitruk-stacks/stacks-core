# Bounded Bitcoin reorganization faults

| Contract | Value |
| --- | --- |
| Fault type | `burnchain-reorg` |
| Backend | Controller-owned regtest worker (`BurnchainReorgWorker`) |
| Action | Omitted |
| Effect assertion | `BurnchainReorgProven` |
| Recovery assertion | `BurnchainPolicyRestored` |

A burnchain reorganization replaces a bounded suffix of exactly one Bitcoin
regtest actor with a longer, higher-work branch. It is deliberately semantic:
the API exposes a finite reorganization operation, not arbitrary Bitcoin RPC.

## Required shape

```yaml
target:
  actors: [bitcoin-1]
  mode: one
fault:
  type: burnchain-reorg
  mode: one
  duration: 30s
  burnchainReorg:
    depth: 2
    replacementBlocks: 3
    replacementInterval: 1s
    destinationIndex: 0
```

The target must name one admitted actor with role `burnchain`; roles, target
value, fault value, action, and raw parameters are forbidden.

## Reorganization fields

| Field | Contract |
| --- | --- |
| `depth` | Integer `1..144` and no greater than the observed tip |
| `replacementBlocks` | Integer `2..288` and strictly greater than `depth` |
| `replacementInterval` | Optional duration `0..1h` |
| `destinationIndex` | Optional bounded mining destination index `0..63` |

The replacement schedule must fit within `fault.duration`:
`(replacementBlocks - 1) * replacementInterval <= duration`.

## Safety and boundary invariants

Every campaign must set:

```yaml
safety:
  allowBurnchain: true
  maxBurnchainReorgDepth: 2
  maxBurnchainReplacementBlocks: 3
```

The safety maxima must cover the requested values. If the inclusive replaced
height interval crosses an epoch boundary, set
`allowEpochBoundaryCrossing: true`. If it crosses a reward-cycle or PoX prepare
boundary, set `allowRewardCycleBoundaryCrossing: true`. When the protocol
schedule cannot be established, both opt-ins are required; uncertainty is not
treated as a safe interval.

Only Bitcoin `regtest` is accepted. Before mutation the controller verifies the
exact chain precondition, pauses the actor's `BurnchainPolicy`, waits for that
generation to become Ready, and binds the worker to a validated Pod annotation.
A stale precondition changes no blocks. Cleanup restores the original policy,
and policy restoration must be proven separately from branch replacement.

Overlapping reorganization actions cannot target the same Bitcoin actor.

## Complete example

```yaml
apiVersion: testing.stacks.org/v1beta1
kind: FaultCampaign
metadata:
  name: bitcoin-two-block-reorg
spec:
  template: true
  safety:
    maxUnavailableSignerBasisPoints: 0
    maxUnavailableMinerBasisPoints: 0
    maxConcurrentFaults: 1
    allowBurnchain: true
    maxBurnchainReorgDepth: 2
    maxBurnchainReplacementBlocks: 3
  stages:
    - id: replace-bitcoin-tip
      faults:
        - id: reorg-bitcoin-1
          target:
            actors: [bitcoin-1]
            mode: one
          fault:
            type: burnchain-reorg
            mode: one
            duration: 30s
            burnchainReorg:
              depth: 2
              replacementBlocks: 3
              replacementInterval: 1s
              destinationIndex: 0
          effectAssertions:
            - type: BurnchainReorgProven
              actor: bitcoin-1
              timeoutSeconds: 120
          recoveryAssertions:
            - type: BurnchainPolicyRestored
              actor: bitcoin-1
              timeoutSeconds: 120
```

Examples and concepts:

- [`bitcoin-two-block-reorg.yaml`](../../../examples/campaigns/bitcoin-two-block-reorg.yaml)
- [`bitcoin-competing-branches.yaml`](../../../examples/campaigns/bitcoin-competing-branches.yaml)
- [`Bitcoin reorganizations`](../../concepts/bitcoin-reorganizations.md)
- [`Multi-Bitcoin split views`](../../concepts/bitcoin-split-views.md)
