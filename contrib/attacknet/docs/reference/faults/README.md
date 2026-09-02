# Fault reference

Attacknet faults are declared as actions in a
`testing.stacks.org/v1beta1` `FaultCampaign`. The controller resolves each
action against the admitted `StacksNetwork`, checks aggregate safety, injects
the mutation, verifies its effect, cleans it up, and verifies recovery.

## Supported fault types

| Fault type | Backend | Actions | Primary use |
| --- | --- | --- | --- |
| [`pod`](pod.md) | Chaos Mesh `PodChaos` | `pod-kill`, `pod-failure`, `container-kill` | Process and Pod availability |
| [`network`](network.md) | Chaos Mesh `NetworkChaos` | `netem`, `delay`, `loss`, `duplicate`, `corrupt`, `partition`, `bandwidth` | P2P, RPC, and telemetry paths |
| [`dns`](dns.md) | Chaos Mesh `DNSChaos` | `error`, `random` | Name-resolution failures |
| [`io`](io.md) | Chaos Mesh `IOChaos` | `latency`, `fault`, `attrOverride`, `mistake` | Filesystem calls on supported hosts |
| [`time`](time.md) | Chaos Mesh `TimeChaos` | Action omitted | Native container clock manipulation |
| [`io-pressure`](io-pressure.md) | Controller-owned restricted Pod | `disk-pressure` | Portable pressure on an actor PVC |
| [`clock-skew`](clock-skew.md) | Controller-owned clock policy | Action omitted | Portable application wall-clock skew |
| [`burnchain-reorg`](burnchain-reorg.md) | Controller-owned regtest worker | Action omitted | Bounded Bitcoin branch replacement |
| [`signer-behavior`](signer-behavior.md) | Controller-owned observation session | `withhold`, `delay`, `suppress-peer-responses` | Deterministic testing-only signer behavior |

## Backends and trust

Chaos Mesh faults compile to namespaced Chaos Mesh custom resources. Attacknet
owns their lifecycle, but a Chaos Mesh condition alone does not prove that the
actor experienced the requested effect. Trusted probes and Kubernetes state
provide effect and recovery evidence.

Controller-owned faults implement semantics that Chaos Mesh does not provide
portably or safely enough for Release 1:

- `io-pressure` runs a fixed, chart-configured image against the admitted
  actor PVC. Campaigns cannot supply a command or image.
- `clock-skew` changes an operator-owned clock-policy ConfigMap consumed by an
  instrumented actor image.
- `burnchain-reorg` uses a closed, typed Bitcoin regtest RPC client and a
  policy pause/restore handshake. It is not an arbitrary RPC facility.
- `signer-behavior` observes a signer policy already admitted by the topology
  operator. It never rewrites a StatefulSet or activates behavior dynamically.

All backends use the same identity pinning, aggregate safety, evidence, cleanup,
and terminal classification. Missing or ambiguous proof produces
`Inconclusive`, never `Passed`.

## Author a campaign

The smallest executable shape is:

```yaml
apiVersion: testing.stacks.org/v1beta1
kind: FaultCampaign
metadata:
  name: example-delay
spec:
  networkRef: minimal
  safety:
    maxUnavailableSignerBasisPoints: 0
    maxUnavailableMinerBasisPoints: 0
    maxConcurrentFaults: 1
  stages:
    - id: disrupt
      faults:
        - id: delay-follower
          target:
            actors: [follower-1]
          fault:
            type: network
            action: delay
            mode: all
            duration: 15s
            parameters:
              direction: both
              peerTarget:
                actors: [bitcoin]
              delay:
                latency: 500ms
          effectAssertions:
            - type: NetworkDegraded
              actor: follower-1
              timeoutSeconds: 60
          recoveryAssertions:
            - type: NetworkRecovered
              actor: follower-1
              timeoutSeconds: 180
```

Set `spec.template: true` and omit `networkRef` for an inert catalog entry that
an `AttacknetRun` will bind to an admitted network. Applying a template does not
inject its faults.

### Select actors and cardinality

`target.actors` and `target.roles` select enrolled candidates. When both are
present, the controller uses their intersection. The actor names, images, Pod
UIDs, and controller identities are pinned at admission and rechecked before
mutation.

For ordinary faults, `fault.mode` controls how many candidates Chaos Mesh
selects:

| Mode | `value` | Meaning |
| --- | --- | --- |
| `one` | Omit | One candidate |
| `all` | Omit | Every candidate |
| `fixed` | Required positive integer | Exactly `value` candidates |
| `fixed-percent` | Required `1..100` | Fixed percentage of candidates |
| `random-max-percent` | Required `1..100` | Random count up to the percentage |

`target.mode` and `target.value` are not the cardinality controls for ordinary
faults; omit them. `burnchain-reorg` is the sole exception and requires both
`target.mode: one` and `fault.mode: one`.

Network `peerTarget` has its own nested mode because it independently selects
the remote side of a network fault. See [`network`](network.md).

### Duration and safety

Durations use integer `ms`, `s`, `m`, or `h` values and must be positive and no
longer than 24 hours. More than 10 minutes requires
`safety.allowExtendedDuration`; more than one hour also requires
`safety.allowExtremeSeverity`. Individual parameters have tighter limits in
their fault-specific documents.

Safety is evaluated over all actions that can overlap, not one action at a
time. Every campaign declares:

- maximum unavailable signer and miner weight in basis points;
- maximum concurrent faults; and
- explicit opt-ins for quorum loss, burnchain mutation, extreme severity,
  long duration, miner-majority outage, or unenrolled network targets when the
  requested scenario needs them.

| Safety field | Contract |
| --- | --- |
| `maxUnavailableSignerBasisPoints` | `0..10000`; aggregate selected signer weight may not exceed it unless `allowQuorumLoss` is true |
| `maxUnavailableMinerBasisPoints` | `0..10000`; aggregate selected miner share may not exceed it unless `allowMinerMajorityOutage` is true |
| `maxConcurrentFaults` | Required `1..512`; aggregate overlapping actions may never exceed it |
| `allowQuorumLoss` | Conspicuous opt-in to exceed the signer-weight ceiling |
| `allowMinerMajorityOutage` | Conspicuous opt-in to exceed the miner ceiling |
| `allowBurnchain` | Required when selecting a burnchain actor or using `burnchain-reorg` |
| `allowExtendedDuration` | Required for a fault longer than 10 minutes |
| `allowExtremeSeverity` | Required for a fault longer than one hour and for fault-specific extreme values |
| `allowUnenrolledNetworkTargets` | Required for raw `network` targets or `externalTargets` |
| `maxBurnchainReorgDepth` | Campaign ceiling `0..144`; must cover each requested reorganization depth |
| `maxBurnchainReplacementBlocks` | Campaign ceiling `0..288`; must cover each replacement branch |
| `allowEpochBoundaryCrossing` | Opt-in for a reorganization crossing an epoch boundary |
| `allowRewardCycleBoundaryCrossing` | Opt-in for a reorganization crossing a reward-cycle or PoX prepare boundary |

Separate campaigns share a namespace mutation lease. Put intentionally
concurrent actions in one campaign so the controller can assess their combined
impact. Shared clock-policy or burnchain-policy mutations cannot overlap on the
same actor.

### Stages and triggers

A campaign has 1–16 stages and each stage has 1–32 actions. A stage may start
immediately or from one trigger:

- elapsed time after campaign start;
- a prior stage reaching `Injected`, `Effective`, `Recovered`, or `Terminal`;
- a trusted burn height or Stacks height; or
- a finite trusted observation.

Use `maxStartSkew` when simultaneous actions are part of the hypothesis. If
partial injection occurs, the controller rolls back the injected subset rather
than treating it as the intended concurrent experiment. See
[`run scheduling`](../../concepts/run-scheduling.md) for run-level scheduling.

### Assertions and outcomes

Action-level assertions are clearest because their target is unambiguous. A
stage- or campaign-level assertion must set `action` when more than one action
is in scope.

| Fault family | Effect assertions | Recovery assertions |
| --- | --- | --- |
| Pod | `PodRestarted`, `PodUnavailable`, `ContainerRestarted` | `TargetReady` |
| Network | `NetworkDegraded` | `NetworkRecovered` |
| DNS | `DNSDegraded` | `DNSRecovered` |
| I/O | `IODegraded`, `IOPressureObserved` | `IORecovered`, `IOPressureRecovered` |
| Clock | `ClockSkewObserved` | `ClockSkewCleared` |
| Burnchain | `BurnchainReorgProven` | `BurnchainPolicyRestored` |
| Signer behavior | `SignerBehaviorObserved` | `SignerBehaviorWindowClosed` |

A mutation reporting success is not sufficient. Attacknet reports `Passed`
only after required effects, recovery, and cleanup are independently proven.
Consult [`evidence`](../../operations/evidence.md) before interpreting a
terminal campaign.

## Validate, submit, and inspect

Run these commands from the repository root after the referenced network is
Ready:

```bash
ATTACKNET=${ATTACKNET:-/tmp/stacks-attacknet}
FILE=contrib/helm/hacknet/examples/fault-campaign-minimal.yaml

$ATTACKNET validate --file "$FILE"
$ATTACKNET submit --namespace hacknet-system --file "$FILE"
$ATTACKNET wait --namespace hacknet-system --for terminal \
  FaultCampaign minimal-follower-restart
$ATTACKNET get --namespace hacknet-system \
  FaultCampaign minimal-follower-restart
```

Use `kubectl describe` for conditions and Kubernetes Events. Preserve the
terminal resource, controller logs, admitted identity, probes, metrics, and
owned mutation objects in the incident bundle before deleting the campaign.
