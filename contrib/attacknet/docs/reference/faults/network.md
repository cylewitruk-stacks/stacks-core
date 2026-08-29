# Network faults

| Contract | Value |
| --- | --- |
| Fault type | `network` |
| Backend | Chaos Mesh `NetworkChaos` |
| Actions | `netem`, `delay`, `loss`, `duplicate`, `corrupt`, `partition`, `bandwidth` |
| Effect assertion | `NetworkDegraded` |
| Recovery assertion | `NetworkRecovered` |

Network faults disrupt traffic from selected enrolled actors. Prefer enrolled
peer or harness targets so Attacknet can attribute the requested path and prove
its effect.

## Select the remote side

Use exactly one remote-target form:

| Form | Use |
| --- | --- |
| `peerTarget` | Enrolled actors or roles; recommended for actor-to-actor paths |
| `harnessTarget: prometheus` | The Attacknet Prometheus workload |
| `target` | Raw Chaos Mesh target object; requires `allowUnenrolledNetworkTargets` |
| `externalTargets` | Non-empty unique string array; requires `allowUnenrolledNetworkTargets` |

`peerTarget.actors` and `.roles` use intersection semantics when both appear.
Its optional `mode` is `one`, `all`, `fixed`, `fixed-percent`, or
`random-max-percent`; it defaults to `all`, and `value` follows the same rules
as the campaign fault mode.

`direction` is `to`, `from`, or `both`. It defaults to `both` when a target is
present. `from` and `both` require `peerTarget`, `harnessTarget`, or raw
`target`. Optional `device` and `targetDevice` strings are limited to 64
characters.

Raw and external targets weaken attribution. If no trusted probe can establish
the affected path, the result is `Inconclusive`, not a pass.

## Actions and parameters

| Action | Required parameter | Notes |
| --- | --- | --- |
| `netem` | At least one of `delay`, `loss`, `duplicate`, `corrupt` | Combines supported packet effects |
| `delay` | `delay` object | Latency plus optional jitter and correlation |
| `loss` | `loss` object | Packet-loss percentage |
| `duplicate` | `duplicate` object | Packet-duplication percentage |
| `corrupt` | `corrupt` object | Packet-corruption percentage |
| `partition` | One remote-target form | Blocks the selected path |
| `bandwidth` | `bandwidth` object | Bounds link rate and queue parameters |

Delay object:

```yaml
delay:
  latency: 750ms
  jitter: 100ms       # optional, zero allowed
  correlation: "25"  # optional, 0..100
```

Latency above 5 seconds requires `allowExtremeSeverity`. Packet-effect objects
use their action name and optional correlation:

```yaml
loss:
  loss: "20"
  correlation: "25"
```

The `loss`, `duplicate`, or `corrupt` percentage must be `0..100`; above 50
requires `allowExtremeSeverity`.

Bandwidth accepts `rate` as a number followed by `bps`, `kbps`, `mbps`, or
`gbps`, plus optional positive integer `limit`, `buffer`, and `minburst`, and
optional `peakrate`. Rates below `10kbps` require `allowExtremeSeverity`.

## Example

```yaml
faults:
  - id: follower-delay
    target:
      actors: [follower-1]
    fault:
      type: network
      action: delay
      mode: all
      duration: 12s
      parameters:
        direction: both
        peerTarget:
          actors: [bitcoin]
          mode: all
        delay:
          latency: 750ms
          jitter: 100ms
          correlation: "25"
    effectAssertions:
      - type: NetworkDegraded
        actor: follower-1
        timeoutSeconds: 60
    recoveryAssertions:
      - type: NetworkRecovered
        actor: follower-1
        timeoutSeconds: 180
```

Examples:

- [`follower-network-delay.yaml`](../../../examples/campaigns/follower-network-delay.yaml)
- [`bitcoin-propagation-delay.yaml`](../../../examples/campaigns/bitcoin-propagation-delay.yaml)
- [`telemetry-prometheus-partition.yaml`](../../../examples/campaigns/telemetry-prometheus-partition.yaml)

