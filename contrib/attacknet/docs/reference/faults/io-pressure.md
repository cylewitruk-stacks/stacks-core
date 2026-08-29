# Portable I/O-pressure faults

| Contract | Value |
| --- | --- |
| Fault type | `io-pressure` |
| Backend | Controller-owned restricted Pod (`IOPressurePod`) |
| Action | `disk-pressure` |
| Effect assertion | `IOPressureObserved` |
| Recovery assertion | `IOPressureRecovered` |

I/O pressure is Attacknet's portable alternative to native Chaos Mesh
`IOChaos`. A controller-owned Pod mounts the exact admitted actor's `/data` PVC
on the same Kubernetes node and runs a fixed bounded workload. The campaign
cannot choose its image, command, executable, shell, or arbitrary arguments.

## Target and capability requirements

- The action must resolve to exactly one actor.
- The actor container must mount a persistent volume claim at `/data`.
- The target Pod must have a positive non-root `fsGroup` or permit the
  controller's non-root default.
- The chart must configure the trusted I/O-pressure image.
- `containerNames` must be exactly `[actor]`.

The pressure Pod receives no service-account token, drops all capabilities,
uses the runtime-default seccomp profile, has a read-only root filesystem, and
has bounded CPU and memory resources. It writes a campaign-specific temporary
file and removes it before completion.

## Parameters

All parameters are required.

| Parameter | Contract |
| --- | --- |
| `containerNames` | Exactly `[actor]` |
| `severity` | `low`, `medium`, or `high` |
| `workers` | Positive integer within the severity limit |
| `bytesMiB` | Integer from 16 through the severity limit |
| `writeSizeKiB` | Integer `4..1024`, no larger than `bytesMiB * 1024` |
| `minimumLatencyMultiplier` | Number `1.1..20` used by effect evidence |
| `minimumAddedLatencyMs` | Number `0.5..5000` used by effect evidence |

| Severity | Maximum workers | Maximum bytes | Maximum duration | Additional opt-in |
| --- | --- | --- | --- | --- |
| `low` | 1 | 64 MiB | 1 minute | None |
| `medium` | 2 | 256 MiB | 3 minutes | None |
| `high` | 4 | 512 MiB | 5 minutes | `allowExtremeSeverity` |

The two latency thresholds are evidence requirements, not pressure-generator
controls. Set them high enough to reject ambient noise but low enough for the
target storage class and baseline.

## Example

```yaml
faults:
  - id: follower-pressure
    target:
      actors: [follower-1]
    fault:
      type: io-pressure
      action: disk-pressure
      mode: all
      duration: 45s
      parameters:
        containerNames: [actor]
        severity: low
        workers: 1
        bytesMiB: 32
        writeSizeKiB: 256
        minimumLatencyMultiplier: 2
        minimumAddedLatencyMs: 5
    effectAssertions:
      - type: IOPressureObserved
        actor: follower-1
        timeoutSeconds: 90
    recoveryAssertions:
      - type: IOPressureRecovered
        actor: follower-1
        timeoutSeconds: 300
```

Complete example: [`fault-campaign-io-pressure.yaml`](../../../../helm/hacknet/examples/fault-campaign-io-pressure.yaml).

## Evidence semantics

Attacknet compares trusted fsync observations against the pre-fault baseline
and the configured minimum multiplier and added latency. The pressure Pod
finishing successfully does not by itself prove an effect. Recovery requires
the I/O observation to return to the accepted range and the owned pressure Pod
to be gone.
