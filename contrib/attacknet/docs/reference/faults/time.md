# Native time faults

| Contract | Value |
| --- | --- |
| Fault type | `time` |
| Backend | Chaos Mesh `TimeChaos` |
| Action | Omitted |
| Effect assertion | `ClockSkewObserved` |
| Recovery assertion | `ClockSkewCleared` |

Native time faults manipulate a selected container's clocks through Chaos
Mesh. In Release 1 they require a supported Linux architecture; the local
arm64 profile rejects them. Use [`clock-skew`](clock-skew.md) for the portable
application-wall-clock mechanism.

## Parameters

| Parameter | Required | Contract |
| --- | --- | --- |
| `timeOffset` | Yes | Signed, non-zero integer duration, absolute value at most 24 hours |
| `clockIds` | No | Non-empty subset of supported clock IDs |
| `containerNames` | No | At most one container name |

Offsets beyond five minutes require `safety.allowExtremeSeverity: true`.
Supported clocks are `CLOCK_REALTIME`, `CLOCK_MONOTONIC`,
`CLOCK_PROCESS_CPUTIME_ID`, and `CLOCK_THREAD_CPUTIME_ID`.

Do not set `fault.action`. The fault still requires `mode` and `duration`.

## Example

```yaml
faults:
  - id: signer-clock
    target:
      actors: [signer-1]
    fault:
      type: time
      mode: all
      duration: 30s
      parameters:
        timeOffset: -30s
        clockIds: [CLOCK_REALTIME]
        containerNames: [actor]
    effectAssertions:
      - type: ClockSkewObserved
        actor: signer-1
        timeoutSeconds: 90
    recoveryAssertions:
      - type: ClockSkewCleared
        actor: signer-1
        timeoutSeconds: 180
```

Complete example: [`signer-wall-clock-skew.yaml`](../../../examples/campaigns/signer-wall-clock-skew.yaml).

## Choose clocks deliberately

Wall-clock injection does not affect Rust `Instant` or other monotonic timeout
machinery unless `CLOCK_MONOTONIC` is explicitly selected and the runtime can
intercept it. Inventory the target decision's clock source before claiming the
fault exercises a timeout. See [`clock sources`](../clock-sources.md).

