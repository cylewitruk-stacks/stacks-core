# Portable application clock-skew faults

| Contract | Value |
| --- | --- |
| Fault type | `clock-skew` |
| Backend | Controller-owned clock-policy ConfigMap (`ClockSkewPolicy`) |
| Action | Omitted |
| Effect assertion | `ClockSkewObserved` |
| Recovery assertion | `ClockSkewCleared` |

Application clock skew is Attacknet's arm64-compatible alternative to native
Chaos Mesh `TimeChaos`. It changes the wall clock seen by an actor instrumented
with libfaketime while leaving monotonic clocks untouched.

## Image and policy contract

Admission requires the actor container to have all of the following:

- `/run/attacknet-clock` mounted from `<network>-clock-policy`;
- `LD_PRELOAD=/usr/lib/stacks-attacknet/libfaketime.so.1`;
- `FAKETIME_TIMESTAMP_FILE=/run/attacknet-clock/<actor>`;
- `FAKETIME_DONT_FAKE_MONOTONIC=1`; and
- `FAKETIME_NO_CACHE=1`.

The operator-owned policy must identify the admitted network, contain every
actor, and be globally at zero offset before injection. A mismatched or already
skewed policy fails capability admission. Overlapping clock-skew actions cannot
target the same actor through the shared policy.

## Parameters

| Parameter | Required | Contract |
| --- | --- | --- |
| `timeOffset` | Yes | Signed, non-zero integer duration, absolute value at most 24 hours |
| `clockIds` | No | If present, exactly `[CLOCK_REALTIME]` |
| `containerNames` | No | If present, exactly `[actor]` |

Offsets beyond five minutes require `safety.allowExtremeSeverity: true`. Do
not set `fault.action`.

## Example

```yaml
faults:
  - id: follower-clock
    target:
      actors: [follower-1]
    fault:
      type: clock-skew
      mode: all
      duration: 20s
      parameters:
        timeOffset: -30s
        clockIds: [CLOCK_REALTIME]
        containerNames: [actor]
    effectAssertions:
      - type: ClockSkewObserved
        actor: follower-1
        timeoutSeconds: 90
    recoveryAssertions:
      - type: ClockSkewCleared
        actor: follower-1
        timeoutSeconds: 180
```

Complete example: [`follower-application-clock-skew.yaml`](../../../examples/campaigns/follower-application-clock-skew.yaml).

## Scope

This mechanism exercises wall-clock reads such as epoch timestamps and
freshness metrics. It intentionally cannot alter Rust `Instant` or
`CLOCK_MONOTONIC` timeout paths. Use the native [`time`](time.md) fault on a
supported host when manipulating another clock is essential. See
[`clock sources`](../clock-sources.md) before designing the experiment.
