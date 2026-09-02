# Pod faults

| Contract | Value |
| --- | --- |
| Fault type | `pod` |
| Backend | Chaos Mesh `PodChaos` |
| Actions | `pod-kill`, `pod-failure`, `container-kill` |
| Effect assertions | `PodRestarted`, `PodUnavailable`, `ContainerRestarted` |
| Recovery assertion | `TargetReady` |

Pod faults exercise actor process and Pod availability without modifying the
actor image or configuration.

## Actions and parameters

| Action | Parameters | Proven effect |
| --- | --- | --- |
| `pod-kill` | Optional `gracePeriod` integer, `0..3600` seconds | The admitted Pod UID disappears and a replacement becomes observable |
| `pod-failure` | No parameters | The same admitted Pod UID becomes NotReady |
| `container-kill` | Required non-empty `containerNames` array | A selected container restart count increases on the same Pod UID |

A `gracePeriod` above 60 seconds requires
`safety.allowExtremeSeverity: true`. Unknown parameters are rejected.

For protocol-process disruption, select `containerNames: [actor]` rather than
a telemetry or probe sidecar. A Pod replacement during `pod-failure` or
`container-kill` is ambiguous and therefore `Inconclusive`; only `pod-kill`
authorizes its selected actor's admitted Pod UID to change.

## Example

```yaml
faults:
  - id: restart-follower
    target:
      actors: [follower-1]
    fault:
      type: pod
      action: pod-kill
      mode: one
      duration: 1s
      parameters:
        gracePeriod: 0
    effectAssertions:
      - type: PodRestarted
        actor: follower-1
        timeoutSeconds: 120
    recoveryAssertions:
      - type: TargetReady
        actor: follower-1
        timeoutSeconds: 300
```

Complete example: [`fault-campaign-minimal.yaml`](../../../../helm/hacknet/examples/fault-campaign-minimal.yaml).

## Operational notes

- A restart does not imply protocol recovery. Retain the `TargetReady`
  assertion and protocol assertions relevant to the hypothesis.
- Pod-kill is a one-shot effect. The campaign proves replacement and cleanup;
  it does not keep the actor unavailable for the entire declared duration.
- Aggregate signer and miner limits use the selected actors' admitted weights.

