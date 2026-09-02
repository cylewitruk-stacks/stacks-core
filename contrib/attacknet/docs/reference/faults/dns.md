# DNS faults

| Contract | Value |
| --- | --- |
| Fault type | `dns` |
| Backend | Chaos Mesh `DNSChaos` |
| Actions | `error`, `random` |
| Effect assertion | `DNSDegraded` |
| Recovery assertion | `DNSRecovered` |

DNS faults alter name resolution inside selected actor Pods. They are useful
for bootstrap, peer-discovery, RPC dependency, and telemetry failure scenarios.

## Parameters

| Parameter | Required | Contract |
| --- | --- | --- |
| `patterns` | Yes | Non-empty, unique DNS patterns; at most 256 entries and 253 characters each |
| `containerNames` | No | Non-empty, unique container-name array |

A pattern may contain one wildcard only, and only as its last character. For
example, `minimal-bitcoin.*` is valid; `*.example` and `foo*bar` are rejected.
Unknown parameters are rejected.

`error` returns resolution errors for matching queries. `random` returns
random addresses. Select `actor` and, where the evidence path needs it,
`attacknet-probe`; otherwise the actor and its trusted probe can observe
different DNS behavior.

## Example

```yaml
faults:
  - id: follower-dns
    target:
      actors: [follower-1]
    fault:
      type: dns
      action: error
      mode: all
      duration: 5s
      parameters:
        patterns: [minimal-bitcoin.*]
        containerNames: [actor, attacknet-probe]
    effectAssertions:
      - type: DNSDegraded
        actor: follower-1
        timeoutSeconds: 60
    recoveryAssertions:
      - type: DNSRecovered
        actor: follower-1
        timeoutSeconds: 180
```

Examples:

- [`dns-enrolled-peer-error.yaml`](../../../examples/campaigns/dns-enrolled-peer-error.yaml)
- [`signer-dns-error.yaml`](../../../examples/campaigns/signer-dns-error.yaml)

## Operational notes

- DNS faults do not close established TCP or P2P connections. Design the
  scenario so the actor must resolve the name during the fault window.
- A Chaos Mesh injection condition is not DNS-effect evidence. Retain both
  degraded and recovered assertions.
- A broad wildcard can affect the probe's own dependencies. Narrow patterns to
  the hypothesis where possible.

