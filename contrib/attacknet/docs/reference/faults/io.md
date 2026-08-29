# Native I/O faults

| Contract | Value |
| --- | --- |
| Fault type | `io` |
| Backend | Chaos Mesh `IOChaos` |
| Actions | `latency`, `fault`, `attrOverride`, `mistake` |
| Effect assertion | `IODegraded` |
| Recovery assertion | `IORecovered` |

Native I/O faults intercept filesystem operations in selected containers. In
Release 1 they require a Linux architecture admitted by the operator's
IOChaos capability policy; the local arm64 profile rejects them. Use
[`io-pressure`](io-pressure.md) for portable arm64 disk stress.

## Common parameters

| Parameter | Required | Contract |
| --- | --- | --- |
| `volumePath` | Yes | Non-empty absolute path, at most 4096 characters |
| `path` | No | Non-empty absolute path, at most 4096 characters |
| `methods` | No | Non-empty subset of the supported operations below |
| `percent` | No | `0..100`; above 50 requires `allowExtremeSeverity` |
| `containerNames` | No | Non-empty unique container-name array |

Supported methods are `READ`, `WRITE`, `FLUSH`, `FSYNC`, `FDATASYNC`,
`READDIR`, `SYNC`, `OPEN`, `MKDIR`, `MKNOD`, `CHOWN`, `CHMOD`, `UTIMES`,
`LINK`, `UNLINK`, and `RENAME`.

For actor chainstate, the common selection is `volumePath: /data`,
`path: /data/**`, and `containerNames: [actor]`.

## Action parameters

| Action | Required parameter | Contract |
| --- | --- | --- |
| `latency` | `delay` | Positive integer duration; above 5 seconds requires `allowExtremeSeverity` |
| `fault` | `errno` | Integer `1..4095` |
| `attrOverride` | `attr` | Non-empty Chaos Mesh attribute-override object |
| `mistake` | `mistake` | Non-empty Chaos Mesh mistake object |

The controller validates that `attr` and `mistake` are non-empty objects, then
passes their bounded action-specific content to Chaos Mesh. Review the
rendered mutation in campaign status and avoid relying on Chaos Mesh fields
that are not qualified by Attacknet.

## Example

```yaml
faults:
  - id: signer-node-latency
    target:
      actors: [signer-node-1]
    fault:
      type: io
      action: latency
      mode: all
      duration: 30s
      parameters:
        volumePath: /data
        path: /data/**
        methods: [READ, WRITE, FSYNC]
        delay: 150ms
        percent: 50
        containerNames: [actor]
    effectAssertions:
      - type: IODegraded
        actor: signer-node-1
        timeoutSeconds: 90
    recoveryAssertions:
      - type: IORecovered
        actor: signer-node-1
        timeoutSeconds: 300
```

Complete example: [`signer-node-io-latency.yaml`](../../../examples/campaigns/signer-node-io-latency.yaml).

## Capability and outcome

Admission probes the target platform and architecture. Unsupported targets
fail capability admission rather than creating an ineffective IOChaos object.
An injected resource without trusted I/O degradation remains `Inconclusive`.

