# Phase 0 candidate handoff

Status: implementation and pre-commit verification complete; immutable
post-commit evidence and review remain pending.

The final dirty-candidate offline run passed 196 Attacknet Node tests, 40
observability Node tests, 9 release-contract tests, 10 event-bridge Python
tests, and the 31-workload offline operator render. These counts are a
developer handoff result, not the immutable post-commit result required by the
review packet.

## Requirement evidence

| Requirement | Evidence |
| --- | --- |
| Machine-readable accepted baseline | `baseline-v1.json`; strict validator and a falsifiable byte-mutation negative control |
| Truthful primary documentation | Attacknet baseline section and corrected Hacknet productization status |
| Digest-bound dual review | Exact contract digest, enforced contract/packet/verdict schemas, matrix evidence checks, tier upgrade, and complete two-reviewer negative controls |
| Clean offline verification | `contrib/attacknet/check.sh` generates an external machine result when `ATTACKNET_OFFLINE_RESULT` is set |

## Compatibility and security analysis

Phase 0 changes no actor process, Kubernetes resource, fault mechanism,
consensus behavior, or evidence interpretation. It adds read-only validation,
indexes existing terminal evidence and product capability boundaries, and
hardens the human review workflow.
Evidence bytes are hashed and substitutions fail a demonstrated mutation
negative control. The review gate prevents accidental digest drift,
contract substitution, schema drift, vacuous approval, and partial-review
promotion, but cannot prove reviewer identity or comprehension.

## Limitations

- Large historical evidence bundles remain gitignored and must be archived
  separately. Their tracked byte digests make absence explicit and detect
  substitution; they do not make missing bytes available.
- The accepted execution used a dirty source tree. Both its base revision and
  dirty patch digest are retained; the baseline does not falsely call it a
  clean release build.
- Native arm64 IOChaos, TimeChaos, and StressChaos remain capability-rejected. Portable CSI,
  managed/x86 qualification, and enterprise registry/identity integration have
  structured external deferrals. Multi-Bitcoin/reorg work and controller HA are
  explicitly `not-done`, not mislabeled as external deferrals.
- Claude Opus 5 review requires user-mediated custody. No placeholder verdict
  is included in this candidate.

## Development-backlog migration audit

The temporary development findings ledger is intentionally not a product
artifact or review-packet input. Before removing that dependency, its
Release-1-relevant constraints were audited into `baseline-v1.json`. The
baseline now states the unsupported native arm64 Chaos mechanisms and the
unimplemented cold-start capacity reservation, actor egress policy,
cryptographically attributed active probes, teardown Loki export, and matched
Kubernetes-client packaging. Bug status, investigation history, and issue IDs
belong in GitHub or a separate findings repository and are not duplicated here.

## Reproduction

```bash
node contrib/attacknet/release/baseline.mjs validate \
  contrib/attacknet/release/baseline-v1.json

node contrib/attacknet/release/baseline.mjs validate \
  contrib/attacknet/release/baseline-v1.json \
  --verify-evidence --root=.

node --test contrib/attacknet/release/phase-zero.test.mjs
contrib/attacknet/check.sh
```

The second baseline command requires the preserved local evidence archive.
The complete `check.sh` needs permission to bind loopback for its HTTP tests.

After creating the hardware-signed candidate commit, record the successful
offline check and generate an external packet before either review. Do not
commit that derived packet back into the candidate. Candidate state is derived
from Git; no flag can claim a dirty tree is committed:

```bash
ATTACKNET_OFFLINE_RESULT=/tmp/phase-0-offline-result.json \
  contrib/attacknet/check.sh
node contrib/attacknet/release/phase-zero-packet.mjs \
  --offline-result=/tmp/phase-0-offline-result.json \
  --output=.docs/reviews/attacknet-phase-0/packet.json
```
