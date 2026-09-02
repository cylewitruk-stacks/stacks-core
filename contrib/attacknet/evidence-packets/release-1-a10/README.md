# Release 1 A10 evidence

The Full-tier review packet and portable live evidence for A10 are generated
only after the exact staged tree passes offline and three-node kind
qualification. Large archives remain outside Git; the tracked release record
binds their digests after approval.

Offline verification and live qualification both require at least 8 GiB free
on their working filesystems and fail before expensive build or mutation work
when that bound is not met.

The qualification proves an admitted two-node Bitcoin graph, a real competing
branch under partition, independently observed Bitcoin and Stacks divergence,
stable recovery, a topology-drift negative control, fresh-network replay, and
complete teardown.

After approval, [`gate-result.json`](gate-result.json) records the signed
candidate, review bindings, and external evidence digests used by the Release 1
baseline without committing the large review archive.
