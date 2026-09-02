# Release 1 amendment A9 evidence

The generated packet and portable evidence archive are written here only after
the bounded Bitcoin-reorganization candidate has been qualified and hardware
signed. Reviewers must recompute packet, archive, source, and evidence digests
from the exact signed revision before issuing a verdict.

The archive includes two kubelet stats-summary capacity checks: one before
candidate image builds and one before network creation. Both root and image
filesystems on every qualification node must have at least 8 GiB available.

[`gate-result.json`](gate-result.json) is the tracked, clean-clone-verifiable
release record. It binds the approved source revision and tree, packet and
contract digests, both verdict files, and the externally retained evidence
summary and archive. The large evidence bundle remains outside Git.
