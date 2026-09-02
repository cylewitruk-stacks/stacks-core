# Controller-owned I/O pressure image

This image is the arm64-compatible fallback for the bounded
`io-pressure`/`disk-pressure` FaultCampaign semantic. It is **not** Chaos Mesh
`IOChaos` (per-syscall injection) or `StressChaos`.

Build from the repository root:

```sh
docker buildx build --platform linux/arm64 \
  -f contrib/attacknet/images/io-pressure/Dockerfile \
  -t stacks-hacknet-io-pressure:local --load .
```

The Helm chart configures this trusted image on the run operator. A
FaultCampaign supplies only bounded structured values. The controller fixes
the executable, argument layout, security context, resource caps, target node,
and target PVC. The workload opens files on the target data claim and unlinks
them before generating write+fsync pressure, so abrupt termination cannot
leave named pressure data on the actor volume.

The same static executable has a separate, mutually exclusive capacity-escrow
mode used by the local fuzz-session admission boundary. That mode writes and
syncs random bytes to a session-owned PVC path, then exits. Users cannot select
this mode through a `FaultCampaign`; the host-side typed CLI fixes its image,
path, size bounds, Pod security context, and lifecycle.
