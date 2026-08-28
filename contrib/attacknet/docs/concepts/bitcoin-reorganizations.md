# Bitcoin reorganization campaigns

`burnchain-reorg` is a semantic regtest fault. It replaces a bounded suffix of
one admitted Bitcoin actor rather than killing a process or exposing arbitrary
Bitcoin RPC.

The controller first creates an inert worker and durably records its identity
and recovery contract. Only the subsequent preparation handshake pauses the
ordinary mining policy, so a controller restart cannot strand an unrecorded
pause. The action then seals the canonical tip, chainwork, fork parent, removed branch,
replacement request, destination, and protocol-boundary assessment before it
mutates Bitcoin. A restricted worker first waits for the replacement clock to
acknowledge the paused policy generation, then prepares the branch and waits
for controller approval of that exact digest. It rechecks the tip, performs the
replacement, removes the local invalidity marker, and proves the longer
replacement branch remains canonical.
`reconsiderblock` alone is never success evidence. RPC transport failures are
recorded as uncertain mutation receipts and reconciled against the observed
canonical chain. Cleanup is successful only when the exact original tip,
height, and chainwork are restored. An approved worker is preserved until it
publishes a terminal result, and ordinary mining resumes only after the worker
is absent.

Depth is configurable from 1 through 144 blocks and the replacement branch may
contain up to 288 blocks. These limits exceed historical Bitcoin reorganizations
while keeping the complete branch proof and RPC receipt set safely below
Kubernetes object limits.

## Safety contract

A campaign must:

- name exactly one `burnchain` actor with `mode: one`;
- set `allowBurnchain: true`;
- set explicit depth and replacement-block ceilings;
- mine more replacement blocks than it removes; and
- opt in explicitly before crossing an epoch or reward-cycle boundary.

The selected `BurnchainPolicy` should declare `protocolSchedule`. If it does
not, both boundary opt-ins are required because the controller cannot prove
that the interval is safe. The controller pauses ordinary cadence and observes
the clock in `paused` state before it permits the worker to read the Bitcoin
tip. It restores the exact previous pause state during cleanup.
A pending flash request blocks admission; a flash may run after recovery.

## Compose with fast blocks

The replacement branch already supports a flash cadence through
`replacementBlocks` and `replacementInterval`. To continue with ordinary
`BurnchainPolicy` flash mining, wait for the campaign to become terminal and
for `BurnchainPolicyRestored` to be `Proven`, then submit a new idempotent flash
request:

```bash
kubectl -n hacknet-system patch burnchainpolicy minimal --type=merge \
  -p '{"spec":{"flash":{"id":"after-reorg-1","blocks":8,"interval":"1s"}}}'
kubectl -n hacknet-system wait burnchainpolicy/minimal \
  --for=jsonpath='{.status.appliedFlashId}'=after-reorg-1 --timeout=120s
```

Do not queue the flash first: an unapplied flash deliberately prevents reorg
admission. This serialization keeps the ordinary cadence controller and the
branch-replacement worker from issuing competing Bitcoin RPC mutations. The
campaign records the replacement cadence; an evidence-qualified orchestration
run must additionally record the subsequent policy patch and the observed
`appliedFlashId` before claiming reorg-plus-flash replay.

## Evidence and failure behavior

`FaultActionStatus.actualInjection` retains the worker's bounded branch proof,
including RPC acknowledgements and final chain tips. Effect and recovery
results separately report `BurnchainReorgProven` and
`BurnchainPolicyRestored`. A stale approval, changed policy identity, changed
policy contract, incomplete replacement, or unproved final branch fails closed.

This first version addresses one Bitcoin node. It proves Stacks behavior under
a canonical reorganization but does not claim simultaneous honest split views.
The A10 roadmap item adds Bitcoin P2P partitions and multiple followers; it will
reuse this node-addressed primitive and its per-node evidence.
