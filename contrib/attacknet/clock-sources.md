# Clock-source inventory for time faults

Time faults must state which clock the hypothesis targets. Changing wall time
does not automatically exercise every timeout in the signer/miner path.

## Monotonic elapsed-time decisions

These use Rust `Instant` or `.elapsed()` and should not move under a
`CLOCK_REALTIME`-only offset:

- miner signer-response/rejection steps in
  `stacks-node/src/nakamoto_node/signer_coordinator.rs`;
- miner tenure-change and relayer initiative scheduling in
  `stacks-node/src/nakamoto_node/miner.rs` and `relayer.rs`;
- the signer's submitted block-validation deadline in
  `stacks-signer/src/v0/signer.rs`;
- signer-monitor polling freshness and the metrics server's poll schedule.

A campaign claiming to accelerate one of these must demonstrate that the
injected primitive changes the container's monotonic clock. Otherwise the
campaign is invalid even when the Chaos resource reports success.

## Wall-clock decisions and evidence

These consume `SystemTime` or `get_epoch_time_secs()` and are intentionally in
scope for wall-clock skew:

- signer block/tenure activity and capitulation comparisons in
  `stacks-signer/src/chainstate` and `v0/signer_state.rs`;
- proposal, approval, signing, pending-validation, and tenure-extension times
  persisted by `stacks-signer/src/signerdb.rs`;
- `get_tenure_extend_timestamp()` as consumed by the miner;
- block timestamps created with `get_epoch_time_secs()`; and
- freshness/last-change observability derived from epoch timestamps.

## Required controls

Every time campaign records before/during/after samples from inside the target
container for both wall and monotonic clocks. The campaign is inconclusive if
the intended clock did not move by the requested offset. Recovery assertions
must tolerate a discontinuous wall clock while still requiring monotonic chain
progress after the fault is removed.
