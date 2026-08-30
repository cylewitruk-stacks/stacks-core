# `stacks-node` metrics

## `libsigner` v0 signer coordinator

These metrics expose the node miner's existing StackerDB-based signing round.
They are available when the node is built with the `monitoring_prom` feature
and a Prometheus endpoint is configured.

The instrumentation is observation-only: it does not change signature or
rejection accumulation, thresholds, timeout steps, retries, transaction
exclusion, or any consensus decision. Labels are finite and exclude block
hashes, signer identities, transaction IDs, error text, and other unbounded
values. Counters reset when the node process restarts.

### Metrics

#### `stacks_node_signer_coordinator_rounds_total`

Counts proposal-round lifecycle events.

- `event`: `started` or `completed`
- `outcome`: `pending` for starts; completed outcomes are `approved`,
  `rejected`, `timeout`, `burnchain_tip_changed`, `stacks_tip_changed`, or
  `error`

A timeout followed by a proposal resend is two rounds. This makes retry churn
explicit without putting proposal hashes into labels.

Completed rounds by outcome, without also counting their corresponding
`event="started",outcome="pending"` events:

```promql
sum by (outcome) (
  rate(stacks_node_signer_coordinator_rounds_total{event="completed"}[5m])
)
```

#### `stacks_node_signer_response_weight_total`

Adds the configured signer weight when the `libsigner` v0 listener adds a
response to the current accumulation round.

- `approved`: weight added to `total_weight_approved`
- `rejected_effective`: weight added to `total_weight_rejected`
- `unavailable_classified`: an overlapping subset of `rejected_effective`
  whose signed reason is `ConnectivityIssues`, `NoSortitionView`, or
  `NoSignerConsensus`

The overlapping classification is deliberate. The current `libsigner` v0
behavior still counts unavailable weight as rejection weight. This metric does
not discount, renormalize, or otherwise change that arithmetic.
`InvalidTenureExtend` is not classified as unavailable because the current
reason represents both genuine policy verdicts and some RPC failures.

Rejection timeouts clear the round's rejection accumulator before the proposal
is resent. A signer that rejects again can therefore contribute weight again,
while approved weight remains accumulated and is not recounted. Rates and
ratios derived from these classifications are consequently retry-weighted, not
proposal-unique.

#### `stacks_node_signer_coordinator_milestone_seconds`

Histogram of monotonic elapsed seconds to three bounded milestones, each with
`outcome="approved"` or `outcome="rejected"`:

- `proposal_to_first_response` records the first cryptographically valid,
  proposal-unique accepted or rejected response after a successful publication;
- `proposal_to_threshold` records an approved or rejected weight threshold,
  measured from the initial publication and including approved blocks recovered
  from local chainstate;
- `round_to_threshold` records the same threshold measured from the latest
  publication attempt, excluding time spent in earlier retries.

The proposal-wide timers remain anchored to the initial publication across
resends. The first-response milestone is emitted at most once per proposal;
resetting it could misattribute a delayed response because signer responses
carry no publication-round identifier. The proposal- and round-to-threshold
observations are emitted together when a threshold is reached. Accumulated
approval and rejection behavior remains unchanged. A response that races the
StackerDB publication acknowledgement is retained and emitted only after the
publication succeeds; a failed initial publication emits no milestone. Metric
timers start immediately before their respective publication so they include
proposal-upload latency. The proposal-wide timers also include retry latency.
The existing rejection timer still starts after each publication and is
unchanged.

All milestones include StackerDB proposal-upload latency, so
`proposal_to_first_response` is publish-to-answer latency rather than pure
signer processing latency. The histograms are independently aggregated and can
be compared only as separate diagnostic distributions, and independently
calculated percentiles must not be subtracted. Because both threshold samples
are emitted from the same event and instant, subtracting their `_sum` increases
does yield aggregate time spent before the final threshold-reaching round.
Dividing that result by the `proposal_to_threshold` `_count` increase yields a
population average, not individual per-proposal values.

Timeout and chain-change exits do not claim that a threshold was reached; use
the rounds counter for those outcomes. At the population level, a slow
`proposal_to_threshold` alongside a faster `round_to_threshold` and elevated
timeout rate suggests retry churn. If both threshold distributions are slow
while timeout rates remain low, weighted-tail or quorum accumulation delay is
more likely. A slow first-response distribution instead points toward
publication, propagation, or initial signer responsiveness.

Examples:

```promql
histogram_quantile(
  0.95,
  sum by (le, milestone, outcome) (
    rate(stacks_node_signer_coordinator_milestone_seconds_bucket[15m])
  )
)
```

Retry timeouts:

```promql
sum(
  rate(stacks_node_signer_coordinator_rounds_total{
    event="completed",
    outcome="timeout"
  }[5m])
)
```

Aggregate seconds spent before final threshold-reaching rounds:

```promql
sum by (outcome) (
  increase(stacks_node_signer_coordinator_milestone_seconds_sum{
    milestone="proposal_to_threshold"
  }[15m])
)
-
sum by (outcome) (
  increase(stacks_node_signer_coordinator_milestone_seconds_sum{
    milestone="round_to_threshold"
  }[15m])
)
```

```promql
sum by (classification) (
  rate(stacks_node_signer_response_weight_total[5m])
)
```

Process restarts create counter discontinuities. Consumers comparing actors
must use rates or reset-aware deltas rather than raw lifetime totals.

## Nakamoto block transfers

The node exports one bounded counter family for Nakamoto block movement:

```text
stacks_node_nakamoto_block_transfers_total{direction,source,outcome}
```

This fills the post-Epoch-3 visibility gap left by
`stacks_node_stx_blocks_received_total`, which only observes legacy block
messages. It is an observation-only metric and does not alter validation,
storage, relay, or HTTP behavior.

### Label contract

All labels are closed Rust enums. No block identifier, peer identifier, error
text, URL, or other unbounded value is used as a label.

| Label | Values | Meaning |
| --- | --- | --- |
| `direction` | `received`, `sent` | Whether the local node consumed or emitted the transfer. |
| `source` | `p2p_push`, `tenure_download`, `rpc_upload`, `p2p_relay`, `rpc_serve` | The bounded transport boundary that supplied or emitted the block. |
| `outcome` | `accepted`, `duplicate`, `rejected`, `error`, `queued`, `completed`, `failed` | The result appropriate to that boundary. |

Only meaningful combinations are emitted:

- received blocks use `p2p_push`, `tenure_download`, or `rpc_upload` with
  `accepted`, `duplicate`, `rejected`, or `error`;
- P2P relays use `p2p_relay` with `queued` or `failed`;
- HTTP block streams use `rpc_serve` with `completed`.

Locally mined and SIP-created shadow blocks are intentionally excluded because
they are not network transfers.

### Counting boundaries

Received blocks are counted exactly once around
`Relayer::process_new_nakamoto_block_ext`, after the existing acceptance result
is known. The wrapper delegates all consensus and storage work to the original
inner implementation and then classifies the unchanged result. In particular,
`duplicate` means the node already had the block; it does not imply invalidity.

P2P relay counts are measured in blocks, not messages. `queued` means the
bounded block batch was successfully handed to the P2P network handle. It does
not claim that any remote peer received or accepted the blocks. `failed` means
that handoff failed.

An HTTP-served block is counted when its stream reaches EOF. A per-stream flag
prevents repeated empty chunk polls from incrementing the counter more than
once. Resetting a tenure stream for its next block also resets that flag, so
each completely generated block stream contributes one observation. This does
not claim that pending bytes reached the client before a disconnect.

### PromQL examples

Accepted ingress rate by transport:

```promql
sum by (source) (
  rate(stacks_node_nakamoto_block_transfers_total{
    direction="received", outcome="accepted"
  }[5m])
)
```

Duplicate ratio for received blocks:

```promql
sum(rate(stacks_node_nakamoto_block_transfers_total{
  direction="received", outcome="duplicate"
}[5m]))
/
clamp_min(sum(rate(stacks_node_nakamoto_block_transfers_total{
  direction="received"
}[5m])), 1)
```

P2P relay handoff failures:

```promql
sum(rate(stacks_node_nakamoto_block_transfers_total{
  direction="sent", source="p2p_relay", outcome="failed"
}[5m]))
```

These counters are process-local and reset when the node restarts. Use
`rate()`/`increase()` for interval analysis and join them with orchestrator
restart evidence when reconstructing an incident.
