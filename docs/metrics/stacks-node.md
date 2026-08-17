# `stacks-node` metrics

## Legacy signer coordinator

These metrics expose the node miner's existing StackerDB-based signing round.
They are available when the node is built with the `monitoring_prom` feature
and a Prometheus endpoint is configured.

The instrumentation is observation-only: it does not change signature or
rejection accumulation, thresholds, timeout steps, retries, transaction
exclusion, or any consensus decision. Labels are finite and exclude block
hashes, signer identities, transaction IDs, error text, and other unbounded
values. Counters reset when the node process restarts.

## Metrics

### `stacks_node_signer_coordinator_rounds_total`

Counts proposal-round lifecycle events.

- `event`: `started` or `completed`
- `outcome`: `pending` for starts; completed outcomes are `approved`,
  `rejected`, `timeout`, `burnchain_tip_changed`, `stacks_tip_changed`, or
  `error`

A timeout followed by a proposal resend is two rounds. This makes retry churn
explicit without putting proposal hashes into labels.

### `stacks_node_signer_response_weight_total`

Adds the configured signer weight at the exact points where the legacy
listener adds a unique response to its accumulator.

- `approved`: weight added to `total_weight_approved`
- `rejected_effective`: weight added to `total_weight_rejected`
- `unavailable_classified`: an overlapping subset of `rejected_effective`
  whose signed reason is `ConnectivityIssues`, `NoSortitionView`, or
  `NoSignerConsensus`

The overlapping classification is deliberate. Current legacy behavior still
counts unavailable weight as rejection weight. This metric does not discount,
renormalize, or otherwise change that arithmetic. `InvalidTenureExtend` is not
classified as unavailable because the current reason represents both genuine
policy verdicts and some RPC failures.

### `stacks_node_signer_coordinator_milestone_seconds`

Histogram of monotonic elapsed seconds from the start of proposal publication
to two bounded milestones, each with `outcome="approved"` or
`outcome="rejected"`:

- `proposal_to_first_response` records the first cryptographically valid,
  proposal-unique accepted or rejected response after a successful publication;
- `proposal_to_threshold` records an approved or rejected weight threshold,
  including approved blocks recovered from local chainstate.

The first-response milestone is emitted at most once per proposal. It does not
reset on resends because signer responses carry no publication-round identifier;
doing so could misattribute a delayed response to a retry. Accumulated approval
and rejection behavior remains unchanged. A response that races the StackerDB
publication acknowledgement is retained and emitted only after the publication
succeeds; a failed initial publication emits neither milestone. The metric timer
starts immediately before publication so it includes proposal-upload latency.
The existing rejection timer still starts after each publication and is
unchanged.

Both milestones include StackerDB proposal-upload latency, so
`proposal_to_first_response` is publish-to-answer latency rather than pure
signer processing latency. The two histograms are independently aggregated and
can be compared only as separate diagnostic distributions. They cannot produce
an exact per-proposal weight-accumulation interval, and their independently
calculated percentiles must not be subtracted. That interval would require its
own explicitly recorded observation if operators later need it.

Timeout and chain-change exits do not claim that a threshold was reached; use
the rounds counter for those outcomes. At the population level, a stable-fast
first-response distribution alongside a slower threshold distribution suggests
weighted-tail or quorum accumulation delay. Both distributions moving together
instead points toward publication, propagation, or initial signer
responsiveness.

Examples:

```promql
histogram_quantile(
  0.95,
  sum by (le, milestone, outcome) (
    rate(stacks_node_signer_coordinator_milestone_seconds_bucket[15m])
  )
)
```

```promql
sum by (classification) (
  rate(stacks_node_signer_response_weight_total[5m])
)
```

Process restarts create counter discontinuities. Consumers comparing actors
must use rates or reset-aware deltas rather than raw lifetime totals.
