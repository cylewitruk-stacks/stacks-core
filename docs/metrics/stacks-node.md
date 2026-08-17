# `stacks-node` metrics

## Nakamoto block transfers

The node exports one bounded counter family for Nakamoto block movement:

```text
stacks_node_nakamoto_block_transfers_total{direction,source,outcome}
```

This fills the post-Epoch-3 visibility gap left by
`stacks_node_stx_blocks_received_total`, which only observes legacy block
messages. It is an observation-only metric and does not alter validation,
storage, relay, or HTTP behavior.

## Label contract

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

## Counting boundaries

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
each completely served block contributes one observation.

## PromQL examples

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
