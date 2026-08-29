# Stacks RPC

`stacks-rpc` is the node's parallel Axum HTTP API. Chainstate reads use an independent, bounded
pool of read-only chainstate, sortition DB, and Clarity MARF handles. Mempool reads use a separate
read-only SQLite pool. Peer-owned status is published as an atomic snapshot, and bounded command
queues carry the operations that must execute on the node thread.

## Public v1 reads

- `GET /rpc/v1/info`
- `GET /rpc/v1/health`
- `GET /rpc/v1/accounts/{principal}`
- `GET /rpc/v1/blocks/{block_id}`
- `GET /rpc/v1/blocks/by-height/{height}`
- `GET /rpc/v1/headers`
- `GET /rpc/v1/transactions/{txid}`
- `GET /rpc/v1/mempool/transactions`
- `GET /rpc/v1/mempool/transactions/{txid}`
- `GET /rpc/v1/pox`
- `GET /rpc/v1/signers/{public_key}/cycles/{reward_cycle}`
- `GET /rpc/v1/stacking/reward-cycles/{reward_cycle}/stackers`
- `GET /rpc/v1/sortitions/{selector}` through the typed selector routes
- `GET /rpc/v1/tenures/{consensus_hash}/tip`
- `GET /rpc/v1/tenures/current`
- `GET /rpc/v1/tenures/{selector}/blocks` through the paginated selector routes
- `GET /rpc/v1/tenures/forks/{start}/{end}`
- Contract source, interface, metadata, data variable, constant, map, trait, and read-only call
  resources below `/rpc/v1/contracts/{address}/{contract}`

`tip` defaults to the canonical anchored tip. `tip=latest` requests unconfirmed state, but pooled
read-only handles do not maintain it and therefore resolve to the canonical anchored tip. A
specific 32-byte index block hash may also be supplied. Proofs are opt-in with `proof=true`.
Confirmed transaction lookup requires the node's `txindex` setting; nodes without it return a
typed `501 transaction_index_disabled` response.

Mempool collection reads are cursor-paginated and return newest transactions first. Post-Nakamoto
nodes do not expose legacy unconfirmed-microblock state through this API.

`/info`, `/health`, and `/tenures/current` are served from one lock-free snapshot published once
per P2P loop. Their `observed_at` Unix timestamp makes snapshot age explicit if the node thread is
delayed. Before the first snapshot, these routes return `503 node_snapshot_unavailable`.

## Public v1 operations

- `POST /rpc/v1/transactions` submits a consensus-serialized transaction through the bounded node
  bridge and returns `202 accepted` or `200 already_known`.
- `POST /rpc/v1/fees/transactions` estimates fees through independent, concurrency-safe estimator
  handles. Nodes without configured estimators return `501 fee_estimation_disabled`; payloads
  without an available estimate return `422 fee_estimate_unavailable`.
- `POST /rpc/v1/block-proposals` submits an authenticated proposal through the bounded node bridge.

## Legacy-only surfaces

The Axum API intentionally does not duplicate detailed peer and neighbor administration, the
peer-sync mempool bloom-filter protocol, Atlas attachment transport, StackerDB replication,
microblocks, raw Clarity MARF access, privileged replay/simulation/fast-call diagnostics, epoch-2
block transport, or raw tenure-download transport. These remain node-internal, peer-sync, or
privileged legacy surfaces.
