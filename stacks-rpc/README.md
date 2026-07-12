# Stacks RPC

`stacks-rpc` is the node's parallel Axum HTTP API. Its read handlers use an independent,
bounded pool of read-only chainstate, sortition DB, and Clarity MARF handles. They do not execute
on the P2P thread.

## Public v1 reads

- `GET /rpc/v1/info`
- `GET /rpc/v1/accounts/{principal}`
- `GET /rpc/v1/blocks/{block_id}`
- `GET /rpc/v1/blocks/by-height/{height}`
- `GET /rpc/v1/headers`
- `GET /rpc/v1/transactions/{txid}`
- `GET /rpc/v1/pox`
- `GET /rpc/v1/signers/{public_key}/cycles/{reward_cycle}`
- `GET /rpc/v1/stacking/reward-cycles/{reward_cycle}/stackers`
- `GET /rpc/v1/sortitions/{selector}` through the typed selector routes
- `GET /rpc/v1/tenures/{consensus_hash}/tip`
- `GET /rpc/v1/tenures/{selector}/blocks` through the paginated selector routes
- `GET /rpc/v1/tenures/forks/{start}/{end}`
- Contract source, interface, metadata, data variable, constant, map, trait, and read-only call
  resources below `/rpc/v1/contracts/{address}/{contract}`

`tip` defaults to the canonical anchored tip. `tip=latest` requests unconfirmed state, but pooled
read-only handles do not maintain it and therefore resolve to the canonical anchored tip. A
specific 32-byte index block hash may also be supplied. Proofs are opt-in with `proof=true`.
Confirmed transaction lookup requires the node's `txindex` setting; nodes without it return a
typed `501 transaction_index_disabled` response.

## Legacy-only surfaces

The Axum API intentionally does not duplicate peer and neighbor state, mempool or unconfirmed
transactions, Atlas attachments, StackerDB replication, fee-estimator state, microblocks, raw
Clarity MARF access, privileged replay/simulation/fast-call diagnostics, epoch-2 block transport,
or raw tenure-download transport. These are node-internal, peer-sync, mutable-owner, or privileged
surfaces rather than public read-pool resources.

The one write endpoint currently exposed is authenticated block-proposal submission. It crosses
the RPC bridge because proposal validation is owned by the node thread.
