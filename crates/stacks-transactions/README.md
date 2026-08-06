# stacks-transactions

The Stacks transaction domain.

This crate owns transaction aggregates and transaction-specific behavior:
authorization and spending conditions, authentication fields, payloads,
post-conditions, tenure-change payloads, sighash progression, signature
verification policy, and public-key/script address derivation. Its optional
`codec` feature contains transaction-specific consensus serialization.

This is the canonical transaction implementation used by `stackslib`.
`stackslib::chainstate::stacks::transaction_types` remains only as a temporary
compatibility re-export for existing import paths; transaction behavior must be
implemented here rather than in that facade.

The crate composes foundational values from `stacks-primitives`, cryptographic
operations from `stacks-crypto`, network and epoch policy from
`stacks-protocol`, and Clarity-facing values from `clarity-types`.

Generic hashing, key generation, and curve operations do not belong here merely
because transactions use them; they remain in `stacks-crypto`. Likewise, this
crate does not own global primitive types, mempool or chainstate acceptance,
account persistence, fee estimation, networking, or SQLite representations.

Transaction-specific cryptographic orchestration belongs here; reusable
cryptographic mechanisms belong in `stacks-crypto`.
