# stacks-codec

The Stacks consensus binary serialization boundary.

This crate owns `StacksMessageCodec`, codec errors, shared serialization macros,
and binary wire-format implementations for foundational Stacks and P2P values.
Domain crates may also provide codec implementations for types they own when
that keeps domain-specific serialization beside the type.

With the `testing` feature enabled, `stacks-codec::testing` provides shared
exact-byte, round-trip, and truncation assertions for domain codec tests.

The word "codec" here means consensus binary serialization. It does not include
every representation of a value:

- C32Check address text, hex formatting, parsing, and serde representations are
  intrinsic representations owned with their value types.
- Cryptographic parsing, hashing, signing, and verification belong in
  `stacks-crypto`.
- SQLite representations belong in `stacks-rusqlite`.

This crate depends on foundational types such as `stacks-primitives` and
`stacks-p2p` so it can implement their wire formats. Those crates must not
depend back on `stacks-codec`; preserving that direction avoids cycles and
keeps values usable without the consensus serialization layer.

This crate does not decide whether a decoded value is valid in a particular
network, epoch, transaction, mempool, or chainstate context. Those decisions
belong to the corresponding protocol and business domains.
