# stacks-crypto

Cryptographic operations over Stacks protocol values.

This crate owns reusable cryptographic behavior: digest calculation, Merkle
hashing, secp256k1 key parsing and generation, signature creation, public-key
recovery, signature verification, public-key/script address-hash derivation,
block-identifier derivation, validated VRF keys and proofs, and native/WASM
backend selection. It accepts and returns value types from `stacks-primitives`
where appropriate.

The corresponding byte containers remain in `stacks-primitives`. For example,
`Hash160` is a primitive value, while computing a `Hash160` from input data is a
`stacks-crypto` operation. Likewise, serialized signature bytes are primitive
values, while signing and verification happen here.

`VRFProof` is intentionally owned here rather than represented as arbitrary
primitive bytes: constructing one validates its encoded curve point and
scalars, and consensus decoding must preserve that invariant. The resulting
opaque `VRFSeed` remains a value in `stacks-primitives`.

This crate deliberately does not own consensus binary serialization, address
network policy, transaction authorization rules, chainstate validity, key
custody or wallet policy, or persistence integrations. Those belong to the
codec, protocol, transaction, application, and storage boundaries.

Dependency direction is `stacks-crypto -> stacks-primitives`; primitives must
not depend on this crate.
