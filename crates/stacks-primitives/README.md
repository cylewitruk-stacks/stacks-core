# stacks-primitives

Foundational value types for the Stacks protocol.

This crate owns small domain values, their structural invariants, and their
canonical self-representations. Examples include block and transaction
identifiers, hash-result values, epoch and network markers, serialized public
key and signature bytes, guarded strings, `StacksAddress`, and the opaque
`VRFSeed` produced after proof validation.

Names such as `hash` and `secp256k1` describe the values represented, not
operations performed by this crate:

- Hash types contain already-computed digest bytes; hashing data belongs in
  `stacks-crypto`.
- Public-key and signature types describe serialized bytes and byte layouts;
  key generation, curve validation, signing, recovery, and verification belong
  in `stacks-crypto`.
- `VRFSeed` stores an already-derived seed; VRF keys, validated proofs, proof
  verification, and seed derivation belong in `stacks-crypto`.
- C32Check belongs here as the canonical textual representation of
  `StacksAddress`, alongside `Display` and parsing. Network-specific address
  interpretation belongs in `stacks-protocol`.
- Hex parsing and `HexError` belong here as intrinsic representations of the
  fixed-byte values; the compatibility facade in `stacks-common` re-exports
  the same error type.

This crate deliberately does not own cryptographic computation, consensus
binary serialization, network or epoch policy, transaction behavior, or
persistence integrations. Those responsibilities belong to `stacks-crypto`,
`stacks-codec`, `stacks-protocol`, `stacks-transactions`, and
`stacks-rusqlite`, respectively.

Dependency direction should point from those behavioral and integration crates
toward `stacks-primitives`, never back from primitives into them.
