# stacks-crypto

Cryptographic helpers for Stacks blockchain types.

This crate owns reusable cryptographic operations over Stacks primitives, such
as hash calculation, signature creation, public-key recovery, and signature
verification.

It intentionally does not own consensus serialization or chainstate validity.
