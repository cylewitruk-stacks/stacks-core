# stacks-macros

Generic helper macros shared across the workspace.

This crate owns reusable macro definitions for repetitive Rust implementations,
such as fixed-byte newtypes and enum helpers. It contains no runtime services or
Stacks protocol policy.

Macro expansions may refer to dependencies supplied by the invoking crate, such
as `serde` or `const-hex`. The macro crate itself should remain domain-agnostic
and must not depend on `stacks-primitives`, `stacks-crypto`, `stacks-codec`,
`stacks-protocol`, `stacks-transactions`, or `stacks-common`.

If a macro encodes a consensus or business rule rather than eliminating purely
mechanical repetition, that rule belongs in the relevant domain crate instead.
