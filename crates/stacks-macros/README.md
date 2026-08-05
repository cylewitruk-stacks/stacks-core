# stacks-macros

Generic helper macros shared by Stacks crates.

This crate should stay domain-light: reusable macro expansions may depend on
caller-side crates like `serde` or `const-hex`, but should not depend on
Stacks domain crates such as `stacks-primitives`, `stacks-codec`, or `stacks-common`.
