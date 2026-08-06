# stacks-rusqlite

The rusqlite integration boundary for persistence-agnostic Stacks domain types.

This crate owns SQLite scalar wrappers, `ToSql` and `FromSql` implementations on
those wrappers, and checked conversion between SQLite values and domain types.
Database code should wrap values only at the query boundary and convert decoded
values back into domain types immediately.

The adapters preserve the legacy `stacks-common` representations: extracted
fixed-byte primitives use lowercase hexadecimal SQLite `TEXT` values, and
validated `VRFProof` values use the same lowercase hexadecimal representation.
`StacksAddress` uses canonical C32Check text, and `VRFSeed` uses lowercase
hexadecimal text.

Use `domain_params!` at query boundaries when a parameter list mixes native
rusqlite values with Stacks domain values. Use `SqlValue<T>` for row decoding;
`SqlRef<T>` is available when an individual borrowed adapter is clearer. These
adapters centralize the legacy schema representation without coupling domain
types to rusqlite or relying on orphan-rule workarounds.

This crate deliberately does not own database connections, schemas, migrations,
queries, repository interfaces, or business-specific row structures. Those
belong beside the application or storage subsystem that owns the schema. Its
wrappers should never become alternative domain types that leak into consensus
or business logic.

Dependency direction is from `stacks-rusqlite` toward the domain crates and
`rusqlite`. Domain crates must not depend on this integration crate.
