# stacks-protocol

Network-, epoch-, and protocol-specific policy for Stacks.

This crate interprets foundational values in protocol context. It owns epoch
schedules and rules, coinbase emission schedules, activation heights, network
parameters, and network-specific address behavior such as version selection and
typed mainnet/testnet addresses. It also owns Proof-of-Transfer fork identity
(`PoxId`) and the protocol rule that derives a `SortitionId` from burnchain and
PoX context.

Raw values and context-free invariants remain in `stacks-primitives`. For
example, primitives owns the bytes and C32Check representation of a
`StacksAddress`; this crate decides whether an address version is valid for a
particular network. Cryptographic computation remains in `stacks-crypto`, and
transaction composition and authorization remain in `stacks-transactions`.

This crate deliberately does not own consensus binary serialization,
chainstate storage, peer networking machinery, or persistence integrations.
It may use P2P marker types where protocol policy maps epochs to advertised
versions, but socket handling and peer state belong elsewhere.

Dependency direction is from protocol policy toward foundational value and P2P
types, not from those lower-level crates back into protocol policy.
