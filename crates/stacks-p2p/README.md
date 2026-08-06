# stacks-p2p

Foundational peer-to-peer protocol values for Stacks.

This crate currently owns peer-facing value types and mappings that are
intrinsic to the P2P protocol, including normalized peer IP addresses,
advertised peer-version constants, and the epoch-to-peer-version mapping.

It deliberately does not own sockets, transports, handshakes, peer databases,
inventory synchronization, connection state machines, or node networking
policy. Those remain in higher-level networking code. Consensus binary
serialization for these values belongs in `stacks-codec`, while broader epoch
and network policy belongs in `stacks-protocol`.

This is intentionally a small boundary: it prevents peer protocol concepts from
being folded into general primitives or unrelated protocol-rule modules.
