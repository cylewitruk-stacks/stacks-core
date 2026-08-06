// TODO: migrate callers to `stacks-codec` directly, then remove this bridge.
pub use stacks_codec::codec::*;
/// Codec test helpers. Available under `cfg(test)` to this crate, and under
/// the `testing` feature to downstream crates that exercise their own codec
/// implementations in tests.
#[cfg(any(test, feature = "testing"))]
pub use stacks_codec::testing;
