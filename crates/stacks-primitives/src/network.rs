/// Type-level Stacks network marker.
///
/// Domain crates attach their own network-specific traits to these marker types
/// instead of centralizing unrelated constants in one crate.
pub trait StacksNetwork {
    const NAME: &'static str;
    const IS_MAINNET: bool;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Mainnet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Testnet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Regtest;

impl StacksNetwork for Mainnet {
    const NAME: &'static str = "mainnet";
    const IS_MAINNET: bool = true;
}

impl StacksNetwork for Testnet {
    const NAME: &'static str = "testnet";
    const IS_MAINNET: bool = false;
}

impl StacksNetwork for Regtest {
    const NAME: &'static str = "regtest";
    const IS_MAINNET: bool = false;
}
