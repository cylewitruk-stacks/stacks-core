#[derive(Clone)]
pub struct EpochScheduleLimits<L> {
    pub mainnet_10: L,
    pub mainnet_20: L,
    pub mainnet_205: L,
    pub mainnet_21: L,
    pub testnet_20: L,
}
