use stacks_p2p::{
    PEER_VERSION_EPOCH_1_0, PEER_VERSION_EPOCH_2_0, PEER_VERSION_EPOCH_2_1, PEER_VERSION_EPOCH_2_2,
    PEER_VERSION_EPOCH_2_3, PEER_VERSION_EPOCH_2_4, PEER_VERSION_EPOCH_2_05,
    PEER_VERSION_EPOCH_2_5, PEER_VERSION_EPOCH_3_0, PEER_VERSION_EPOCH_3_1, PEER_VERSION_EPOCH_3_2,
    PEER_VERSION_EPOCH_3_3, PEER_VERSION_EPOCH_3_4,
};
use stacks_primitives::StacksEpochId;
use stacks_primitives::network::Testnet;

use crate::address::AddressNetwork;
use crate::epoch::schedule::{EpochList, StacksEpoch};
use crate::network::params::EpochScheduleLimits;

pub const C32_ADDRESS_VERSION_TESTNET_SINGLESIG: u8 = 26; // T
pub const C32_ADDRESS_VERSION_TESTNET_MULTISIG: u8 = 21; // N

impl AddressNetwork for Testnet {
    const C32_ADDRESS_VERSION_SINGLESIG: u8 = C32_ADDRESS_VERSION_TESTNET_SINGLESIG;
    const C32_ADDRESS_VERSION_MULTISIG: u8 = C32_ADDRESS_VERSION_TESTNET_MULTISIG;
}

/// Bitcoin mainline testnet3 activation heights.
/// TODO: No longer used since testnet3 is dead, so remove.
pub const BITCOIN_TESTNET_FIRST_BLOCK_HEIGHT: u64 = 2_000_000;
pub const BITCOIN_TESTNET_FIRST_BLOCK_TIMESTAMP: u32 = 1_622_691_840;
pub const BITCOIN_TESTNET_FIRST_BLOCK_HASH: &str =
    "000000000000010dd0863ec3d7a0bae17c1957ae1de9cbcdae8e77aad33e3b8c";
pub const BITCOIN_TESTNET_STACKS_2_05_BURN_HEIGHT: u64 = 2_104_380;
pub const BITCOIN_TESTNET_STACKS_21_BURN_HEIGHT: u64 = 2_422_101;
pub const BITCOIN_TESTNET_STACKS_22_BURN_HEIGHT: u64 = 2_431_300;
pub const BITCOIN_TESTNET_STACKS_23_BURN_HEIGHT: u64 = 2_431_633;
pub const BITCOIN_TESTNET_STACKS_24_BURN_HEIGHT: u64 = 2_432_545;
pub const BITCOIN_TESTNET_STACKS_25_BURN_HEIGHT: u64 = 2_583_893;
pub const BITCOIN_TESTNET_STACKS_30_BURN_HEIGHT: u64 = 30_000_000;
pub const BITCOIN_TESTNET_STACKS_31_BURN_HEIGHT: u64 = 30_000_001;
pub const BITCOIN_TESTNET_STACKS_32_BURN_HEIGHT: u64 = 30_000_002;
pub const BITCOIN_TESTNET_STACKS_33_BURN_HEIGHT: u64 = 30_000_003;
pub const BITCOIN_TESTNET_STACKS_34_BURN_HEIGHT: u64 = 30_000_004;

pub fn epoch_schedule<L: Clone>(
    limits: &EpochScheduleLimits<L>,
    stacks_epoch_max: u64,
) -> EpochList<L> {
    EpochList::new(&[
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch10,
            start_height: 0,
            end_height: BITCOIN_TESTNET_FIRST_BLOCK_HEIGHT,
            block_limit: limits.mainnet_10.clone(),
            network_epoch: PEER_VERSION_EPOCH_1_0,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch20,
            start_height: BITCOIN_TESTNET_FIRST_BLOCK_HEIGHT,
            end_height: BITCOIN_TESTNET_STACKS_2_05_BURN_HEIGHT,
            block_limit: limits.mainnet_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_0,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch2_05,
            start_height: BITCOIN_TESTNET_STACKS_2_05_BURN_HEIGHT,
            end_height: BITCOIN_TESTNET_STACKS_21_BURN_HEIGHT,
            block_limit: limits.mainnet_205.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_05,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch21,
            start_height: BITCOIN_TESTNET_STACKS_21_BURN_HEIGHT,
            end_height: BITCOIN_TESTNET_STACKS_22_BURN_HEIGHT,
            block_limit: limits.mainnet_21.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_1,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch22,
            start_height: BITCOIN_TESTNET_STACKS_22_BURN_HEIGHT,
            end_height: BITCOIN_TESTNET_STACKS_23_BURN_HEIGHT,
            block_limit: limits.mainnet_21.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_2,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch23,
            start_height: BITCOIN_TESTNET_STACKS_23_BURN_HEIGHT,
            end_height: BITCOIN_TESTNET_STACKS_24_BURN_HEIGHT,
            block_limit: limits.mainnet_21.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_3,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch24,
            start_height: BITCOIN_TESTNET_STACKS_24_BURN_HEIGHT,
            end_height: BITCOIN_TESTNET_STACKS_25_BURN_HEIGHT,
            block_limit: limits.mainnet_21.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_4,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch25,
            start_height: BITCOIN_TESTNET_STACKS_25_BURN_HEIGHT,
            end_height: BITCOIN_TESTNET_STACKS_30_BURN_HEIGHT,
            block_limit: limits.mainnet_21.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_5,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch30,
            start_height: BITCOIN_TESTNET_STACKS_30_BURN_HEIGHT,
            end_height: BITCOIN_TESTNET_STACKS_31_BURN_HEIGHT,
            block_limit: limits.mainnet_21.clone(),
            network_epoch: PEER_VERSION_EPOCH_3_0,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch31,
            start_height: BITCOIN_TESTNET_STACKS_31_BURN_HEIGHT,
            end_height: BITCOIN_TESTNET_STACKS_32_BURN_HEIGHT,
            block_limit: limits.mainnet_21.clone(),
            network_epoch: PEER_VERSION_EPOCH_3_1,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch32,
            start_height: BITCOIN_TESTNET_STACKS_32_BURN_HEIGHT,
            end_height: BITCOIN_TESTNET_STACKS_33_BURN_HEIGHT,
            block_limit: limits.mainnet_21.clone(),
            network_epoch: PEER_VERSION_EPOCH_3_2,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch33,
            start_height: BITCOIN_TESTNET_STACKS_33_BURN_HEIGHT,
            end_height: BITCOIN_TESTNET_STACKS_34_BURN_HEIGHT,
            block_limit: limits.mainnet_21.clone(),
            network_epoch: PEER_VERSION_EPOCH_3_3,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch34,
            start_height: BITCOIN_TESTNET_STACKS_34_BURN_HEIGHT,
            end_height: stacks_epoch_max,
            block_limit: limits.mainnet_21.clone(),
            network_epoch: PEER_VERSION_EPOCH_3_4,
        },
    ])
}
