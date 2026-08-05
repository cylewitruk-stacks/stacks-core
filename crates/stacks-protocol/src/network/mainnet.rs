use stacks_p2p::{
    PEER_VERSION_EPOCH_1_0, PEER_VERSION_EPOCH_2_0, PEER_VERSION_EPOCH_2_1, PEER_VERSION_EPOCH_2_2,
    PEER_VERSION_EPOCH_2_3, PEER_VERSION_EPOCH_2_4, PEER_VERSION_EPOCH_2_05,
    PEER_VERSION_EPOCH_2_5, PEER_VERSION_EPOCH_3_0, PEER_VERSION_EPOCH_3_1, PEER_VERSION_EPOCH_3_2,
    PEER_VERSION_EPOCH_3_3, PEER_VERSION_EPOCH_3_4,
};
use stacks_primitives::StacksEpochId;
use stacks_primitives::network::Mainnet;

use crate::address::AddressNetwork;
use crate::epoch::schedule::{EpochList, StacksEpoch};
use crate::network::params::EpochScheduleLimits;

pub const C32_ADDRESS_VERSION_MAINNET_SINGLESIG: u8 = 22; // P
pub const C32_ADDRESS_VERSION_MAINNET_MULTISIG: u8 = 20; // M

impl AddressNetwork for Mainnet {
    const C32_ADDRESS_VERSION_SINGLESIG: u8 = C32_ADDRESS_VERSION_MAINNET_SINGLESIG;
    const C32_ADDRESS_VERSION_MULTISIG: u8 = C32_ADDRESS_VERSION_MAINNET_MULTISIG;
}

// TODO: TO BE SET BY STACKS_V1_MINER_THRESHOLD
pub const BITCOIN_MAINNET_FIRST_BLOCK_HEIGHT: u64 = 666_050;
pub const BITCOIN_MAINNET_FIRST_BLOCK_TIMESTAMP: u32 = 1_610_643_248;
pub const BITCOIN_MAINNET_FIRST_BLOCK_HASH: &str =
    "0000000000000000000ab248c8e35c574514d052a83dbc12669e19bc43df486e";
pub const BITCOIN_MAINNET_INITIAL_REWARD_START_BLOCK: u64 = 651_389;
pub const BITCOIN_MAINNET_STACKS_2_05_BURN_HEIGHT: u64 = 713_000;
pub const BITCOIN_MAINNET_STACKS_21_BURN_HEIGHT: u64 = 781_551;
/// This is Epoch-2.2 activation height proposed in SIP-022
pub const BITCOIN_MAINNET_STACKS_22_BURN_HEIGHT: u64 = 787_651;
/// This is Epoch-2.3 activation height proposed in SIP-023
pub const BITCOIN_MAINNET_STACKS_23_BURN_HEIGHT: u64 = 788_240;
/// This is Epoch-2.3, now Epoch-2.4, activation height proposed in SIP-024
pub const BITCOIN_MAINNET_STACKS_24_BURN_HEIGHT: u64 = 791_551;
/// This is Epoch-2.5, activation height proposed in SIP-021
pub const BITCOIN_MAINNET_STACKS_25_BURN_HEIGHT: u64 = 840_360;
/// This is Epoch-3.0, activation height proposed in SIP-021
pub const BITCOIN_MAINNET_STACKS_30_BURN_HEIGHT: u64 = 867_867;
/// This is Epoch-3.1, activation height proposed in SIP-029
pub const BITCOIN_MAINNET_STACKS_31_BURN_HEIGHT: u64 = 875_000;
/// This is Epoch-3.2, activation height proposed in SIP-031
pub const BITCOIN_MAINNET_STACKS_32_BURN_HEIGHT: u64 = 907_740;
/// This is Epoch-3.3, activation timing proposed in SIP-033
pub const BITCOIN_MAINNET_STACKS_33_BURN_HEIGHT: u64 = 923_222;
/// This is Epoch-3.4, activation timing proposed in SIP-039
pub const BITCOIN_MAINNET_STACKS_34_BURN_HEIGHT: u64 = 943_333;

pub fn epoch_schedule<L: Clone>(
    limits: &EpochScheduleLimits<L>,
    stacks_epoch_max: u64,
) -> EpochList<L> {
    EpochList::new(&[
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch10,
            start_height: 0,
            end_height: BITCOIN_MAINNET_FIRST_BLOCK_HEIGHT,
            block_limit: limits.mainnet_10.clone(),
            network_epoch: PEER_VERSION_EPOCH_1_0,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch20,
            start_height: BITCOIN_MAINNET_FIRST_BLOCK_HEIGHT,
            end_height: BITCOIN_MAINNET_STACKS_2_05_BURN_HEIGHT,
            block_limit: limits.mainnet_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_0,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch2_05,
            start_height: BITCOIN_MAINNET_STACKS_2_05_BURN_HEIGHT,
            end_height: BITCOIN_MAINNET_STACKS_21_BURN_HEIGHT,
            block_limit: limits.mainnet_205.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_05,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch21,
            start_height: BITCOIN_MAINNET_STACKS_21_BURN_HEIGHT,
            end_height: BITCOIN_MAINNET_STACKS_22_BURN_HEIGHT,
            block_limit: limits.mainnet_21.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_1,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch22,
            start_height: BITCOIN_MAINNET_STACKS_22_BURN_HEIGHT,
            end_height: BITCOIN_MAINNET_STACKS_23_BURN_HEIGHT,
            block_limit: limits.mainnet_21.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_2,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch23,
            start_height: BITCOIN_MAINNET_STACKS_23_BURN_HEIGHT,
            end_height: BITCOIN_MAINNET_STACKS_24_BURN_HEIGHT,
            block_limit: limits.mainnet_21.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_3,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch24,
            start_height: BITCOIN_MAINNET_STACKS_24_BURN_HEIGHT,
            end_height: BITCOIN_MAINNET_STACKS_25_BURN_HEIGHT,
            block_limit: limits.mainnet_21.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_4,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch25,
            start_height: BITCOIN_MAINNET_STACKS_25_BURN_HEIGHT,
            end_height: BITCOIN_MAINNET_STACKS_30_BURN_HEIGHT,
            block_limit: limits.mainnet_21.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_5,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch30,
            start_height: BITCOIN_MAINNET_STACKS_30_BURN_HEIGHT,
            end_height: BITCOIN_MAINNET_STACKS_31_BURN_HEIGHT,
            block_limit: limits.mainnet_21.clone(),
            network_epoch: PEER_VERSION_EPOCH_3_0,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch31,
            start_height: BITCOIN_MAINNET_STACKS_31_BURN_HEIGHT,
            end_height: BITCOIN_MAINNET_STACKS_32_BURN_HEIGHT,
            block_limit: limits.mainnet_21.clone(),
            network_epoch: PEER_VERSION_EPOCH_3_1,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch32,
            start_height: BITCOIN_MAINNET_STACKS_32_BURN_HEIGHT,
            end_height: BITCOIN_MAINNET_STACKS_33_BURN_HEIGHT,
            block_limit: limits.mainnet_21.clone(),
            network_epoch: PEER_VERSION_EPOCH_3_2,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch33,
            start_height: BITCOIN_MAINNET_STACKS_33_BURN_HEIGHT,
            end_height: BITCOIN_MAINNET_STACKS_34_BURN_HEIGHT,
            block_limit: limits.mainnet_21.clone(),
            network_epoch: PEER_VERSION_EPOCH_3_3,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch34,
            start_height: BITCOIN_MAINNET_STACKS_34_BURN_HEIGHT,
            end_height: stacks_epoch_max,
            block_limit: limits.mainnet_21.clone(),
            network_epoch: PEER_VERSION_EPOCH_3_4,
        },
    ])
}
