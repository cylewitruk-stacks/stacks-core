use stacks_p2p::{
    PEER_VERSION_EPOCH_1_0, PEER_VERSION_EPOCH_2_0, PEER_VERSION_EPOCH_2_1, PEER_VERSION_EPOCH_2_2,
    PEER_VERSION_EPOCH_2_3, PEER_VERSION_EPOCH_2_4, PEER_VERSION_EPOCH_2_05,
    PEER_VERSION_EPOCH_2_5, PEER_VERSION_EPOCH_3_0, PEER_VERSION_EPOCH_3_1, PEER_VERSION_EPOCH_3_2,
    PEER_VERSION_EPOCH_3_3, PEER_VERSION_EPOCH_3_4, PEER_VERSION_EPOCH_4_0, PEER_VERSION_EPOCH_4_1,
};
use stacks_primitives::StacksEpochId;
use stacks_primitives::network::Regtest;

use crate::address::AddressNetwork;
use crate::epoch::schedule::{EpochList, StacksEpoch};
use crate::network::params::EpochScheduleLimits;
use crate::network::testnet::{
    C32_ADDRESS_VERSION_TESTNET_MULTISIG, C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
};

pub const BITCOIN_REGTEST_FIRST_BLOCK_HEIGHT: u64 = 0;
pub const BITCOIN_REGTEST_FIRST_BLOCK_TIMESTAMP: u32 = 0;
pub const BITCOIN_REGTEST_FIRST_BLOCK_HASH: &str =
    "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";

impl AddressNetwork for Regtest {
    const C32_ADDRESS_VERSION_SINGLESIG: u8 = C32_ADDRESS_VERSION_TESTNET_SINGLESIG;
    const C32_ADDRESS_VERSION_MULTISIG: u8 = C32_ADDRESS_VERSION_TESTNET_MULTISIG;
}

pub fn epoch_schedule<L: Clone>(
    limits: &EpochScheduleLimits<L>,
    stacks_epoch_max: u64,
) -> EpochList<L> {
    EpochList::new(&[
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch10,
            start_height: 0,
            end_height: 0,
            block_limit: limits.mainnet_10.clone(),
            network_epoch: PEER_VERSION_EPOCH_1_0,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch20,
            start_height: 0,
            end_height: 1000,
            block_limit: limits.testnet_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_0,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch2_05,
            start_height: 1000,
            end_height: 2000,
            block_limit: limits.testnet_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_05,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch21,
            start_height: 2000,
            end_height: 3000,
            block_limit: limits.testnet_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_1,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch22,
            start_height: 3000,
            end_height: 4000,
            block_limit: limits.testnet_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_2,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch23,
            start_height: 4000,
            end_height: 5000,
            block_limit: limits.testnet_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_3,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch24,
            start_height: 5000,
            end_height: 6000,
            block_limit: limits.testnet_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_4,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch25,
            start_height: 6000,
            end_height: 7001,
            block_limit: limits.mainnet_21.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_5,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch30,
            start_height: 7001,
            end_height: 8001,
            block_limit: limits.mainnet_21.clone(),
            network_epoch: PEER_VERSION_EPOCH_3_0,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch31,
            start_height: 8001,
            end_height: 9001,
            block_limit: limits.mainnet_21.clone(),
            network_epoch: PEER_VERSION_EPOCH_3_1,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch32,
            start_height: 9001,
            end_height: 10001,
            block_limit: limits.mainnet_21.clone(),
            network_epoch: PEER_VERSION_EPOCH_3_2,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch33,
            start_height: 10001,
            end_height: 11001,
            block_limit: limits.mainnet_21.clone(),
            network_epoch: PEER_VERSION_EPOCH_3_3,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch34,
            start_height: 11001,
            end_height: 12001,
            block_limit: limits.mainnet_21.clone(),
            network_epoch: PEER_VERSION_EPOCH_3_4,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch40,
            start_height: 12001,
            end_height: 13001,
            block_limit: limits.mainnet_40.clone(),
            network_epoch: PEER_VERSION_EPOCH_4_0,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch41,
            start_height: 13001,
            end_height: stacks_epoch_max,
            block_limit: limits.mainnet_40.clone(),
            network_epoch: PEER_VERSION_EPOCH_4_1,
        },
    ])
}
