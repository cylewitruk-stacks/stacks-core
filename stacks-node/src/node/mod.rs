mod chainstate;
mod context;
mod genesis;
mod leader_key;
mod network;
mod protocol;
mod runtime;
mod simulator;
mod supervisor;

pub use protocol::epoch2::node::{BlockMinerThread, TipCandidate};
pub use simulator::driver::Driver as SimulatorDriver;
pub use supervisor::{NodeRunner, RuntimePlan};

#[cfg(test)]
pub mod test_support {
    pub use crate::node::leader_key::load_activated_vrf_key;
    pub use crate::node::runtime::{Counters, RunLoopCounter};

    pub mod epoch2 {
        pub use crate::node::protocol::epoch2::driver::Driver;
    }

    pub mod nakamoto {
        pub mod miner {
            pub use crate::node::protocol::nakamoto::miner::{
                fault_injection_stall_miner, fault_injection_try_stall_miner,
                fault_injection_unstall_miner, TEST_BLOCK_ANNOUNCE_STALL,
                TEST_BROADCAST_PROPOSAL_STALL, TEST_MINER_BROADCASTING_BLOCK, TEST_MINE_SKIP,
                TEST_P2P_BROADCAST_SKIP, TEST_P2P_BROADCAST_STALL,
            };
        }

        pub mod relayer {
            pub use crate::node::protocol::nakamoto::relayer::{
                TEST_MINER_COMMIT_TIP, TEST_MINER_THREAD_STALL,
            };
        }

        pub mod signer {
            pub mod listener {
                pub use crate::node::protocol::nakamoto::signer::listener::TEST_IGNORE_SIGNERS;
            }
        }
    }
}
