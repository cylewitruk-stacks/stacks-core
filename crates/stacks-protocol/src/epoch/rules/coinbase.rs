use stacks_primitives::StacksEpochId;

use crate::epoch::emission::{coinbase_reward_pre_sip029, coinbase_reward_sip029};

pub trait EpochCoinbaseReward {
    fn coinbase_reward(
        self,
        mainnet: bool,
        first_burnchain_height: u64,
        current_burnchain_height: u64,
    ) -> u128;
}

impl EpochCoinbaseReward for StacksEpochId {
    fn coinbase_reward(
        self,
        mainnet: bool,
        first_burnchain_height: u64,
        current_burnchain_height: u64,
    ) -> u128 {
        if self == StacksEpochId::Epoch10 {
            0
        } else if self < StacksEpochId::Epoch31 {
            coinbase_reward_pre_sip029(first_burnchain_height, current_burnchain_height)
        } else {
            coinbase_reward_sip029(mainnet, first_burnchain_height, current_burnchain_height)
        }
    }
}
