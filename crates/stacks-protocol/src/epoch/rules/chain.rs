use stacks_primitives::StacksEpochId;

// Sliding burnchain window over which a miner's past block-commit payouts will be used to weight
// its current block-commit in a sortition. This is the value used in epoch 2.x.
pub const MINING_COMMITMENT_WINDOW: u8 = 6;

// How often a miner must commit in its mining commitment window in order to even be considered for
// sortition. Only relevant for Nakamoto (epoch 3.x).
pub const MINING_COMMITMENT_FREQUENCY_NAKAMOTO: u8 = 3;

#[derive(Debug)]
pub enum MempoolCollectionBehavior {
    ByStacksHeight,
    ByReceiveTime,
}

pub trait ChainEpochRules {
    fn mempool_garbage_behavior(self) -> MempoolCollectionBehavior;
    fn enforces_strict_signature_order(self) -> bool;
    fn allows_pox_punishment(self) -> bool;
    fn block_commits_to_parent(self) -> bool;
    fn supports_shadow_blocks(self) -> bool;
    fn supports_pox_missed_slot_unlocks(self) -> bool;
    fn mining_commitment_window(self) -> u8;
    fn mining_commitment_frequency(self) -> u8;
    fn uses_nakamoto_blocks(self) -> bool;
    fn uses_nakamoto_reward_set(
        self,
        cur_reward_cycle: u64,
        first_epoch30_reward_cycle: u64,
    ) -> bool;
    fn supports_sip040_post_conditions(self) -> bool;
    fn supports_cost_voting_contract(self) -> bool;
    fn starts_reward_cycle_at_0(self) -> bool;
    fn supports_staking_post_conditions(self) -> bool;
    fn allows_tx_signatures_with_high_s(self) -> bool;
}

impl ChainEpochRules for StacksEpochId {
    fn mempool_garbage_behavior(self) -> MempoolCollectionBehavior {
        if self >= StacksEpochId::Epoch30 {
            MempoolCollectionBehavior::ByReceiveTime
        } else {
            MempoolCollectionBehavior::ByStacksHeight
        }
    }

    fn enforces_strict_signature_order(self) -> bool {
        self >= StacksEpochId::Epoch40
    }

    fn allows_pox_punishment(self) -> bool {
        self >= StacksEpochId::Epoch30
    }

    fn block_commits_to_parent(self) -> bool {
        self >= StacksEpochId::Epoch30
    }

    fn supports_shadow_blocks(self) -> bool {
        self >= StacksEpochId::Epoch30
    }

    fn supports_pox_missed_slot_unlocks(self) -> bool {
        self < StacksEpochId::Epoch25
    }

    fn mining_commitment_window(self) -> u8 {
        MINING_COMMITMENT_WINDOW
    }

    fn mining_commitment_frequency(self) -> u8 {
        if self >= StacksEpochId::Epoch30 {
            MINING_COMMITMENT_FREQUENCY_NAKAMOTO
        } else {
            0
        }
    }

    fn uses_nakamoto_blocks(self) -> bool {
        self >= StacksEpochId::Epoch30
    }

    fn uses_nakamoto_reward_set(
        self,
        cur_reward_cycle: u64,
        first_epoch30_reward_cycle: u64,
    ) -> bool {
        self >= StacksEpochId::Epoch30 && cur_reward_cycle > first_epoch30_reward_cycle
    }

    fn supports_sip040_post_conditions(self) -> bool {
        self >= StacksEpochId::Epoch34
    }

    fn supports_cost_voting_contract(self) -> bool {
        self < StacksEpochId::Epoch40
    }

    fn starts_reward_cycle_at_0(self) -> bool {
        self >= StacksEpochId::Epoch40
    }

    fn supports_staking_post_conditions(self) -> bool {
        self >= StacksEpochId::Epoch40
    }

    fn allows_tx_signatures_with_high_s(self) -> bool {
        self < StacksEpochId::Epoch40
    }
}
