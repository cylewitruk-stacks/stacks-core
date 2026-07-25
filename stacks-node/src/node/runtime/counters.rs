// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Runtime counters shared across protocol transitions.

#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(test)]
use std::sync::Arc;

use stacks::chainstate::burn::ConsensusHash;
#[cfg(test)]
use stacks::util::tests::TestFlag;

#[cfg(test)]
#[derive(Clone)]
pub struct RunLoopCounter(pub Arc<AtomicU64>);

#[cfg(not(test))]
#[derive(Clone)]
pub struct RunLoopCounter();

impl Default for RunLoopCounter {
    #[cfg(test)]
    fn default() -> Self {
        RunLoopCounter(Arc::new(AtomicU64::new(0)))
    }

    #[cfg(not(test))]
    fn default() -> Self {
        Self()
    }
}

impl RunLoopCounter {
    #[cfg(test)]
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    pub fn load(&self, ordering: Ordering) -> u64 {
        self.0.load(ordering)
    }
}

#[cfg(test)]
impl std::ops::Deref for RunLoopCounter {
    type Target = Arc<AtomicU64>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Default)]
pub struct Counters {
    pub blocks_processed: RunLoopCounter,
    pub microblocks_processed: RunLoopCounter,
    pub missed_tenures: RunLoopCounter,
    pub sortitions_processed: RunLoopCounter,
    pub naka_submitted_vrfs: RunLoopCounter,
    pub neon_submitted_commits: RunLoopCounter,
    pub neon_submitted_commit_last_burn_height: RunLoopCounter,
    pub naka_submitted_commits: RunLoopCounter,
    pub naka_submitted_commit_last_burn_height: RunLoopCounter,
    pub naka_mined_blocks: RunLoopCounter,
    pub naka_rejected_blocks: RunLoopCounter,
    pub naka_proposed_blocks: RunLoopCounter,
    pub naka_mined_tenures: RunLoopCounter,
    pub naka_signer_pushed_blocks: RunLoopCounter,
    pub naka_miner_directives: RunLoopCounter,
    pub naka_submitted_commit_last_stacks_tip: RunLoopCounter,
    pub naka_submitted_commit_last_commit_amount: RunLoopCounter,
    pub naka_miner_current_rejections: RunLoopCounter,
    pub naka_miner_current_rejections_timeout_secs: RunLoopCounter,

    #[cfg(test)]
    pub naka_submitted_commit_last_parent_tenure_id: TestFlag<ConsensusHash>,
    #[cfg(test)]
    pub skip_commit_op: TestFlag<bool>,
}

impl Counters {
    #[cfg(test)]
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    fn inc(ctr: &RunLoopCounter) {
        ctr.0.fetch_add(1, Ordering::SeqCst);
    }

    #[cfg(not(test))]
    fn inc(_ctr: &RunLoopCounter) {}

    #[cfg(test)]
    fn set(ctr: &RunLoopCounter, value: u64) {
        ctr.0.store(value, Ordering::SeqCst);
    }

    #[cfg(not(test))]
    fn set(_ctr: &RunLoopCounter, _value: u64) {}

    pub fn bump_blocks_processed(&self) {
        Counters::inc(&self.blocks_processed);
    }

    pub fn bump_sortitions_processed(&self) {
        Counters::inc(&self.sortitions_processed);
    }

    pub fn bump_missed_tenures(&self) {
        Counters::inc(&self.missed_tenures);
    }

    pub fn bump_neon_submitted_commits(&self, committed_burn_height: u64) {
        Counters::inc(&self.neon_submitted_commits);
        Counters::set(
            &self.neon_submitted_commit_last_burn_height,
            committed_burn_height,
        );
    }

    pub fn bump_naka_submitted_vrfs(&self) {
        Counters::inc(&self.naka_submitted_vrfs);
    }

    pub fn bump_naka_submitted_commits(
        &self,
        committed_burn_height: u64,
        committed_stacks_height: u64,
        committed_sats_amount: u64,
        committed_parent_tenure_id: &ConsensusHash,
    ) {
        Counters::inc(&self.naka_submitted_commits);
        Counters::set(
            &self.naka_submitted_commit_last_burn_height,
            committed_burn_height,
        );
        Counters::set(
            &self.naka_submitted_commit_last_stacks_tip,
            committed_stacks_height,
        );
        Counters::set(
            &self.naka_submitted_commit_last_commit_amount,
            committed_sats_amount,
        );
        #[cfg(test)]
        self.naka_submitted_commit_last_parent_tenure_id
            .set(committed_parent_tenure_id.clone());
        #[cfg(not(test))]
        let _ = committed_parent_tenure_id;
    }

    pub fn bump_naka_mined_blocks(&self) {
        Counters::inc(&self.naka_mined_blocks);
    }

    pub fn bump_naka_proposed_blocks(&self) {
        Counters::inc(&self.naka_proposed_blocks);
    }

    pub fn bump_naka_rejected_blocks(&self) {
        Counters::inc(&self.naka_rejected_blocks);
    }

    pub fn bump_naka_signer_pushed_blocks(&self) {
        Counters::inc(&self.naka_signer_pushed_blocks);
    }

    pub fn bump_naka_mined_tenures(&self) {
        Counters::inc(&self.naka_mined_tenures);
    }

    pub fn bump_naka_miner_directives(&self) {
        Counters::inc(&self.naka_miner_directives);
    }

    pub fn set_microblocks_processed(&self, value: u64) {
        Counters::set(&self.microblocks_processed, value)
    }

    pub fn set_miner_current_rejections_timeout_secs(&self, value: u64) {
        Counters::set(&self.naka_miner_current_rejections_timeout_secs, value)
    }

    pub fn set_miner_current_rejections(&self, value: u32) {
        Counters::set(&self.naka_miner_current_rejections, u64::from(value))
    }
}

#[cfg(test)]
mod tests {
    use stacks::chainstate::burn::ConsensusHash;

    use super::Counters;

    #[test]
    fn parent_tenure_counter_preserves_unset_state() {
        let counters = Counters::new();
        assert!(counters
            .naka_submitted_commit_last_parent_tenure_id
            .get_opt()
            .is_none());

        let parent_tenure_id = ConsensusHash([1; 20]);
        counters.bump_naka_submitted_commits(1, 2, 3, &parent_tenure_id);

        assert_eq!(
            counters
                .naka_submitted_commit_last_parent_tenure_id
                .get_opt(),
            Some(parent_tenure_id)
        );
    }
}
