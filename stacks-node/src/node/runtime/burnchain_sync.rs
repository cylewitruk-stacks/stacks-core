// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use std::mem;
use std::ops::RangeInclusive;

use stacks::burnchains::Burnchain;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::operations::LeaderKeyRegisterOp;
use stacks::chainstate::burn::BlockSnapshot;
use stacks::monitoring::update_active_miners_count_gauge;
use stacks_common::types::chainstate::SortitionId;

use crate::burnchains::BurnchainTip;
use crate::node::leader_key::save_activated_vrf_key;
use crate::node::runtime::Globals;
use crate::Config;

/// Tracks the shared progress invariants while a protocol driver synchronizes burnchain blocks.
///
/// The drivers retain ownership of IBD, polling, mining, error handling, and per-block policy. This
/// value object only keeps the cursor state whose meaning is identical in both protocol eras.
pub struct BurnchainSyncCursor {
    tip: BurnchainTip,
    burnchain_height: u64,
    processed_sortition_height: u64,
    last_announced_sortition_height: u64,
    mine_start: u64,
}

/// Facts established when the burnchain and Stacks chain have reached the configured mining tip.
pub struct MiningReadiness {
    sortition_height: u64,
    newly_announced: bool,
}

impl MiningReadiness {
    pub fn sortition_height(&self) -> u64 {
        self.sortition_height
    }

    pub fn newly_announced(&self) -> bool {
        self.newly_announced
    }
}

impl BurnchainSyncCursor {
    pub fn new(tip: BurnchainTip, aligned_height: u64, mine_start: u64) -> Self {
        Self {
            tip,
            burnchain_height: aligned_height,
            processed_sortition_height: aligned_height,
            last_announced_sortition_height: 0,
            mine_start,
        }
    }

    pub fn tip(&self) -> &BurnchainTip {
        &self.tip
    }

    pub fn tip_height(&self) -> u64 {
        self.tip.block_snapshot.block_height
    }

    pub fn burnchain_height(&self) -> u64 {
        self.burnchain_height
    }

    pub fn processed_sortition_height(&self) -> u64 {
        self.processed_sortition_height
    }

    pub fn record_synced_tip(&mut self, tip: BurnchainTip, burnchain_height: u64) {
        self.tip = tip;
        self.burnchain_height = burnchain_height;
    }

    pub fn pending_sortition_heights(&self) -> RangeInclusive<u64> {
        (self.processed_sortition_height + 1)..=self.tip_height()
    }

    pub fn load_snapshot(&self, sortdb: &SortitionDB, block_height: u64) -> BlockSnapshot {
        let index = sortdb.index_conn();
        SortitionDB::get_ancestor_snapshot(
            &index,
            block_height,
            &self.tip.block_snapshot.sortition_id,
        )
        .unwrap()
        .expect("Failed to find block in fork processed by burnchain indexer")
    }

    pub fn mark_sortitions_processed(&mut self) {
        self.processed_sortition_height = self.tip_height();
    }

    pub fn is_caught_up(&self) -> bool {
        self.processed_sortition_height >= self.burnchain_height
    }

    fn sync_percent(&self, remote_chain_height: u64) -> f64 {
        if remote_chain_height > 0 {
            self.tip_height() as f64 / remote_chain_height as f64
        } else {
            0.0
        }
    }

    pub fn log_download_target(
        &self,
        burnchain: &Burnchain,
        target_burnchain_height: u64,
        remote_chain_height: u64,
    ) {
        let percent = self.sync_percent(remote_chain_height);
        debug!(
            "Runloop: Download burnchain blocks up to reward cycle #{} (height {target_burnchain_height})",
            burnchain
                .block_height_to_reward_cycle(target_burnchain_height)
                .expect("FATAL: target burnchain block height does not have a reward cycle");
            "total_burn_sync_percent" => %percent,
            "local_burn_height" => self.tip_height(),
            "remote_tip_height" => remote_chain_height
        );
    }

    pub fn log_synced_tip(&self, target_burnchain_height: u64, remote_chain_height: u64) {
        if !self.tip_needs_announcement() {
            return;
        }

        let burnchain_height = self.burnchain_height();
        let next_sortition_height = self.tip_height();
        let sortition_db_height = self.processed_sortition_height();
        info!(
            "Runloop: Downloaded burnchain blocks up to height {burnchain_height}; target height is {target_burnchain_height}; remote_chain_height = {remote_chain_height} next_sortition_height = {next_sortition_height}, sortition_db_height = {sortition_db_height}"
        );
    }

    pub fn mining_readiness(
        &mut self,
        sortdb: &SortitionDB,
        ibd: bool,
        is_miner: bool,
    ) -> Option<MiningReadiness> {
        if !self.is_caught_up() || ibd {
            return None;
        }

        let canonical_stacks_tip_height = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
            .map(|snapshot| snapshot.canonical_stacks_tip_height)
            .unwrap_or(0);
        self.evaluate_mining_readiness(canonical_stacks_tip_height, is_miner)
    }

    fn evaluate_mining_readiness(
        &mut self,
        canonical_stacks_tip_height: u64,
        is_miner: bool,
    ) -> Option<MiningReadiness> {
        if canonical_stacks_tip_height < self.mine_start {
            info!(
                "Runloop: Synchronized full burnchain, but stacks tip height is {canonical_stacks_tip_height}, and we are trying to boot to {}, not mining until reaching chain tip",
                self.mine_start
            );
            return None;
        }

        // Once the node has synchronized to the requested Stacks tip, do not apply the threshold
        // again. This avoids re-entering boot gating after a PoX fork.
        self.mine_start = 0;
        let sortition_height = self.processed_sortition_height();
        let newly_announced = self.tip_needs_announcement();
        if newly_announced {
            if is_miner {
                info!(
                    "Runloop: Synchronized full burnchain up to height {sortition_height}. Proceeding to mine blocks"
                );
            } else {
                info!("Runloop: Synchronized full burnchain up to height {sortition_height}.");
            }
            self.mark_tip_announced();
        }

        Some(MiningReadiness {
            sortition_height,
            newly_announced,
        })
    }

    fn tip_needs_announcement(&self) -> bool {
        self.tip_height() != self.last_announced_sortition_height
    }

    fn mark_tip_announced(&mut self) {
        self.last_announced_sortition_height = self.tip_height();
    }
}

#[cfg(test)]
mod burnchain_sync_cursor_tests {
    use std::time::Instant;

    use stacks::burnchains::BurnchainStateTransitionOps;
    use stacks_common::types::chainstate::BurnchainHeaderHash;

    use super::{BlockSnapshot, BurnchainSyncCursor, BurnchainTip};

    fn tip(block_height: u64) -> BurnchainTip {
        BurnchainTip {
            block_snapshot: BlockSnapshot::initial(block_height, &BurnchainHeaderHash::zero(), 0),
            state_transition: BurnchainStateTransitionOps::noop(),
            received_at: Instant::now(),
        }
    }

    #[test]
    fn tracks_pending_sortitions_and_tip_announcements_independently() {
        let mut cursor = BurnchainSyncCursor::new(tip(8), 8, 0);

        assert!(cursor.is_caught_up());
        assert!(cursor.pending_sortition_heights().is_empty());

        cursor.record_synced_tip(tip(10), 10);

        assert_eq!(
            cursor.pending_sortition_heights().collect::<Vec<_>>(),
            vec![9, 10]
        );
        assert!(!cursor.is_caught_up());
        assert!(cursor.tip_needs_announcement());
        assert_eq!(cursor.sync_percent(20), 0.5);

        cursor.mark_sortitions_processed();
        assert!(cursor.is_caught_up());
        assert!(cursor.pending_sortition_heights().is_empty());

        cursor.mark_tip_announced();
        assert!(!cursor.tip_needs_announcement());

        cursor.record_synced_tip(tip(12), 12);
        assert_eq!(
            cursor.pending_sortition_heights().collect::<Vec<_>>(),
            vec![11, 12]
        );
        assert!(!cursor.is_caught_up());
        assert!(cursor.tip_needs_announcement());
    }

    #[test]
    fn reports_zero_progress_without_a_remote_tip() {
        let cursor = BurnchainSyncCursor::new(tip(0), 0, 0);
        assert_eq!(cursor.sync_percent(0), 0.0);
    }

    #[test]
    fn clears_mine_start_once_and_announces_each_tip_once() {
        let mut cursor = BurnchainSyncCursor::new(tip(8), 8, 5);

        assert!(cursor.evaluate_mining_readiness(4, true).is_none());
        assert!(cursor.tip_needs_announcement());

        let readiness = cursor.evaluate_mining_readiness(5, true).unwrap();
        assert_eq!(readiness.sortition_height(), 8);
        assert!(readiness.newly_announced());
        assert!(!cursor.tip_needs_announcement());

        // The cleared threshold remains cleared even if the canonical Stacks tip later drops.
        let readiness = cursor.evaluate_mining_readiness(0, true).unwrap();
        assert_eq!(readiness.sortition_height(), 8);
        assert!(!readiness.newly_announced());

        cursor.record_synced_tip(tip(9), 9);
        cursor.mark_sortitions_processed();
        let readiness = cursor.evaluate_mining_readiness(0, false).unwrap();
        assert_eq!(readiness.sortition_height(), 9);
        assert!(readiness.newly_announced());
    }
}

/// Era-neutral facts loaded while processing a burn block.
pub struct BurnBlockObservation {
    snapshot: BlockSnapshot,
    winning_commit_vtxindex: Option<u32>,
    key_registers: Vec<LeaderKeyRegisterOp>,
    block_commit_count: usize,
}

impl BurnBlockObservation {
    pub fn load(sortdb: &SortitionDB, sortition_id: &SortitionId, is_miner: bool) -> Self {
        let index = sortdb.index_conn();
        let snapshot = SortitionDB::get_block_snapshot(&index, sortition_id)
            .expect("Failed to obtain block snapshot for processed burn block")
            .expect("Processed burn block snapshot is missing");
        let block_commits = SortitionDB::get_block_commits_by_block(&index, &snapshot.sortition_id)
            .expect("Unexpected SortitionDB error fetching block commits");
        update_active_miners_count_gauge(block_commits.len() as i64);

        let mut winning_commit_vtxindex = None;
        for operation in &block_commits {
            if operation.txid == snapshot.winning_block_txid {
                info!(
                    "Received burnchain block #{} including block_commit_op (winning) - {} ({})",
                    snapshot.block_height, operation.apparent_sender, operation.block_header_hash
                );
                winning_commit_vtxindex = Some(operation.vtxindex);
            } else if is_miner {
                info!(
                    "Received burnchain block #{} including block_commit_op - {} ({})",
                    snapshot.block_height, operation.apparent_sender, operation.block_header_hash
                );
            }
        }

        let key_registers = SortitionDB::get_leader_keys_by_block(&index, &snapshot.sortition_id)
            .expect("Unexpected SortitionDB error fetching key registers");

        Self {
            snapshot,
            winning_commit_vtxindex,
            key_registers,
            block_commit_count: block_commits.len(),
        }
    }

    pub fn snapshot(&self) -> &BlockSnapshot {
        &self.snapshot
    }

    pub fn winning_snapshot(&self) -> Option<BlockSnapshot> {
        self.winning_commit_vtxindex.map(|_| self.snapshot.clone())
    }

    pub fn log_processed(&self, ibd: bool) {
        debug!(
            "Processed burnchain state";
            "burn_height" => self.snapshot.block_height,
            "leader_keys_count" => self.key_registers.len(),
            "block_commits_count" => self.block_commit_count,
            "in_initial_block_download?" => ibd,
        );
    }

    pub fn activate_leader_key<T>(&mut self, globals: &Globals<T>, config: &Config) {
        let activated_key = globals.try_activate_leader_key_registration(
            self.snapshot.block_height,
            mem::take(&mut self.key_registers),
        );
        if let (Some(key), Some(path)) = (
            activated_key,
            config.miner.activated_vrf_key_path.as_deref(),
        ) {
            save_activated_vrf_key(path, &key);
        }
    }

    pub fn into_snapshot(self) -> BlockSnapshot {
        self.snapshot
    }
}
