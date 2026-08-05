// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Network-download progress used to decide when mining may resume.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PassProgress {
    completed: u64,
    required: u64,
}

impl PassProgress {
    fn require_pass_after(&mut self, completed: u64) {
        self.required = completed + 1;
    }

    fn record_completed(&mut self, completed: u64) {
        self.completed = completed;
    }

    fn requirement_satisfied(self) -> bool {
        self.required <= self.completed
    }
}

/// Tracks the network observation that gates mining after a burnchain advance.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DownloadReadiness {
    burn_height: u64,
    burn_height_observed_at_ms: u128,
    downloads: PassProgress,
}

impl DownloadReadiness {
    /// Observe the P2P network's current burn height.
    ///
    /// Returns `true` when the height advanced and a subsequent network pass is
    /// therefore required before mining is considered ready.
    pub fn observe_burn_height(
        &mut self,
        burn_height: u64,
        download_passes: u64,
        now_ms: u128,
    ) -> bool {
        if self.burn_height == burn_height {
            return false;
        }

        self.burn_height = burn_height;
        self.burn_height_observed_at_ms = now_ms;
        self.downloads.require_pass_after(download_passes);
        true
    }

    /// Record the latest completed network passes.
    pub fn record_completed_passes(&mut self, download_passes: u64) {
        self.downloads.record_completed(download_passes);
    }

    /// Determine whether the current downloader-only mining gate is open.
    ///
    /// Inventory progress is intentionally not consulted. Both protocol
    /// implementations have behaved this way since the historical duplicated
    /// downloader condition was removed. Changing that policy requires a
    /// separate semantic review.
    pub fn permits_mining(
        self,
        wait_for_block_download: bool,
        wait_time_for_blocks_ms: u64,
        now_ms: u128,
    ) -> bool {
        self.downloads.requirement_satisfied()
            || self.burn_height_observed_at_ms + u128::from(wait_time_for_blocks_ms) < now_ms
            || !wait_for_block_download
    }

    pub fn burn_height(self) -> u64 {
        self.burn_height
    }

    pub fn diagnostic_status(
        self,
        wait_for_block_download: bool,
        wait_time_for_blocks_ms: u64,
        now_ms: u128,
    ) -> String {
        format!(
            "{} <= {} || {} + {} < {} || {}",
            self.downloads.required,
            self.downloads.completed,
            self.burn_height_observed_at_ms,
            wait_time_for_blocks_ms,
            now_ms,
            wait_for_block_download
        )
    }
}

#[cfg(test)]
mod tests {
    use super::DownloadReadiness;

    #[test]
    fn unchanged_burn_height_does_not_change_requirements() {
        let mut readiness = DownloadReadiness::default();
        assert!(!readiness.observe_burn_height(0, 4, 10));
        assert!(readiness.permits_mining(true, 5_000, 10));
    }

    #[test]
    fn burn_height_advance_requires_the_next_download_pass() {
        let mut readiness = DownloadReadiness::default();
        assert!(readiness.observe_burn_height(100, 4, 10));
        readiness.record_completed_passes(4);
        assert!(!readiness.permits_mining(true, 5_000, 10));

        readiness.record_completed_passes(5);
        assert!(readiness.permits_mining(true, 5_000, 10));
    }

    #[test]
    fn timeout_or_disabled_wait_allows_mining() {
        let mut readiness = DownloadReadiness::default();
        readiness.observe_burn_height(100, 4, 10);

        assert!(!readiness.permits_mining(true, 5_000, 5_010));
        assert!(readiness.permits_mining(true, 5_000, 5_011));
        assert!(readiness.permits_mining(false, 5_000, 10));
    }
}
