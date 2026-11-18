// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use serde::{Deserialize, Serialize};

/// The domain separator shared by every protocol in one Stacks network.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct NetworkScope {
    chain_id: u32,
    network_id: u32,
}

impl NetworkScope {
    pub const fn new(chain_id: u32, network_id: u32) -> Self {
        Self {
            chain_id,
            network_id,
        }
    }

    pub const fn chain_id(self) -> u32 {
        self.chain_id
    }

    pub const fn network_id(self) -> u32 {
        self.network_id
    }
}

/// Current and optional next reward cycle retained during a transition.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct RewardCycleWindow {
    current: u64,
    next: Option<u64>,
}

impl RewardCycleWindow {
    pub const fn current_only(current: u64) -> Self {
        Self {
            current,
            next: None,
        }
    }

    pub fn new(current: u64, next: Option<u64>) -> Result<Self, RewardCycleWindowError> {
        if next.is_some_and(|next| next != current.saturating_add(1)) {
            return Err(RewardCycleWindowError { current, next });
        }
        Ok(Self { current, next })
    }

    /// Retain a current cycle and its successor. At the integer boundary there
    /// is no representable successor, so the window safely becomes current-only.
    pub const fn current_and_next(current: u64) -> Self {
        Self {
            current,
            next: current.checked_add(1),
        }
    }

    /// Retain the preceding cycle and `current` during the mod-zero handoff.
    /// Cycle zero has no predecessor and therefore uses the normal overlap.
    pub const fn previous_and_current(current: u64) -> Self {
        match current.checked_sub(1) {
            Some(previous) => Self {
                current: previous,
                next: Some(current),
            },
            None => Self::current_and_next(current),
        }
    }

    pub const fn current(self) -> u64 {
        self.current
    }

    pub const fn next(self) -> Option<u64> {
        self.next
    }

    pub fn contains(self, cycle: u64) -> bool {
        cycle == self.current || self.next == Some(cycle)
    }

    pub fn iter(self) -> impl Iterator<Item = u64> {
        std::iter::once(self.current).chain(self.next)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("reward-cycle window next value {next:?} must immediately follow current cycle {current}")]
pub struct RewardCycleWindowError {
    pub current: u64,
    pub next: Option<u64>,
}

/// Independently clamped PoX and tenure synchronization horizons.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncHorizons {
    pub pox_through_cycle: u64,
    pub tenure_through_cycle: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reward_cycle_window_is_ordered_and_exact() {
        let window = RewardCycleWindow::new(9, Some(10)).unwrap();
        assert_eq!(window.iter().collect::<Vec<_>>(), vec![9, 10]);
        assert!(window.contains(9));
        assert!(window.contains(10));
        assert!(!window.contains(11));
        assert!(RewardCycleWindow::new(9, Some(11)).is_err());
        assert_eq!(
            RewardCycleWindow::current_and_next(u64::MAX),
            RewardCycleWindow::current_only(u64::MAX)
        );
        assert_eq!(
            RewardCycleWindow::previous_and_current(9),
            RewardCycleWindow::new(8, Some(9)).unwrap()
        );
    }

    #[test]
    fn network_scope_keeps_ids_named() {
        let scope = NetworkScope::new(1, 2);
        assert_eq!(scope.chain_id(), 1);
        assert_eq!(scope.network_id(), 2);
    }
}
