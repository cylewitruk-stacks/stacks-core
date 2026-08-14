// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Immutable, transport-neutral progression for a Nakamoto tip sync.

/// Bounds chosen from one authenticated status response. They are stored once
/// and copied unchanged through every stage transition.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SyncPlanBounds {
    pox_end_cycle: u64,
    epoch2_start: u64,
    epoch2_end: u64,
    first_nakamoto_cycle: u64,
    current_reward_cycle: u64,
}

impl SyncPlanBounds {
    pub fn new(
        pox_end_cycle: u64,
        epoch2_start: u64,
        epoch2_end: u64,
        first_nakamoto_cycle: u64,
        current_reward_cycle: u64,
    ) -> Result<Self, SyncPlanError> {
        if epoch2_start > epoch2_end {
            return Err(SyncPlanError::InvalidBounds("epoch-2 start exceeds end"));
        }
        Ok(Self {
            pox_end_cycle,
            epoch2_start,
            epoch2_end,
            first_nakamoto_cycle,
            current_reward_cycle,
        })
    }

    pub const fn pox_end_cycle(self) -> u64 {
        self.pox_end_cycle
    }

    pub const fn epoch2_start(self) -> u64 {
        self.epoch2_start
    }

    pub const fn epoch2_end(self) -> u64 {
        self.epoch2_end
    }

    pub const fn first_nakamoto_cycle(self) -> u64 {
        self.first_nakamoto_cycle
    }

    pub const fn current_reward_cycle(self) -> u64 {
        self.current_reward_cycle
    }
}

/// The only mutable part of a sync plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SyncStage {
    Status,
    Pox { cursor: u64 },
    Epoch2 { cursor: u64 },
    Tenure { reward_cycle: u64, cursor: u64 },
    Mempool { cursor: Vec<u8> },
    Attachments { cursor: Vec<u8> },
    Complete,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NakamotoSyncStep {
    bounds: SyncPlanBounds,
    stage: SyncStage,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SyncPlanError {
    InvalidBounds(&'static str),
    NonAdvancingCursor,
    WrongStage(&'static str),
}

impl std::fmt::Display for SyncPlanError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBounds(reason) => write!(formatter, "invalid sync-plan bounds: {reason}"),
            Self::NonAdvancingCursor => formatter.write_str("page cursor did not advance"),
            Self::WrongStage(stage) => {
                write!(formatter, "page response does not match sync stage {stage}")
            }
        }
    }
}

impl std::error::Error for SyncPlanError {}

impl NakamotoSyncStep {
    pub const fn status() -> Self {
        Self {
            bounds: SyncPlanBounds {
                pox_end_cycle: 0,
                epoch2_start: 0,
                epoch2_end: 0,
                first_nakamoto_cycle: 0,
                current_reward_cycle: 0,
            },
            stage: SyncStage::Status,
        }
    }

    pub const fn mempool() -> Self {
        Self {
            bounds: SyncPlanBounds {
                pox_end_cycle: 0,
                epoch2_start: 0,
                epoch2_end: 0,
                first_nakamoto_cycle: 0,
                current_reward_cycle: 0,
            },
            stage: SyncStage::Mempool { cursor: Vec::new() },
        }
    }

    pub fn after_status(
        pox_end_cycle: u64,
        epoch2_start: u64,
        epoch2_end: u64,
        first_nakamoto_cycle: u64,
        current_reward_cycle: u64,
    ) -> Result<Self, SyncPlanError> {
        let bounds = SyncPlanBounds::new(
            pox_end_cycle,
            epoch2_start,
            epoch2_end,
            first_nakamoto_cycle,
            current_reward_cycle,
        )?;
        let stage = if pox_end_cycle > 0 {
            SyncStage::Pox { cursor: 0 }
        } else {
            Self::stage_after_pox(bounds)
        };
        Ok(Self { bounds, stage })
    }

    pub const fn bounds(&self) -> SyncPlanBounds {
        self.bounds
    }

    pub const fn stage(&self) -> &SyncStage {
        &self.stage
    }

    fn stage_after_pox(bounds: SyncPlanBounds) -> SyncStage {
        if bounds.epoch2_start < bounds.epoch2_end {
            SyncStage::Epoch2 {
                cursor: bounds.epoch2_start,
            }
        } else {
            Self::first_tenure(bounds)
        }
    }

    fn first_tenure(bounds: SyncPlanBounds) -> SyncStage {
        if bounds.first_nakamoto_cycle <= bounds.current_reward_cycle {
            SyncStage::Tenure {
                reward_cycle: bounds.first_nakamoto_cycle,
                cursor: 0,
            }
        } else {
            SyncStage::Mempool { cursor: Vec::new() }
        }
    }

    pub fn advance_inventory(
        &self,
        next_cursor: u64,
        complete: bool,
    ) -> Result<Self, SyncPlanError> {
        let stage = match self.stage {
            SyncStage::Pox { cursor } => {
                if next_cursor <= cursor && next_cursor < self.bounds.pox_end_cycle {
                    return Err(SyncPlanError::NonAdvancingCursor);
                }
                if next_cursor < self.bounds.pox_end_cycle {
                    SyncStage::Pox {
                        cursor: next_cursor,
                    }
                } else {
                    Self::stage_after_pox(self.bounds)
                }
            }
            SyncStage::Epoch2 { cursor } => {
                if next_cursor <= cursor && next_cursor < self.bounds.epoch2_end {
                    return Err(SyncPlanError::NonAdvancingCursor);
                }
                if next_cursor < self.bounds.epoch2_end {
                    SyncStage::Epoch2 {
                        cursor: next_cursor,
                    }
                } else {
                    Self::first_tenure(self.bounds)
                }
            }
            SyncStage::Tenure {
                reward_cycle,
                cursor,
            } => {
                if !complete && next_cursor <= cursor {
                    return Err(SyncPlanError::NonAdvancingCursor);
                }
                if !complete {
                    SyncStage::Tenure {
                        reward_cycle,
                        cursor: next_cursor,
                    }
                } else if reward_cycle < self.bounds.current_reward_cycle {
                    SyncStage::Tenure {
                        reward_cycle: reward_cycle.saturating_add(1),
                        cursor: 0,
                    }
                } else {
                    SyncStage::Mempool { cursor: Vec::new() }
                }
            }
            _ => return Err(SyncPlanError::WrongStage("inventory")),
        };
        Ok(Self {
            bounds: self.bounds,
            stage,
        })
    }

    pub fn advance_mempool(
        &self,
        next_cursor: Vec<u8>,
        complete: bool,
    ) -> Result<Self, SyncPlanError> {
        let SyncStage::Mempool { cursor } = &self.stage else {
            return Err(SyncPlanError::WrongStage("mempool"));
        };
        if !complete && next_cursor <= *cursor {
            return Err(SyncPlanError::NonAdvancingCursor);
        }
        Ok(Self {
            bounds: self.bounds,
            stage: if complete {
                SyncStage::Attachments { cursor: Vec::new() }
            } else {
                SyncStage::Mempool {
                    cursor: next_cursor,
                }
            },
        })
    }

    pub fn advance_attachments(
        &self,
        next_cursor: Vec<u8>,
        complete: bool,
    ) -> Result<Self, SyncPlanError> {
        let SyncStage::Attachments { cursor } = &self.stage else {
            return Err(SyncPlanError::WrongStage("attachments"));
        };
        if !complete && next_cursor <= *cursor {
            return Err(SyncPlanError::NonAdvancingCursor);
        }
        Ok(Self {
            bounds: self.bounds,
            stage: if complete {
                SyncStage::Complete
            } else {
                SyncStage::Attachments {
                    cursor: next_cursor,
                }
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn immutable_bounds_cross_every_stage() {
        let plan = NakamotoSyncStep::after_status(2, 10, 12, 3, 4).unwrap();
        let bounds = plan.bounds();
        assert_eq!(plan.stage(), &SyncStage::Pox { cursor: 0 });
        let plan = plan.advance_inventory(1, true).unwrap();
        let plan = plan.advance_inventory(2, true).unwrap();
        assert_eq!(plan.stage(), &SyncStage::Epoch2 { cursor: 10 });
        let plan = plan.advance_inventory(11, true).unwrap();
        let plan = plan.advance_inventory(12, true).unwrap();
        assert_eq!(
            plan.stage(),
            &SyncStage::Tenure {
                reward_cycle: 3,
                cursor: 0,
            }
        );
        let plan = plan.advance_inventory(8, true).unwrap();
        let plan = plan.advance_inventory(9, true).unwrap();
        let plan = plan.advance_mempool(vec![1], false).unwrap();
        let plan = plan.advance_mempool(vec![2], true).unwrap();
        let plan = plan.advance_attachments(vec![3], true).unwrap();
        assert_eq!(plan.stage(), &SyncStage::Complete);
        assert_eq!(plan.bounds(), bounds);
    }

    #[test]
    fn invalid_bounds_and_nonadvancing_pages_fail_closed() {
        assert!(SyncPlanBounds::new(0, 12, 10, 3, 4).is_err());
        let plan = NakamotoSyncStep::after_status(2, 0, 0, 0, 0).unwrap();
        assert_eq!(
            plan.advance_inventory(0, false),
            Err(SyncPlanError::NonAdvancingCursor)
        );
        let mempool = NakamotoSyncStep::mempool();
        assert_eq!(
            mempool.advance_mempool(Vec::new(), false),
            Err(SyncPlanError::NonAdvancingCursor)
        );
    }
}
