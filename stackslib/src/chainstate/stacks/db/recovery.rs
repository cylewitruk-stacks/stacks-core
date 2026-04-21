// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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

//! Chainstate recovery: detect cross-database inconsistency and rewind-replay.
//!
//! This module implements a composable consistency-check architecture for detecting
//! and recovering from corruption across the node's multiple databases (state-index
//! MARF, clarity MARF, sortition DB, etc.).
//!
//! The core abstraction is: **find the newest canonical block from which this binary
//! can replay safely.** The walker (`walk_to_last_consistent_block`) walks backward
//! from a tip, applying a set of `ConsistencyCheck` predicates at each block. When
//! inconsistency is found, the block is added to a rewind set. The rewind executor
//! (`execute_rewind`) deletes the affected chainstate data so blocks can be replayed.
//!
//! See `.docs/chainstate-recovery.md` for the full design document.

use rusqlite::{params, Connection, OptionalExtension};
use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::types::StacksEpochId;

use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::index::marf::MarfConnection;
use crate::chainstate::stacks::index::ClarityMarfTrieId;
use crate::chainstate::stacks::{Error, StacksBlockHeader};
use crate::core::EpochList;
use crate::util_lib::db::{DBTx, Error as db_error};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Result of checking a single block's consistency.
#[derive(Debug)]
pub enum BlockConsistency {
    /// Block is fully consistent — safe to replay from here.
    Consistent,
    /// Block needs rewind. Contains the reason and the parent block ID
    /// (to continue walking without a redundant query).
    NeedsRewind {
        reason: RecoveryReason,
        parent_block_id: StacksBlockId,
    },
    /// Block doesn't exist in chainstate headers (sortition ahead of chainstate).
    /// Not an error — the walker will try staging_blocks parent links to continue.
    NotInChainstate,
}

/// Diagnostic information about why a block is inconsistent.
#[derive(Debug)]
pub enum RecoveryReason {
    /// Block committed to state-index headers but missing from the clarity MARF.
    MissingClarityMarf,
    /// Block committed to clarity MARF but missing from the state-index MARF.
    /// During rewind, the clarity MARF is also cleaned via `MARF::drop_block()`
    /// so that `begin()` can recreate the block on replay.
    MissingStateIndex,
    /// Block was evaluated under a different epoch than the binary's epoch table
    /// expects for that burn block height.
    EpochMismatch {
        expected: StacksEpochId,
        found: StacksEpochId,
    },
}

/// Result of walking backward to find the last consistent block.
#[derive(Debug)]
pub enum WalkResult {
    /// Found a verified-consistent block. `rewind_set` may be empty (tip itself
    /// was consistent) or non-empty (blocks between the tip and `last_good` need
    /// rewind).
    Consistent {
        last_good: StacksBlockId,
        rewind_set: Vec<StacksBlockId>,
    },
    /// The walk ran out of parent links before reaching a verified-consistent
    /// block. The canonical tip cannot be connected to committed chainstate.
    Disconnected {
        stopped_at: StacksBlockId,
        rewind_set: Vec<StacksBlockId>,
    },
}

/// Read-only SQL handles for consistency checks.
///
/// Constructed inside `ClarityInstance::with_marf()` where both `&Connection`
/// lifetimes are valid. `chainstate_conn` is the state-index database (contains
/// `block_headers`, `nakamoto_block_headers`, `staging_blocks`, and the state-index
/// `marf_data` table). `clarity_marf_conn` is the clarity MARF database (contains
/// the clarity `marf_data` table).
pub struct CheckContext<'a> {
    pub chainstate_conn: &'a Connection,
    pub clarity_marf_conn: &'a Connection,
}

// ---------------------------------------------------------------------------
// Consistency check trait + Tier 1 implementation
// ---------------------------------------------------------------------------

/// A composable consistency predicate. Implementations check one class of
/// invariant. Checks receive read-only SQL handles via `CheckContext`.
pub trait ConsistencyCheck {
    fn check_block(
        &self,
        ctx: &CheckContext,
        block_id: &StacksBlockId,
    ) -> Result<BlockConsistency, Error>;
}

/// Tier 1 check: verify that the block exists in both MARFs and in chainstate
/// headers, with a valid parent link.
pub struct MarfExistenceCheck;

impl ConsistencyCheck for MarfExistenceCheck {
    fn check_block(
        &self,
        ctx: &CheckContext,
        block_id: &StacksBlockId,
    ) -> Result<BlockConsistency, Error> {
        // Step 1: Is the block in chainstate headers? Get parent_block_id.
        let parent_opt: Option<StacksBlockId> = ctx
            .chainstate_conn
            .query_row(
                "SELECT parent_block_id FROM block_headers WHERE index_block_hash = ?1",
                params![block_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        let parent_opt = match parent_opt {
            Some(p) => Some(p),
            None => {
                // Try nakamoto_block_headers
                ctx.chainstate_conn
                    .query_row(
                        "SELECT parent_block_id FROM nakamoto_block_headers \
                         WHERE index_block_hash = ?1",
                        params![block_id],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(|e| Error::DBError(db_error::SqliteError(e)))?
            }
        };

        let parent_block_id = match parent_opt {
            Some(p) => p,
            None => return Ok(BlockConsistency::NotInChainstate),
        };

        // Step 2: Is the block in the clarity MARF's marf_data?
        let clarity_has_block: bool = ctx
            .clarity_marf_conn
            .query_row(
                "SELECT 1 FROM marf_data WHERE block_hash = ?1 AND unconfirmed = 0",
                params![block_id],
                |_| Ok(true),
            )
            .optional()
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?
            .unwrap_or(false);

        if !clarity_has_block {
            return Ok(BlockConsistency::NeedsRewind {
                reason: RecoveryReason::MissingClarityMarf,
                parent_block_id,
            });
        }

        // Step 3: Is the block in the state-index MARF's marf_data?
        // (chainstate_conn is the state-index DB, which also contains marf_data)
        let state_index_has_block: bool = ctx
            .chainstate_conn
            .query_row(
                "SELECT 1 FROM marf_data WHERE block_hash = ?1 AND unconfirmed = 0",
                params![block_id],
                |_| Ok(true),
            )
            .optional()
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?
            .unwrap_or(false);

        if !state_index_has_block {
            return Ok(BlockConsistency::NeedsRewind {
                reason: RecoveryReason::MissingStateIndex,
                parent_block_id,
            });
        }

        // All checks passed.
        Ok(BlockConsistency::Consistent)
    }
}

/// Tier 2 check: verify that the block's stored `evaluated_epoch` matches the
/// epoch the binary expects for the block's burn height.
///
/// Blocks committed by older binaries (before the `evaluated_epoch` column was
/// added) have `NULL` and are unconditionally treated as `Consistent`
/// (grandfathered). This means Tier 2 only protects blocks committed after the
/// schema migration that added the column.
pub struct EpochConsistencyCheck {
    epochs: EpochList,
}

impl EpochConsistencyCheck {
    pub fn new(sortdb_conn: &Connection) -> Result<Self, Error> {
        let epochs = SortitionDB::get_stacks_epochs(sortdb_conn).map_err(|e| Error::DBError(e))?;
        Ok(Self { epochs })
    }

    #[cfg(test)]
    pub fn from_epochs(epochs: EpochList) -> Self {
        Self { epochs }
    }
}

impl ConsistencyCheck for EpochConsistencyCheck {
    fn check_block(
        &self,
        ctx: &CheckContext,
        block_id: &StacksBlockId,
    ) -> Result<BlockConsistency, Error> {
        // Try block_headers first, then nakamoto_block_headers.
        // We need burn_header_height, evaluated_epoch, and parent_block_id.
        let row_opt: Option<(u64, Option<u32>, StacksBlockId)> = ctx
            .chainstate_conn
            .query_row(
                "SELECT burn_header_height, evaluated_epoch, parent_block_id \
                 FROM block_headers WHERE index_block_hash = ?1",
                params![block_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)? as u64,
                        row.get::<_, Option<u32>>(1)?,
                        row.get(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        let row = match row_opt {
            Some(r) => r,
            None => {
                // Try nakamoto_block_headers
                match ctx
                    .chainstate_conn
                    .query_row(
                        "SELECT burn_header_height, evaluated_epoch, parent_block_id \
                         FROM nakamoto_block_headers WHERE index_block_hash = ?1",
                        params![block_id],
                        |row| {
                            Ok((
                                row.get::<_, i64>(0)? as u64,
                                row.get::<_, Option<u32>>(1)?,
                                row.get(2)?,
                            ))
                        },
                    )
                    .optional()
                    .map_err(|e| Error::DBError(db_error::SqliteError(e)))?
                {
                    Some(r) => r,
                    None => return Ok(BlockConsistency::NotInChainstate),
                }
            }
        };

        let (burn_height, evaluated_epoch_opt, parent_block_id) = row;

        // NULL evaluated_epoch -> grandfathered (committed by older binary).
        let stored_epoch_int = match evaluated_epoch_opt {
            Some(v) => v,
            None => return Ok(BlockConsistency::Consistent),
        };

        let stored_epoch = match StacksEpochId::try_from(stored_epoch_int) {
            Ok(e) => e,
            Err(_) => {
                warn!(
                    "Epoch consistency: block {block_id} has invalid evaluated_epoch \
                     value {stored_epoch_int}. Treating as consistent (cannot validate)."
                );
                return Ok(BlockConsistency::Consistent);
            }
        };

        let expected_epoch = match self.epochs.epoch_id_at_height(burn_height) {
            Some(e) => e,
            None => {
                warn!(
                    "Epoch consistency: no epoch defined for burn height {burn_height} \
                     (block {block_id}). Treating as consistent."
                );
                return Ok(BlockConsistency::Consistent);
            }
        };

        if stored_epoch != expected_epoch {
            return Ok(BlockConsistency::NeedsRewind {
                reason: RecoveryReason::EpochMismatch {
                    expected: expected_epoch,
                    found: stored_epoch,
                },
                parent_block_id,
            });
        }

        Ok(BlockConsistency::Consistent)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve the canonical stacks chain tip from the sortition DB.
fn canonical_stacks_tip(sortdb_conn: &Connection) -> Result<StacksBlockId, Error> {
    let (consensus_hash, block_hash) =
        SortitionDB::get_canonical_stacks_chain_tip_hash(sortdb_conn)
            .map_err(|e| Error::DBError(e))?;
    Ok(StacksBlockHeader::make_index_block_hash(
        &consensus_hash,
        &block_hash,
    ))
}

/// Check whether a block that is still `processed = 0` in the staging DB
/// has committed residue in the chainstate or clarity databases.
///
/// Residue means at least one of:
/// - A `nakamoto_block_headers` row (inserted by `advance_tip`)
/// - A state-index `marf_data` row (inserted by the state-index MARF)
/// - A clarity `marf_data` row (inserted by the clarity MARF)
///
/// Any of these indicate the block was partially committed before a crash.
fn has_committed_residue(
    chainstate_conn: &Connection,
    clarity_conn: &Connection,
    block_id: &StacksBlockId,
) -> Result<bool, Error> {
    // Check nakamoto_block_headers (may not exist on pre-Nakamoto chainstates).
    let has_header: bool = match chainstate_conn.query_row(
        "SELECT 1 FROM nakamoto_block_headers WHERE index_block_hash = ?1",
        params![block_id],
        |_| Ok(true),
    ) {
        Ok(_) => true,
        Err(rusqlite::Error::QueryReturnedNoRows) => false,
        Err(rusqlite::Error::SqliteFailure(err, _))
            if err.code == rusqlite::ErrorCode::Unknown && err.extended_code == 1 =>
        {
            // "no such table" — pre-Nakamoto chainstate; skip.
            false
        }
        Err(e) => return Err(Error::DBError(db_error::SqliteError(e))),
    };

    if has_header {
        return Ok(true);
    }

    // Check state-index marf_data.
    let has_state_index: bool = chainstate_conn
        .query_row(
            "SELECT 1 FROM marf_data WHERE block_hash = ?1 AND unconfirmed = 0",
            params![block_id],
            |_| Ok(true),
        )
        .optional()
        .map_err(|e| Error::DBError(db_error::SqliteError(e)))?
        .unwrap_or(false);

    if has_state_index {
        return Ok(true);
    }

    // Check clarity marf_data.
    let has_clarity: bool = clarity_conn
        .query_row(
            "SELECT 1 FROM marf_data WHERE block_hash = ?1 AND unconfirmed = 0",
            params![block_id],
            |_| Ok(true),
        )
        .optional()
        .map_err(|e| Error::DBError(db_error::SqliteError(e)))?
        .unwrap_or(false);

    Ok(has_clarity)
}

// ---------------------------------------------------------------------------
// Generic walker
// ---------------------------------------------------------------------------

/// Walk backward from `starting_tip`, applying `checks` at each block, until a
/// `Consistent` block is found, the sentinel is reached, or the walk runs out of
/// parent links.
///
/// Returns a [`WalkResult`] with `found_consistent = true` if the walk found a
/// verified-good block, or `false` if it stopped because it ran out of parent
/// links (the canonical tip couldn't be connected to committed chainstate).
///
/// For blocks that are `NotInChainstate` (sortition ahead of chainstate), the
/// walker follows `staging_blocks` parent links to continue. These blocks are NOT
/// added to the rewind set since there is nothing to clean up.
pub fn walk_to_last_consistent_block(
    ctx: &CheckContext,
    starting_tip: &StacksBlockId,
    checks: &[&dyn ConsistencyCheck],
) -> Result<WalkResult, Error> {
    let mut rewind_set = Vec::new();
    let mut cursor = starting_tip.clone();
    let sentinel = StacksBlockId::sentinel();

    loop {
        if cursor == sentinel {
            warn!(
                "Chainstate recovery: walked back to sentinel without finding a good block. \
                 Full replay from genesis required."
            );
            return Ok(WalkResult::Consistent {
                last_good: sentinel,
                rewind_set,
            });
        }

        // Run all consistency checks. Short-circuit on first non-Consistent result.
        let mut status = BlockConsistency::Consistent;
        for check in checks {
            let result = check.check_block(ctx, &cursor)?;
            match result {
                BlockConsistency::Consistent => continue,
                other => {
                    status = other;
                    break;
                }
            }
        }

        match status {
            BlockConsistency::Consistent => {
                info!(
                    "Chainstate recovery: found last good block {cursor} ({} blocks to rewind)",
                    rewind_set.len()
                );
                return Ok(WalkResult::Consistent {
                    last_good: cursor,
                    rewind_set,
                });
            }
            BlockConsistency::NeedsRewind {
                reason,
                parent_block_id,
            } => {
                debug!("Chainstate recovery: block {cursor} needs rewind ({reason:?})",);
                rewind_set.push(cursor.clone());
                cursor = parent_block_id;
            }
            BlockConsistency::NotInChainstate => {
                // Block not in any header table — sortition ahead of chainstate.
                // Don't add to rewind set, but try staging_blocks for parent link.
                warn!(
                    "Chainstate recovery: block {cursor} not in block_headers or \
                     nakamoto_block_headers (sortition ahead of chainstate). \
                     Trying staging_blocks for parent link.",
                );

                let staging_parent: Option<StacksBlockId> = ctx
                    .chainstate_conn
                    .query_row(
                        "SELECT p.index_block_hash FROM staging_blocks p \
                         JOIN staging_blocks c \
                           ON p.anchored_block_hash = c.parent_anchored_block_hash \
                          AND p.consensus_hash = c.parent_consensus_hash \
                         WHERE c.index_block_hash = ?1 \
                         LIMIT 1",
                        params![cursor],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

                match staging_parent {
                    Some(parent) => {
                        cursor = parent;
                    }
                    None => {
                        warn!(
                            "Chainstate recovery: block {cursor} has no parent link in any table. \
                             Stopping walk.",
                        );
                        return Ok(WalkResult::Disconnected {
                            stopped_at: cursor,
                            rewind_set,
                        });
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Rewind functions (moved verbatim from blocks.rs)
// ---------------------------------------------------------------------------

impl StacksChainState {
    /// Rewind a single epoch 2.x block by resetting its staging entry and deleting its chainstate
    /// header data. The block will be re-executed on the next coordinator pass.
    ///
    /// Tables cleaned (matching `advance_tip()` writes):
    /// - `block_headers`
    /// - `payments`
    /// - `burnchain_txids`
    /// - `epoch_transitions`
    /// - `matured_rewards` (both parent and child keys)
    /// - `nakamoto_reward_sets`
    pub fn rewind_epoch2x_block(
        chainstate_tx: &DBTx,
        block_id: &StacksBlockId,
    ) -> Result<(), Error> {
        // Reset the staging entry so the block can be reprocessed
        chainstate_tx
            .execute(
                "UPDATE staging_blocks SET processed = 0, attachable = 1, orphaned = 0, \
                 processed_time = 0 WHERE index_block_hash = ?1",
                params![block_id],
            )
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        // Delete from all tables written by advance_tip()
        chainstate_tx
            .execute(
                "DELETE FROM block_headers WHERE index_block_hash = ?1",
                params![block_id],
            )
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        chainstate_tx
            .execute(
                "DELETE FROM payments WHERE index_block_hash = ?1",
                params![block_id],
            )
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        chainstate_tx
            .execute(
                "DELETE FROM burnchain_txids WHERE index_block_hash = ?1",
                params![block_id],
            )
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        chainstate_tx
            .execute(
                "DELETE FROM epoch_transitions WHERE block_id = ?1",
                params![block_id],
            )
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        chainstate_tx
            .execute(
                "DELETE FROM matured_rewards WHERE child_index_block_hash = ?1 \
                 OR parent_index_block_hash = ?1",
                params![block_id],
            )
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        // nakamoto_reward_sets may have been written during epoch 2.x processing too.
        // Ignore "no such table" if Nakamoto tables haven't been created yet.
        match chainstate_tx.execute(
            "DELETE FROM nakamoto_reward_sets WHERE index_block_hash = ?1",
            params![block_id],
        ) {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::Unknown && err.extended_code == 1 => {}
            Err(e) => return Err(Error::DBError(db_error::SqliteError(e))),
        }

        // Delete the block from the header-index MARF (state_index). This is necessary so that
        // advance_tip() can recreate the block on replay — MARF::begin() will reject it with
        // ExistsError if the marf_data row is still present.
        chainstate_tx
            .execute(
                "DELETE FROM marf_data WHERE block_hash = ?1",
                params![block_id],
            )
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        chainstate_tx
            .execute(
                "DELETE FROM block_extension_locks WHERE block_hash = ?1",
                params![block_id],
            )
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        Ok(())
    }

    /// Rewind a single Nakamoto block by resetting its staging entry and deleting its
    /// chainstate header data. No-op if the Nakamoto tables don't exist (pre-Nakamoto
    /// chainstate) or the block doesn't exist in them.
    pub fn rewind_nakamoto_block(
        chainstate_tx: &DBTx,
        block_id: &StacksBlockId,
    ) -> Result<(), Error> {
        // Helper: execute SQL, ignoring "no such table" errors (expected for pre-Nakamoto
        // chainstates where Nakamoto tables haven't been created yet).
        let exec_ignore_missing_table = |sql: &str| -> Result<(), Error> {
            match chainstate_tx.execute(sql, params![block_id]) {
                Ok(_) => Ok(()),
                Err(rusqlite::Error::SqliteFailure(err, _))
                    if err.code == rusqlite::ErrorCode::Unknown && err.extended_code == 1 =>
                {
                    // "no such table" — Nakamoto tables not yet created; skip.
                    Ok(())
                }
                Err(e) => Err(Error::DBError(db_error::SqliteError(e))),
            }
        };

        // NOTE: nakamoto_staging_blocks lives in a SEPARATE SQLite file from the
        // state_index. It must be updated via chainstate.nakamoto_staging_blocks_conn,
        // not via this transaction. The caller (execute_rewind) handles that.
        exec_ignore_missing_table(
            "DELETE FROM nakamoto_block_headers WHERE index_block_hash = ?1",
        )?;
        exec_ignore_missing_table("DELETE FROM payments WHERE index_block_hash = ?1")?;
        exec_ignore_missing_table("DELETE FROM burnchain_txids WHERE index_block_hash = ?1")?;
        exec_ignore_missing_table("DELETE FROM epoch_transitions WHERE block_id = ?1")?;
        exec_ignore_missing_table(
            "DELETE FROM matured_rewards WHERE child_index_block_hash = ?1 \
             OR parent_index_block_hash = ?1",
        )?;
        exec_ignore_missing_table("DELETE FROM nakamoto_reward_sets WHERE index_block_hash = ?1")?;
        exec_ignore_missing_table("DELETE FROM nakamoto_tenure_events WHERE block_id = ?1")?;

        // Delete from the header-index MARF (state_index) so advance_tip() can recreate it.
        // marf_data and block_extension_locks are epoch-agnostic — same tables as epoch 2.x.
        exec_ignore_missing_table("DELETE FROM marf_data WHERE block_hash = ?1")?;
        exec_ignore_missing_table("DELETE FROM block_extension_locks WHERE block_hash = ?1")?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Rewind executor
    // -----------------------------------------------------------------------

    /// Execute the rewind phase: delete chainstate data for all blocks in the rewind
    /// set, commit the transaction, reset MARF runtime state, and reset
    /// nakamoto_staging_blocks entries (separate DB file).
    ///
    /// Idempotent — safe to re-run if interrupted mid-recovery.
    ///
    /// Phase ordering is designed for crash safety:
    /// 1. Clean the clarity MARF first (separate SQLite file).
    /// 2. Then commit the state-index transaction (headers + state-index marf_data).
    ///
    /// If the node crashes after Phase 1 but before Phase 2, the next startup
    /// sees blocks still in headers but missing from the clarity MARF →
    /// `MissingClarityMarf` → re-triggers the full rewind. Idempotent.
    fn execute_rewind(&mut self, rewind_set: &[StacksBlockId]) -> Result<(), Error> {
        if rewind_set.is_empty() {
            return Ok(());
        }

        // Phase 1: Clean rewound blocks from the clarity MARF. This runs BEFORE
        // the state-index commit so that a crash leaves blocks detectable as
        // MissingClarityMarf (headers still exist, clarity marf_data deleted).
        // Without this, MARF::begin() would reject replay with ExistsError.
        self.clarity_state.with_marf(|marf| -> Result<(), Error> {
            for block_id in rewind_set {
                marf.drop_block(block_id)?;
            }
            Ok(())
        })?;

        // Phase 2: Rewind state-index inside a chainstate transaction.
        let tx = self.db_tx_begin()?;
        for block_id in rewind_set {
            info!("Chainstate recovery: rewinding block {block_id}");
            Self::rewind_epoch2x_block(&tx, block_id)?;
            Self::rewind_nakamoto_block(&tx, block_id)?;
        }
        tx.commit()
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        // Phase 3: Reset in-memory MARF caches for both the state-index and
        // clarity MARFs so stale entries don't cause open_block() to succeed
        // for blocks whose marf_data rows were deleted.
        self.state_index.post_recovery_reset(rewind_set);
        self.clarity_state.with_marf(|marf| {
            marf.post_recovery_reset(rewind_set);
        });

        // Phase 4: Reset nakamoto_staging_blocks entries. This table lives in a
        // SEPARATE SQLite file from the state_index, so it must be updated via its
        // own connection. Suppress "no such table" (pre-Nakamoto chainstate).
        for block_id in rewind_set {
            match self.nakamoto_staging_blocks_conn.execute(
                "UPDATE nakamoto_staging_blocks SET processed = 0, orphaned = 0 \
                 WHERE index_block_hash = ?1",
                params![block_id],
            ) {
                Ok(_) => {}
                Err(rusqlite::Error::SqliteFailure(err, _))
                    if err.code == rusqlite::ErrorCode::Unknown && err.extended_code == 1 =>
                {
                    // "no such table" — pre-Nakamoto chainstate; skip.
                }
                Err(e) => return Err(Error::DBError(db_error::SqliteError(e))),
            }
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Half-committed block recovery
    // -----------------------------------------------------------------------

    /// Detect and rewind Nakamoto blocks that are stuck in a half-committed
    /// state: the MARF and/or header row were written, but the staging DB
    /// was never updated to `processed = 1` (crash between
    /// `chainstate_tx.commit()` and `infallible_set_block_processed()`).
    ///
    /// These blocks are invisible to the backward walk (which only visits
    /// committed headers reachable from the canonical sortition tip) but
    /// will cause `MARF::begin()` → `ExistsError` when the coordinator
    /// tries to re-process them.
    ///
    /// Returns the number of blocks cleaned up.
    fn recover_half_committed_blocks(&mut self) -> Result<usize, Error> {
        // Collect candidate block IDs from the staging DB: unprocessed,
        // non-orphaned Nakamoto blocks that might have residue.
        let candidates: Vec<StacksBlockId> = {
            let sql = "SELECT index_block_hash FROM nakamoto_staging_blocks \
                       WHERE processed = 0 AND orphaned = 0";
            let mut stmt = self
                .nakamoto_staging_blocks_conn
                .prepare(sql)
                .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;
            let rows = stmt
                .query_map(params![], |row| row.get(0))
                .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;
            let mut ids = Vec::new();
            for row in rows {
                ids.push(row.map_err(|e| Error::DBError(db_error::SqliteError(e)))?);
            }
            ids
        };

        if candidates.is_empty() {
            return Ok(0);
        }

        // For each candidate, check for committed residue: a header row
        // or MARF entry that should not exist for an unprocessed block.
        let chainstate_conn = self.state_index.sqlite_conn();
        let half_committed: Vec<StacksBlockId> =
            self.clarity_state
                .with_marf(|marf| -> Result<Vec<StacksBlockId>, Error> {
                    let clarity_conn = marf.sqlite_conn();
                    let mut result = Vec::new();
                    for block_id in &candidates {
                        if has_committed_residue(chainstate_conn, clarity_conn, block_id)? {
                            result.push(block_id.clone());
                        }
                    }
                    Ok(result)
                })?;

        if half_committed.is_empty() {
            return Ok(0);
        }

        let count = half_committed.len();
        warn!("Startup recovery: found {count} half-committed Nakamoto block(s). Rewinding.",);
        for block_id in &half_committed {
            info!("Startup recovery: half-committed block {block_id}");
        }

        self.execute_rewind(&half_committed)?;

        warn!("Startup recovery: successfully cleaned {count} half-committed block(s).",);
        Ok(count)
    }

    // -----------------------------------------------------------------------
    // Recovery helpers
    // -----------------------------------------------------------------------

    /// Build a [`CheckContext`] and run the consistency walker from `tip`.
    ///
    /// This encapsulates the boilerplate of obtaining both SQL connections
    /// (state-index and clarity MARF) and threading them through
    /// `walk_to_last_consistent_block`. Every recovery call site needs this
    /// same setup; only the tip and check slice differ.
    fn run_recovery_pass(
        &mut self,
        tip: &StacksBlockId,
        checks: &[&dyn ConsistencyCheck],
    ) -> Result<WalkResult, Error> {
        let chainstate_conn = self.state_index.sqlite_conn();
        self.clarity_state.with_marf(|marf| {
            let ctx = CheckContext {
                chainstate_conn,
                clarity_marf_conn: marf.sqlite_conn(),
            };
            walk_to_last_consistent_block(&ctx, tip, checks)
        })
    }

    // -----------------------------------------------------------------------
    // Recovery orchestrators
    // -----------------------------------------------------------------------

    /// Run startup consistency validation against the canonical chain tip.
    ///
    /// Runs three passes:
    /// 0. **Pre-flight** (half-committed blocks): scans the staging DB for
    ///    blocks still marked `processed = 0` that have committed residue
    ///    (header rows, MARF entries) left behind by a crash between
    ///    `chainstate_tx.commit()` and `infallible_set_block_processed()`.
    ///    These blocks are passed through `execute_rewind()` so the
    ///    coordinator can re-process them cleanly.
    /// 1. **Tier 1** (MARF existence): always auto-rewinds, no depth limit.
    /// 2. **Tier 2** (epoch consistency): always runs (even after Tier 1
    ///    rewinds) to catch stale-epoch blocks behind the Tier 1 rewind
    ///    point. Subject to `max_epoch_rewind_depth` safety valve — if the
    ///    Tier 2 rewind count exceeds this limit, the function returns an
    ///    error instead of rewinding. Set to `0` to disable the limit.
    ///
    /// Returns the total number of blocks rewound across all passes
    /// (0 if consistent).
    ///
    /// This should be called after `StacksChainState::open()` returns but before
    /// the chains coordinator is spawned.
    pub fn check_and_recover_chainstate(
        &mut self,
        sortdb_conn: &Connection,
        max_epoch_rewind_depth: u64,
    ) -> Result<usize, Error> {
        let canonical_tip = canonical_stacks_tip(sortdb_conn)?;

        info!("Startup recovery: validating chainstate from canonical tip {canonical_tip}");

        // -- Pre-flight: recover half-committed Nakamoto blocks. --
        let preflight_count = self.recover_half_committed_blocks()?;

        // -- Pass 1: Tier 1 (MARF existence). Always auto-rewinds. --
        let tier1_checks: &[&dyn ConsistencyCheck] = &[&MarfExistenceCheck];
        let tier1_walk = self.run_recovery_pass(&canonical_tip, tier1_checks)?;

        let tier1_count = match tier1_walk {
            WalkResult::Disconnected { stopped_at, .. } => {
                warn!(
                    "Startup recovery: canonical tip {canonical_tip} cannot be connected \
                     to committed chainstate (walk stopped at {stopped_at}). \
                     This is unrecoverable.",
                );
                return Err(Error::NoSuchBlockError);
            }
            WalkResult::Consistent { rewind_set, .. } if rewind_set.is_empty() => 0,
            WalkResult::Consistent { rewind_set, .. } => {
                let count = rewind_set.len();
                warn!("Startup recovery: Tier 1 found {count} inconsistent blocks. Rewinding.");
                self.execute_rewind(&rewind_set)?;
                warn!("Startup recovery: Tier 1 successfully rewound {count} blocks.",);
                count
            }
        };

        // -- Pass 2: Tier 2 (epoch consistency). Subject to depth limit. --
        //
        // Always runs, even after Tier 1 rewinds. The walker will see
        // Tier 1-rewound blocks as NotInChainstate (their header rows were
        // deleted) and walk past them to check deeper committed blocks for
        // stale epochs. This guarantees a single boot fully reconciles
        // the chainstate against the current binary's epoch table.
        let epoch_check = EpochConsistencyCheck::new(sortdb_conn)?;
        let tier2_checks: &[&dyn ConsistencyCheck] = &[&epoch_check];
        let tier2_walk = self.run_recovery_pass(&canonical_tip, &tier2_checks)?;

        match tier2_walk {
            WalkResult::Disconnected { stopped_at, .. } => {
                warn!(
                    "Startup recovery: Tier 2 walk disconnected at {stopped_at}. \
                     This is unrecoverable.",
                );
                Err(Error::NoSuchBlockError)
            }
            WalkResult::Consistent { rewind_set, .. } if rewind_set.is_empty() => {
                let total = preflight_count + tier1_count;
                if total > 0 {
                    info!(
                        "Startup recovery: Tier 2 consistent. \
                         Coordinator will replay {total} blocks on start \
                         ({preflight_count} pre-flight + {tier1_count} Tier 1).",
                    );
                } else {
                    info!("Startup recovery: chainstate is consistent. No rewind needed.");
                }
                Ok(total)
            }
            WalkResult::Consistent { rewind_set, .. } => {
                let tier2_count = rewind_set.len();

                // Safety valve: refuse to rewind more than max_epoch_rewind_depth
                // blocks for epoch mismatches. A limit of 0 disables the valve.
                if max_epoch_rewind_depth > 0 && tier2_count as u64 > max_epoch_rewind_depth {
                    error!(
                        "Startup recovery: epoch rewind depth ({tier2_count}) exceeds \
                         max_epoch_rewind_depth ({max_epoch_rewind_depth}). \
                         Refusing to rewind. Increase the limit or re-sync from a snapshot."
                    );
                    return Err(Error::InvalidChainstateDB);
                }

                warn!(
                    "Startup recovery: Tier 2 found {tier2_count} epoch-mismatched blocks. \
                     Rewinding.",
                );
                self.execute_rewind(&rewind_set)?;

                let total = preflight_count + tier1_count + tier2_count;
                warn!(
                    "Startup recovery: rewound {total} blocks total \
                     ({preflight_count} pre-flight + {tier1_count} Tier 1 + \
                     {tier2_count} Tier 2). Coordinator will replay on start.",
                );
                Ok(total)
            }
        }
    }

    /// Perform runtime chainstate recovery: find the canonical stacks chain tip,
    /// walk backward to the last consistent block, and rewind all descendant
    /// blocks so they can be reprocessed.
    ///
    /// The walk starts from the canonical stacks tip (from the sortition DB), not
    /// from the missing parent, to ensure we rewind the correct (canonical) branch
    /// regardless of which block happened to trigger the error.
    ///
    /// If the canonical tip is intact, falls back to walking from `missing_parent_id`
    /// directly (the broken block may be on a different branch).
    pub fn handle_chainstate_recovery(
        &mut self,
        sortdb_conn: &Connection,
        missing_parent_id: &StacksBlockId,
    ) -> Result<(), Error> {
        warn!(
            "Chainstate recovery: beginning reconciliation \
             (triggered by missing parent {missing_parent_id})",
        );

        let canonical_tip = canonical_stacks_tip(sortdb_conn)?;

        info!(
            "Chainstate recovery: canonical stacks tip is {canonical_tip}. \
             Walking backward to find last good block.",
        );

        // Walk from canonical tip using all consistency checks.
        let epoch_check = EpochConsistencyCheck::new(sortdb_conn)?;
        let checks: &[&dyn ConsistencyCheck] = &[&MarfExistenceCheck, &epoch_check];

        let walk = self.run_recovery_pass(&canonical_tip, checks)?;

        if let WalkResult::Consistent {
            last_good,
            rewind_set,
        } = walk
        {
            if !rewind_set.is_empty() {
                warn!(
                    "Chainstate recovery: rewinding {} blocks after last good block {last_good}",
                    rewind_set.len(),
                );
                self.execute_rewind(&rewind_set)?;
                warn!(
                    "Chainstate recovery: successfully rewound {} blocks. Next coordinator pass \
                     will replay from block {last_good}.",
                    rewind_set.len(),
                );
                return Ok(());
            }
        }

        // Canonical tip walk found nothing to rewind. The broken block may be on a
        // different branch. Fallback: walk from missing_parent_id directly.
        if *missing_parent_id != canonical_tip {
            warn!(
                "Chainstate recovery: canonical tip {canonical_tip} walk found no blocks to \
                 rewind. Falling back to walk from missing parent {missing_parent_id}.",
            );

            let fallback = self.run_recovery_pass(missing_parent_id, checks)?;

            match fallback {
                WalkResult::Consistent { rewind_set, .. } if !rewind_set.is_empty() => {
                    warn!(
                        "Chainstate recovery: fallback walk found {} blocks to rewind",
                        rewind_set.len(),
                    );
                    self.execute_rewind(&rewind_set)?;
                    warn!(
                        "Chainstate recovery: fallback successfully rewound {} blocks.",
                        rewind_set.len(),
                    );
                    return Ok(());
                }
                WalkResult::Consistent { .. } => {
                    return self.diagnose_missing_parent(sortdb_conn, missing_parent_id);
                }
                WalkResult::Disconnected { stopped_at, .. } => {
                    warn!(
                        "Chainstate recovery: fallback walk from {missing_parent_id} disconnected \
                         at {stopped_at}. The child block will be orphaned by the caller.",
                    );
                    return Err(Error::NoSuchBlockError);
                }
            }
        }

        // Canonical tip IS the missing parent and data is intact — unexpected.
        warn!(
            "Chainstate recovery: canonical tip {canonical_tip} matches missing parent \
             but has intact MARF data. This is unexpected — the child block will \
             be orphaned by the caller.",
        );
        Err(Error::NoSuchBlockError)
    }

    /// When a fallback walk finds no blocks to rewind, determine whether the
    /// missing parent is a transient error or genuinely unrecoverable.
    fn diagnose_missing_parent(
        &self,
        sortdb_conn: &Connection,
        missing_parent_id: &StacksBlockId,
    ) -> Result<(), Error> {
        let _ = sortdb_conn; // available for future diagnostics
        let chainstate_conn = self.state_index.sqlite_conn();

        let parent_in_headers: bool = chainstate_conn
            .query_row(
                "SELECT 1 FROM block_headers WHERE index_block_hash = ?1 \
                 UNION SELECT 1 FROM nakamoto_block_headers \
                 WHERE index_block_hash = ?1",
                params![missing_parent_id],
                |_| Ok(true),
            )
            .optional()
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?
            .unwrap_or(false);

        if parent_in_headers {
            warn!(
                "Chainstate recovery: parent {missing_parent_id} has intact MARF data and headers. \
                 The original error may have been transient.",
            );
            return Ok(());
        }

        warn!(
            "Chainstate recovery: parent {missing_parent_id} not in block_headers \
             and not recoverable. The child block will be orphaned by the caller.",
        );
        Err(Error::NoSuchBlockError)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use clarity::vm::costs::ExecutionCost;
    use rusqlite::{params, Connection};
    use stacks_common::types::chainstate::StacksBlockId;
    use stacks_common::types::StacksEpochId;

    use super::*;
    use crate::core::{EpochList, StacksEpoch};

    /// Build a minimal in-memory chainstate DB with just the columns the
    /// consistency checks need. Includes a `marf_data` table representing the
    /// state-index MARF (lives in the same SQLite file as `block_headers`).
    fn make_test_chainstate_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE block_headers (
                index_block_hash TEXT NOT NULL PRIMARY KEY,
                parent_block_id TEXT NOT NULL,
                burn_header_height INT NOT NULL,
                evaluated_epoch INTEGER
            );
            CREATE TABLE nakamoto_block_headers (
                index_block_hash TEXT NOT NULL PRIMARY KEY,
                parent_block_id TEXT NOT NULL,
                burn_header_height INT NOT NULL,
                evaluated_epoch INTEGER
            );
            CREATE TABLE staging_blocks (
                index_block_hash TEXT NOT NULL,
                anchored_block_hash TEXT NOT NULL,
                consensus_hash TEXT NOT NULL,
                parent_anchored_block_hash TEXT NOT NULL,
                parent_consensus_hash TEXT NOT NULL
            );
            CREATE TABLE marf_data (
                block_hash TEXT NOT NULL,
                unconfirmed INTEGER NOT NULL DEFAULT 0
            );",
        )
        .unwrap();
        conn
    }

    /// Build a minimal in-memory clarity MARF DB.
    fn make_test_clarity_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE marf_data (
                block_hash TEXT NOT NULL,
                unconfirmed INTEGER NOT NULL DEFAULT 0
            );",
        )
        .unwrap();
        conn
    }

    /// Insert a block_headers row for testing.
    fn insert_test_block(
        conn: &Connection,
        block_id: &str,
        parent_id: &str,
        burn_height: u32,
        evaluated_epoch: Option<u32>,
    ) {
        conn.execute(
            "INSERT INTO block_headers \
             (index_block_hash, parent_block_id, burn_header_height, evaluated_epoch) \
             VALUES (?1, ?2, ?3, ?4)",
            params![block_id, parent_id, burn_height, evaluated_epoch],
        )
        .unwrap();
    }

    /// Insert a nakamoto_block_headers row for testing.
    fn insert_test_nakamoto_block(
        conn: &Connection,
        block_id: &str,
        parent_id: &str,
        burn_height: u32,
        evaluated_epoch: Option<u32>,
    ) {
        conn.execute(
            "INSERT INTO nakamoto_block_headers \
             (index_block_hash, parent_block_id, burn_header_height, evaluated_epoch) \
             VALUES (?1, ?2, ?3, ?4)",
            params![block_id, parent_id, burn_height, evaluated_epoch],
        )
        .unwrap();
    }

    /// Insert a clarity marf_data row.
    fn insert_test_clarity_marf(conn: &Connection, block_id: &str) {
        conn.execute(
            "INSERT INTO marf_data (block_hash, unconfirmed) VALUES (?1, 0)",
            params![block_id],
        )
        .unwrap();
    }

    /// Insert a state-index marf_data row (same DB as block_headers).
    fn insert_test_state_index_marf(conn: &Connection, block_id: &str) {
        conn.execute(
            "INSERT INTO marf_data (block_hash, unconfirmed) VALUES (?1, 0)",
            params![block_id],
        )
        .unwrap();
    }

    /// Build a test epoch list: Epoch20 at heights [0, 100), Epoch30 at [100, u64::MAX).
    fn test_epoch_list() -> EpochList {
        EpochList::from(vec![
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch20,
                start_height: 0,
                end_height: 100,
                block_limit: ExecutionCost::ZERO,
                network_epoch: 0,
            },
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch30,
                start_height: 100,
                end_height: u64::MAX,
                block_limit: ExecutionCost::ZERO,
                network_epoch: 0,
            },
        ])
    }

    // ----- EpochConsistencyCheck unit tests -----

    #[test]
    fn test_epoch_check_consistent_block() {
        let chainstate = make_test_chainstate_db();
        let clarity = make_test_clarity_db();
        let block_id = StacksBlockId([0x01; 32]);
        let parent_id = StacksBlockId([0x00; 32]);

        // Block at burn height 50, evaluated in Epoch20 — matches epoch table.
        insert_test_block(
            &chainstate,
            &block_id.to_string(),
            &parent_id.to_string(),
            50,
            Some(StacksEpochId::Epoch20 as u32),
        );

        let check = EpochConsistencyCheck::from_epochs(test_epoch_list());
        let ctx = CheckContext {
            chainstate_conn: &chainstate,
            clarity_marf_conn: &clarity,
        };

        match check.check_block(&ctx, &block_id).unwrap() {
            BlockConsistency::Consistent => {} // expected
            other => panic!("Expected Consistent, got {other:?}"),
        }
    }

    #[test]
    fn test_epoch_check_mismatch_detected() {
        let chainstate = make_test_chainstate_db();
        let clarity = make_test_clarity_db();
        let block_id = StacksBlockId([0x02; 32]);
        let parent_id = StacksBlockId([0x01; 32]);

        // Block at burn height 50, but stored as Epoch30 — should be Epoch20.
        insert_test_block(
            &chainstate,
            &block_id.to_string(),
            &parent_id.to_string(),
            50,
            Some(StacksEpochId::Epoch30 as u32),
        );

        let check = EpochConsistencyCheck::from_epochs(test_epoch_list());
        let ctx = CheckContext {
            chainstate_conn: &chainstate,
            clarity_marf_conn: &clarity,
        };

        match check.check_block(&ctx, &block_id).unwrap() {
            BlockConsistency::NeedsRewind {
                reason: RecoveryReason::EpochMismatch { expected, found },
                parent_block_id,
            } => {
                assert_eq!(expected, StacksEpochId::Epoch20);
                assert_eq!(found, StacksEpochId::Epoch30);
                assert_eq!(parent_block_id, parent_id);
            }
            other => panic!("Expected NeedsRewind(EpochMismatch), got {other:?}"),
        }
    }

    #[test]
    fn test_epoch_check_null_grandfathered() {
        let chainstate = make_test_chainstate_db();
        let clarity = make_test_clarity_db();
        let block_id = StacksBlockId([0x03; 32]);
        let parent_id = StacksBlockId([0x02; 32]);

        // Block with NULL evaluated_epoch — committed by older binary.
        insert_test_block(
            &chainstate,
            &block_id.to_string(),
            &parent_id.to_string(),
            50,
            None,
        );

        let check = EpochConsistencyCheck::from_epochs(test_epoch_list());
        let ctx = CheckContext {
            chainstate_conn: &chainstate,
            clarity_marf_conn: &clarity,
        };

        match check.check_block(&ctx, &block_id).unwrap() {
            BlockConsistency::Consistent => {} // expected — NULL is grandfathered
            other => panic!("Expected Consistent (grandfathered), got {other:?}"),
        }
    }

    #[test]
    fn test_epoch_check_not_in_chainstate() {
        let chainstate = make_test_chainstate_db();
        let clarity = make_test_clarity_db();
        let block_id = StacksBlockId([0x99; 32]);

        // Block not in any header table.
        let check = EpochConsistencyCheck::from_epochs(test_epoch_list());
        let ctx = CheckContext {
            chainstate_conn: &chainstate,
            clarity_marf_conn: &clarity,
        };

        match check.check_block(&ctx, &block_id).unwrap() {
            BlockConsistency::NotInChainstate => {} // expected
            other => panic!("Expected NotInChainstate, got {other:?}"),
        }
    }

    #[test]
    fn test_epoch_check_nakamoto_block() {
        let chainstate = make_test_chainstate_db();
        let clarity = make_test_clarity_db();
        let block_id = StacksBlockId([0x04; 32]);
        let parent_id = StacksBlockId([0x03; 32]);

        // Block in nakamoto_block_headers at burn height 150, evaluated Epoch30 — correct.
        insert_test_nakamoto_block(
            &chainstate,
            &block_id.to_string(),
            &parent_id.to_string(),
            150,
            Some(StacksEpochId::Epoch30 as u32),
        );

        let check = EpochConsistencyCheck::from_epochs(test_epoch_list());
        let ctx = CheckContext {
            chainstate_conn: &chainstate,
            clarity_marf_conn: &clarity,
        };

        match check.check_block(&ctx, &block_id).unwrap() {
            BlockConsistency::Consistent => {}
            other => panic!("Expected Consistent, got {other:?}"),
        }
    }

    #[test]
    fn test_epoch_check_nakamoto_mismatch() {
        let chainstate = make_test_chainstate_db();
        let clarity = make_test_clarity_db();
        let block_id = StacksBlockId([0x05; 32]);
        let parent_id = StacksBlockId([0x04; 32]);

        // Block in nakamoto at burn height 150, but stored as Epoch20 — wrong.
        insert_test_nakamoto_block(
            &chainstate,
            &block_id.to_string(),
            &parent_id.to_string(),
            150,
            Some(StacksEpochId::Epoch20 as u32),
        );

        let check = EpochConsistencyCheck::from_epochs(test_epoch_list());
        let ctx = CheckContext {
            chainstate_conn: &chainstate,
            clarity_marf_conn: &clarity,
        };

        match check.check_block(&ctx, &block_id).unwrap() {
            BlockConsistency::NeedsRewind {
                reason: RecoveryReason::EpochMismatch { expected, found },
                ..
            } => {
                assert_eq!(expected, StacksEpochId::Epoch30);
                assert_eq!(found, StacksEpochId::Epoch20);
            }
            other => panic!("Expected NeedsRewind(EpochMismatch), got {other:?}"),
        }
    }

    // ----- Walker integration tests with EpochConsistencyCheck -----

    #[test]
    fn test_walk_epoch_mismatch_rewind() {
        let chainstate = make_test_chainstate_db();
        let clarity = make_test_clarity_db();

        let sentinel = StacksBlockId::sentinel();
        let block_a = StacksBlockId([0x0a; 32]);
        let block_b = StacksBlockId([0x0b; 32]);
        let block_c = StacksBlockId([0x0c; 32]);

        // Chain: sentinel <- A (good) <- B (good) <- C (epoch mismatch)
        // All at burn height 50 (Epoch20 range).
        insert_test_block(
            &chainstate,
            &block_a.to_string(),
            &sentinel.to_string(),
            50,
            Some(StacksEpochId::Epoch20 as u32),
        );
        insert_test_clarity_marf(&clarity, &block_a.to_string());
        insert_test_state_index_marf(&chainstate, &block_a.to_string());

        insert_test_block(
            &chainstate,
            &block_b.to_string(),
            &block_a.to_string(),
            51,
            Some(StacksEpochId::Epoch20 as u32),
        );
        insert_test_clarity_marf(&clarity, &block_b.to_string());
        insert_test_state_index_marf(&chainstate, &block_b.to_string());

        // Block C has wrong epoch (Epoch30 instead of Epoch20)
        insert_test_block(
            &chainstate,
            &block_c.to_string(),
            &block_b.to_string(),
            52,
            Some(StacksEpochId::Epoch30 as u32),
        );
        insert_test_clarity_marf(&clarity, &block_c.to_string());
        insert_test_state_index_marf(&chainstate, &block_c.to_string());

        let epoch_check = EpochConsistencyCheck::from_epochs(test_epoch_list());
        let checks: &[&dyn ConsistencyCheck] = &[&MarfExistenceCheck, &epoch_check];
        let ctx = CheckContext {
            chainstate_conn: &chainstate,
            clarity_marf_conn: &clarity,
        };

        let result = walk_to_last_consistent_block(&ctx, &block_c, checks).unwrap();
        match result {
            WalkResult::Consistent {
                last_good,
                rewind_set,
            } => {
                assert_eq!(last_good, block_b);
                assert_eq!(rewind_set, vec![block_c]);
            }
            other => panic!("Expected Consistent with rewind, got {other:?}"),
        }
    }

    #[test]
    fn test_walk_multiple_epoch_mismatches() {
        let chainstate = make_test_chainstate_db();
        let clarity = make_test_clarity_db();

        let sentinel = StacksBlockId::sentinel();
        let block_a = StacksBlockId([0x0a; 32]);
        let block_b = StacksBlockId([0x0b; 32]);
        let block_c = StacksBlockId([0x0c; 32]);

        // A is good (Epoch20 at height 50), B and C are mismatched (Epoch30 at heights 51-52).
        insert_test_block(
            &chainstate,
            &block_a.to_string(),
            &sentinel.to_string(),
            50,
            Some(StacksEpochId::Epoch20 as u32),
        );
        insert_test_clarity_marf(&clarity, &block_a.to_string());
        insert_test_state_index_marf(&chainstate, &block_a.to_string());

        insert_test_block(
            &chainstate,
            &block_b.to_string(),
            &block_a.to_string(),
            51,
            Some(StacksEpochId::Epoch30 as u32), // wrong
        );
        insert_test_clarity_marf(&clarity, &block_b.to_string());
        insert_test_state_index_marf(&chainstate, &block_b.to_string());

        insert_test_block(
            &chainstate,
            &block_c.to_string(),
            &block_b.to_string(),
            52,
            Some(StacksEpochId::Epoch30 as u32), // wrong
        );
        insert_test_clarity_marf(&clarity, &block_c.to_string());
        insert_test_state_index_marf(&chainstate, &block_c.to_string());

        let epoch_check = EpochConsistencyCheck::from_epochs(test_epoch_list());
        let checks: &[&dyn ConsistencyCheck] = &[&MarfExistenceCheck, &epoch_check];
        let ctx = CheckContext {
            chainstate_conn: &chainstate,
            clarity_marf_conn: &clarity,
        };

        let result = walk_to_last_consistent_block(&ctx, &block_c, checks).unwrap();
        match result {
            WalkResult::Consistent {
                last_good,
                rewind_set,
            } => {
                assert_eq!(last_good, block_a);
                assert_eq!(rewind_set, vec![block_c, block_b]);
            }
            other => panic!("Expected Consistent with 2 rewinds, got {other:?}"),
        }
    }

    #[test]
    fn test_walk_null_epoch_grandfathered_mid_chain() {
        let chainstate = make_test_chainstate_db();
        let clarity = make_test_clarity_db();

        let sentinel = StacksBlockId::sentinel();
        let block_a = StacksBlockId([0x0a; 32]);
        let block_b = StacksBlockId([0x0b; 32]);

        // A has NULL epoch (grandfathered), B has correct epoch.
        insert_test_block(
            &chainstate,
            &block_a.to_string(),
            &sentinel.to_string(),
            50,
            None, // grandfathered
        );
        insert_test_clarity_marf(&clarity, &block_a.to_string());
        insert_test_state_index_marf(&chainstate, &block_a.to_string());

        insert_test_block(
            &chainstate,
            &block_b.to_string(),
            &block_a.to_string(),
            51,
            Some(StacksEpochId::Epoch20 as u32),
        );
        insert_test_clarity_marf(&clarity, &block_b.to_string());
        insert_test_state_index_marf(&chainstate, &block_b.to_string());

        let epoch_check = EpochConsistencyCheck::from_epochs(test_epoch_list());
        let checks: &[&dyn ConsistencyCheck] = &[&MarfExistenceCheck, &epoch_check];
        let ctx = CheckContext {
            chainstate_conn: &chainstate,
            clarity_marf_conn: &clarity,
        };

        let result = walk_to_last_consistent_block(&ctx, &block_b, checks).unwrap();
        match result {
            WalkResult::Consistent {
                last_good,
                rewind_set,
            } => {
                // Tip is consistent, walk stops immediately.
                assert_eq!(last_good, block_b);
                assert!(rewind_set.is_empty());
            }
            other => panic!("Expected fully consistent, got {other:?}"),
        }
    }

    // ----- MissingStateIndex detection tests -----

    #[test]
    fn test_missing_state_index_detected() {
        let chainstate = make_test_chainstate_db();
        let clarity = make_test_clarity_db();
        let block_id = StacksBlockId([0x10; 32]);
        let parent_id = StacksBlockId([0x0f; 32]);

        // Block in headers and clarity marf_data, but NOT in state-index marf_data.
        insert_test_block(
            &chainstate,
            &block_id.to_string(),
            &parent_id.to_string(),
            50,
            None,
        );
        insert_test_clarity_marf(&clarity, &block_id.to_string());
        // Deliberately NOT calling insert_test_state_index_marf

        let check = MarfExistenceCheck;
        let ctx = CheckContext {
            chainstate_conn: &chainstate,
            clarity_marf_conn: &clarity,
        };

        match check.check_block(&ctx, &block_id).unwrap() {
            BlockConsistency::NeedsRewind {
                reason: RecoveryReason::MissingStateIndex,
                parent_block_id,
            } => {
                assert_eq!(parent_block_id, parent_id);
            }
            other => panic!("Expected NeedsRewind(MissingStateIndex), got {other:?}"),
        }
    }

    #[test]
    fn test_walk_missing_state_index_rewind() {
        let chainstate = make_test_chainstate_db();
        let clarity = make_test_clarity_db();

        let sentinel = StacksBlockId::sentinel();
        let block_a = StacksBlockId([0x0a; 32]);
        let block_b = StacksBlockId([0x0b; 32]);

        // Block A: fully consistent (in headers, clarity, AND state-index)
        insert_test_block(
            &chainstate,
            &block_a.to_string(),
            &sentinel.to_string(),
            50,
            None,
        );
        insert_test_clarity_marf(&clarity, &block_a.to_string());
        insert_test_state_index_marf(&chainstate, &block_a.to_string());

        // Block B: in headers and clarity but MISSING from state-index
        insert_test_block(
            &chainstate,
            &block_b.to_string(),
            &block_a.to_string(),
            51,
            None,
        );
        insert_test_clarity_marf(&clarity, &block_b.to_string());
        // Deliberately NOT inserting into state-index marf_data

        let checks: &[&dyn ConsistencyCheck] = &[&MarfExistenceCheck];
        let ctx = CheckContext {
            chainstate_conn: &chainstate,
            clarity_marf_conn: &clarity,
        };

        let result = walk_to_last_consistent_block(&ctx, &block_b, checks).unwrap();
        match result {
            WalkResult::Consistent {
                last_good,
                rewind_set,
            } => {
                assert_eq!(last_good, block_a);
                assert_eq!(rewind_set, vec![block_b]);
            }
            other => panic!("Expected Consistent with rewind, got {other:?}"),
        }
    }

    // ----- Startup orchestration tests (check_and_recover_chainstate) -----
    //
    // These tests exercise the full startup recovery path including the
    // two-pass structure (Tier 1 then Tier 2) and the safety valve.

    use std::fs;

    use stacks_common::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash};

    use crate::burnchains::PoxConstants;
    use crate::chainstate::burn::db::sortdb::SortitionDB;
    use crate::chainstate::burn::ConsensusHash;
    use crate::chainstate::stacks::db::test::instantiate_chainstate;
    use crate::core::StacksEpochExtension;

    /// Helper: create a SortitionDB with custom epochs for testing.
    fn make_test_sortdb(test_name: &str, epochs: EpochList) -> SortitionDB {
        let path = format!("/tmp/stacks-node-tests/recovery-sortdb-{test_name}");
        if fs::metadata(&path).is_ok() {
            fs::remove_dir_all(&path).unwrap();
        }
        SortitionDB::connect(
            &path,
            0,
            &BurnchainHeaderHash::zero(),
            0,
            &epochs,
            PoxConstants::testnet_default(),
            None,
            true,
            None,
        )
        .unwrap()
    }

    #[test]
    fn test_startup_recovery_consistent_chainstate() {
        // Fresh chainstate + sortition DB with matching epochs → no rewind.
        let test_name = "test_startup_recovery_consistent_chainstate";
        let mut chainstate = instantiate_chainstate(false, 0x80000000, test_name);
        let epochs = StacksEpoch::unit_test(StacksEpochId::Epoch20, 0);
        let sortdb = make_test_sortdb(test_name, epochs);

        let result = chainstate.check_and_recover_chainstate(sortdb.conn(), 256);
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_startup_recovery_epoch_mismatch_rewind() {
        // Corrupt the genesis block's evaluated_epoch, verify Tier 2 detects and rewinds it.
        let test_name = "test_startup_recovery_epoch_mismatch_rewind";
        let mut chainstate = instantiate_chainstate(false, 0x80000000, test_name);

        // The genesis block was inserted with evaluated_epoch = Epoch20. Corrupt it to Epoch30.
        let genesis_id = StacksBlockHeader::make_index_block_hash(
            &crate::core::FIRST_BURNCHAIN_CONSENSUS_HASH,
            &crate::core::FIRST_STACKS_BLOCK_HASH,
        );
        chainstate
            .state_index
            .sqlite_conn()
            .execute(
                "UPDATE block_headers SET evaluated_epoch = ?1 WHERE index_block_hash = ?2",
                params![StacksEpochId::Epoch30 as u32, genesis_id],
            )
            .unwrap();

        // Use default test epochs (Epoch20 at height 0) so the stored Epoch30 is a mismatch.
        let epochs = StacksEpoch::unit_test(StacksEpochId::Epoch20, 0);
        let sortdb = make_test_sortdb(test_name, epochs);

        let result = chainstate.check_and_recover_chainstate(sortdb.conn(), 256);
        // Should have rewound the genesis block.
        assert_eq!(result.unwrap(), 1);
    }

    #[test]
    fn test_startup_recovery_safety_valve_blocks_deep_rewind() {
        // Same epoch mismatch as above, but with max_epoch_rewind_depth = 0 meaning unlimited,
        // and then with a tight limit that should block the rewind.
        let test_name = "test_startup_recovery_safety_valve_blocks_deep_rewind";

        // --- Case 1: limit = 0 (unlimited) → rewind succeeds ---
        {
            let case_name = &format!("{test_name}_unlimited");
            let mut chainstate = instantiate_chainstate(false, 0x80000000, case_name);
            let genesis_id = StacksBlockHeader::make_index_block_hash(
                &crate::core::FIRST_BURNCHAIN_CONSENSUS_HASH,
                &crate::core::FIRST_STACKS_BLOCK_HASH,
            );
            chainstate
                .state_index
                .sqlite_conn()
                .execute(
                    "UPDATE block_headers SET evaluated_epoch = ?1 WHERE index_block_hash = ?2",
                    params![StacksEpochId::Epoch30 as u32, genesis_id],
                )
                .unwrap();

            let epochs = StacksEpoch::unit_test(StacksEpochId::Epoch20, 0);
            let sortdb = make_test_sortdb(case_name, epochs);

            // limit = 0 disables safety valve.
            let result = chainstate.check_and_recover_chainstate(sortdb.conn(), 0);
            assert_eq!(result.unwrap(), 1);
        }

        // --- Case 2: limit = 1 allows rewind of exactly 1 block (edge case) ---
        {
            let case_name = &format!("{test_name}_exact_limit");
            let mut chainstate = instantiate_chainstate(false, 0x80000000, case_name);
            let genesis_id = StacksBlockHeader::make_index_block_hash(
                &crate::core::FIRST_BURNCHAIN_CONSENSUS_HASH,
                &crate::core::FIRST_STACKS_BLOCK_HASH,
            );
            chainstate
                .state_index
                .sqlite_conn()
                .execute(
                    "UPDATE block_headers SET evaluated_epoch = ?1 WHERE index_block_hash = ?2",
                    params![StacksEpochId::Epoch30 as u32, genesis_id],
                )
                .unwrap();

            let epochs = StacksEpoch::unit_test(StacksEpochId::Epoch20, 0);
            let sortdb = make_test_sortdb(case_name, epochs);

            // limit = 1, rewind count = 1 → should succeed (count is NOT > limit).
            let result = chainstate.check_and_recover_chainstate(sortdb.conn(), 1);
            assert_eq!(result.unwrap(), 1);
        }

        // --- Case 3: limit exceeded → error ---
        //
        // Insert a fake child block so the walk finds 2 mismatched blocks,
        // then set limit = 1 which should block the rewind.
        {
            let case_name = &format!("{test_name}_exceeded");
            let mut chainstate = instantiate_chainstate(false, 0x80000000, case_name);
            let genesis_id = StacksBlockHeader::make_index_block_hash(
                &crate::core::FIRST_BURNCHAIN_CONSENSUS_HASH,
                &crate::core::FIRST_STACKS_BLOCK_HASH,
            );

            // Corrupt the genesis block's epoch.
            chainstate
                .state_index
                .sqlite_conn()
                .execute(
                    "UPDATE block_headers SET evaluated_epoch = ?1 WHERE index_block_hash = ?2",
                    params![StacksEpochId::Epoch30 as u32, genesis_id],
                )
                .unwrap();

            // Insert a fake child block that also has a mismatched epoch.
            // This block will be the canonical tip (we'll update the sortition
            // DB's snapshot to point to it).
            let fake_consensus = ConsensusHash([0xBB; 20]);
            let fake_block_hash = BlockHeaderHash([0xCC; 32]);
            let fake_child_id =
                StacksBlockHeader::make_index_block_hash(&fake_consensus, &fake_block_hash);
            chainstate
                .state_index
                .sqlite_conn()
                .execute(
                    "INSERT INTO block_headers \
                     (version, total_burn, total_work, proof, parent_block, \
                      parent_microblock, parent_microblock_sequence, tx_merkle_root, \
                      state_index_root, microblock_pubkey_hash, block_hash, \
                      index_block_hash, consensus_hash, burn_header_hash, \
                      burn_header_height, burn_header_timestamp, block_height, \
                      index_root, cost, block_size, parent_block_id, evaluated_epoch) \
                     VALUES (0, '0', '1', '', '', '', 0, '', '', '', ?1, ?2, ?3, '', \
                             0, 0, 1, '', '{ \"runtime\": 0, \"write_length\": 0, \
                             \"write_count\": 0, \"read_length\": 0, \"read_count\": 0 }', \
                             '0', ?4, ?5)",
                    params![
                        fake_block_hash,
                        fake_child_id,
                        fake_consensus,
                        genesis_id,
                        StacksEpochId::Epoch30 as u32 // wrong epoch
                    ],
                )
                .unwrap();

            // Also add the fake child to the clarity MARF marf_data so Tier 1
            // passes for it (otherwise Tier 1 would catch it first).
            chainstate
                .clarity_state
                .with_marf(|marf| {
                    marf.sqlite_conn().execute(
                        "INSERT INTO marf_data (block_hash, data, unconfirmed) \
                     VALUES (?1, X'00', 0)",
                        params![fake_child_id],
                    )
                })
                .unwrap();

            // Create sortition DB and update the canonical stacks tip to our fake child.
            let epochs = StacksEpoch::unit_test(StacksEpochId::Epoch20, 0);
            let sortdb = make_test_sortdb(case_name, epochs);
            sortdb
                .conn()
                .execute(
                    "UPDATE snapshots SET canonical_stacks_tip_consensus_hash = ?1, \
                     canonical_stacks_tip_hash = ?2",
                    params![fake_consensus, fake_block_hash],
                )
                .unwrap();

            // limit = 1, but 2 blocks need rewind → should fail.
            let result = chainstate.check_and_recover_chainstate(sortdb.conn(), 1);
            assert!(
                result.is_err(),
                "Expected error when rewind depth exceeds limit, got {result:?}",
            );
        }
    }

    // ----- has_committed_residue unit tests -----

    #[test]
    fn test_has_committed_residue_no_residue() {
        let chainstate = make_test_chainstate_db();
        let clarity = make_test_clarity_db();
        let block_id = StacksBlockId([0x42; 32]);

        // Block has no header, no state-index MARF, no clarity MARF → no residue.
        assert!(!has_committed_residue(&chainstate, &clarity, &block_id).unwrap());
    }

    #[test]
    fn test_has_committed_residue_header_only() {
        let chainstate = make_test_chainstate_db();
        let clarity = make_test_clarity_db();
        let block_id = StacksBlockId([0x42; 32]);
        let parent_id = StacksBlockId([0x41; 32]);

        // Block has a nakamoto_block_headers row but nothing else.
        insert_test_nakamoto_block(
            &chainstate,
            &block_id.to_string(),
            &parent_id.to_string(),
            100,
            Some(StacksEpochId::Epoch30 as u32),
        );

        assert!(has_committed_residue(&chainstate, &clarity, &block_id).unwrap());
    }

    #[test]
    fn test_has_committed_residue_state_index_marf_only() {
        let chainstate = make_test_chainstate_db();
        let clarity = make_test_clarity_db();
        let block_id = StacksBlockId([0x42; 32]);

        // Block has state-index marf_data but no header or clarity entry.
        insert_test_state_index_marf(&chainstate, &block_id.to_string());

        assert!(has_committed_residue(&chainstate, &clarity, &block_id).unwrap());
    }

    #[test]
    fn test_has_committed_residue_clarity_marf_only() {
        let chainstate = make_test_chainstate_db();
        let clarity = make_test_clarity_db();
        let block_id = StacksBlockId([0x42; 32]);

        // Block has clarity marf_data but no header or state-index entry.
        insert_test_clarity_marf(&clarity, &block_id.to_string());

        assert!(has_committed_residue(&chainstate, &clarity, &block_id).unwrap());
    }

    #[test]
    fn test_has_committed_residue_all_residue() {
        let chainstate = make_test_chainstate_db();
        let clarity = make_test_clarity_db();
        let block_id = StacksBlockId([0x42; 32]);
        let parent_id = StacksBlockId([0x41; 32]);

        // Full residue: header + both MARFs.
        insert_test_nakamoto_block(
            &chainstate,
            &block_id.to_string(),
            &parent_id.to_string(),
            100,
            Some(StacksEpochId::Epoch30 as u32),
        );
        insert_test_state_index_marf(&chainstate, &block_id.to_string());
        insert_test_clarity_marf(&clarity, &block_id.to_string());

        assert!(has_committed_residue(&chainstate, &clarity, &block_id).unwrap());
    }

    // ----- Half-committed block recovery integration tests -----

    #[test]
    fn test_startup_recovery_half_committed_block() {
        // Simulate a crash between chainstate_tx.commit() and
        // infallible_set_block_processed(): the block has a header row and
        // MARF entries but staging still says processed = 0.
        let test_name = "test_startup_recovery_half_committed_block";
        let mut chainstate = instantiate_chainstate(false, 0x80000000, test_name);
        let epochs = StacksEpoch::unit_test(StacksEpochId::Epoch20, 0);
        let sortdb = make_test_sortdb(test_name, epochs);

        let fake_consensus = ConsensusHash([0xAA; 20]);
        let fake_block_hash = BlockHeaderHash([0xBB; 32]);
        let fake_block_id =
            StacksBlockHeader::make_index_block_hash(&fake_consensus, &fake_block_hash);
        let genesis_id = StacksBlockHeader::make_index_block_hash(
            &crate::core::FIRST_BURNCHAIN_CONSENSUS_HASH,
            &crate::core::FIRST_STACKS_BLOCK_HASH,
        );

        // Insert a nakamoto_staging_blocks entry: processed = 0, orphaned = 0.
        chainstate
            .nakamoto_staging_blocks_conn
            .execute(
                "INSERT INTO nakamoto_staging_blocks \
                 (block_hash, consensus_hash, parent_block_id, is_tenure_start, \
                  burn_attachable, processed, orphaned, index_block_hash, \
                  processed_time, obtain_method, signing_weight, data, height) \
                 VALUES (?1, ?2, ?3, 0, 1, 0, 0, ?4, 0, 'test', 0, X'00', 1)",
                params![fake_block_hash, fake_consensus, genesis_id, fake_block_id],
            )
            .unwrap();

        // Simulate residue: insert state-index marf_data (written by
        // chainstate_tx.commit() before the crash).
        chainstate
            .state_index
            .sqlite_conn()
            .execute(
                "INSERT INTO marf_data (block_hash, data, unconfirmed) VALUES (?1, X'00', 0)",
                params![fake_block_id],
            )
            .unwrap();

        // And clarity marf_data residue.
        chainstate
            .clarity_state
            .with_marf(|marf| {
                marf.sqlite_conn().execute(
                    "INSERT INTO marf_data (block_hash, data, unconfirmed) VALUES (?1, X'00', 0)",
                    params![fake_block_id],
                )
            })
            .unwrap();

        // Run recovery. The pre-flight should detect and rewind the
        // half-committed block.
        let result = chainstate.check_and_recover_chainstate(sortdb.conn(), 256);
        assert_eq!(
            result.unwrap(),
            1,
            "Expected 1 half-committed block rewound"
        );

        // Verify the residue was cleaned up:
        // - state-index marf_data row should be gone.
        let marf_count: u32 = chainstate
            .state_index
            .sqlite_conn()
            .query_row(
                "SELECT COUNT(*) FROM marf_data WHERE block_hash = ?1 AND unconfirmed = 0",
                params![fake_block_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            marf_count, 0,
            "State-index marf_data should have been deleted"
        );

        // - clarity marf_data row should be gone.
        let clarity_count: u32 = chainstate
            .clarity_state
            .with_marf(|marf| {
                marf.sqlite_conn().query_row(
                    "SELECT COUNT(*) FROM marf_data WHERE block_hash = ?1 AND unconfirmed = 0",
                    params![fake_block_id],
                    |row| row.get(0),
                )
            })
            .unwrap();
        assert_eq!(
            clarity_count, 0,
            "Clarity marf_data should have been deleted"
        );

        // - staging entry should still have processed = 0 (ready for reprocessing).
        let processed: u32 = chainstate
            .nakamoto_staging_blocks_conn
            .query_row(
                "SELECT processed FROM nakamoto_staging_blocks WHERE index_block_hash = ?1",
                params![fake_block_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(processed, 0, "Staging entry should still be processed = 0");
    }

    #[test]
    fn test_startup_recovery_no_half_committed_blocks() {
        // Verify that when there are unprocessed staging blocks with NO
        // committed residue, the pre-flight is a no-op.
        let test_name = "test_startup_recovery_no_half_committed_blocks";
        let mut chainstate = instantiate_chainstate(false, 0x80000000, test_name);
        let epochs = StacksEpoch::unit_test(StacksEpochId::Epoch20, 0);
        let sortdb = make_test_sortdb(test_name, epochs);

        let fake_consensus = ConsensusHash([0xCC; 20]);
        let fake_block_hash = BlockHeaderHash([0xDD; 32]);
        let fake_block_id =
            StacksBlockHeader::make_index_block_hash(&fake_consensus, &fake_block_hash);
        let genesis_id = StacksBlockHeader::make_index_block_hash(
            &crate::core::FIRST_BURNCHAIN_CONSENSUS_HASH,
            &crate::core::FIRST_STACKS_BLOCK_HASH,
        );

        // Insert a staging block with NO committed residue (normal pending block).
        chainstate
            .nakamoto_staging_blocks_conn
            .execute(
                "INSERT INTO nakamoto_staging_blocks \
                 (block_hash, consensus_hash, parent_block_id, is_tenure_start, \
                  burn_attachable, processed, orphaned, index_block_hash, \
                  processed_time, obtain_method, signing_weight, data, height) \
                 VALUES (?1, ?2, ?3, 0, 1, 0, 0, ?4, 0, 'test', 0, X'00', 1)",
                params![fake_block_hash, fake_consensus, genesis_id, fake_block_id],
            )
            .unwrap();

        // Recovery should find nothing to rewind.
        let result = chainstate.check_and_recover_chainstate(sortdb.conn(), 256);
        assert_eq!(result.unwrap(), 0, "Expected no blocks rewound");
    }

    #[test]
    fn test_startup_recovery_orphaned_staging_ignored() {
        // Verify that orphaned staging blocks are not scanned — only
        // unprocessed non-orphaned blocks are candidates.
        let test_name = "test_startup_recovery_orphaned_staging_ignored";
        let mut chainstate = instantiate_chainstate(false, 0x80000000, test_name);
        let epochs = StacksEpoch::unit_test(StacksEpochId::Epoch20, 0);
        let sortdb = make_test_sortdb(test_name, epochs);

        let fake_consensus = ConsensusHash([0xEE; 20]);
        let fake_block_hash = BlockHeaderHash([0xFF; 32]);
        let fake_block_id =
            StacksBlockHeader::make_index_block_hash(&fake_consensus, &fake_block_hash);
        let genesis_id = StacksBlockHeader::make_index_block_hash(
            &crate::core::FIRST_BURNCHAIN_CONSENSUS_HASH,
            &crate::core::FIRST_STACKS_BLOCK_HASH,
        );

        // Insert a staging block that is orphaned = 1 (should be skipped).
        chainstate
            .nakamoto_staging_blocks_conn
            .execute(
                "INSERT INTO nakamoto_staging_blocks \
                 (block_hash, consensus_hash, parent_block_id, is_tenure_start, \
                  burn_attachable, processed, orphaned, index_block_hash, \
                  processed_time, obtain_method, signing_weight, data, height) \
                 VALUES (?1, ?2, ?3, 0, 1, 0, 1, ?4, 0, 'test', 0, X'00', 1)",
                params![fake_block_hash, fake_consensus, genesis_id, fake_block_id],
            )
            .unwrap();

        // Insert residue that WOULD be detected if the block weren't orphaned.
        chainstate
            .state_index
            .sqlite_conn()
            .execute(
                "INSERT INTO marf_data (block_hash, data, unconfirmed) VALUES (?1, X'00', 0)",
                params![fake_block_id],
            )
            .unwrap();

        // Recovery should find nothing because orphaned blocks are excluded.
        let result = chainstate.check_and_recover_chainstate(sortdb.conn(), 256);
        assert_eq!(
            result.unwrap(),
            0,
            "Expected no blocks rewound (orphaned ignored)"
        );
    }
}
