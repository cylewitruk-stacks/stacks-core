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
use std::ops::Deref;
#[cfg(any(test, feature = "testing"))]
use std::sync::LazyLock;
use std::time::Instant;

#[cfg(any(test, feature = "testing"))]
use clarity::util::tests::TestFlag;
use rusqlite::{Connection, Transaction};
use stacks_common::types::chainstate::{TrieHash, TRIEHASH_ENCODED_SIZE};
use stacks_common::util::hash::Sha512Trunc256Sum;

use super::squash::SquashMode;
use super::storage::ReopenedTrieStorageConnection;
use crate::chainstate::stacks::index::node::{
    clear_backptr, is_backptr, node_copy_update_ptrs, set_backptr, CursorError, TrieCowPtr,
    TrieCursor, TrieNode256, TrieNodeID, TrieNodeType, TriePtr,
};
use crate::chainstate::stacks::index::scratch::MarfReadState;
use crate::chainstate::stacks::index::storage::{
    TrieFileStorage, TrieHashCalculationMode, TrieStorageConnection, TrieStorageTransaction,
};
use crate::chainstate::stacks::index::trie::Trie;
use crate::chainstate::stacks::index::{
    bits, Error, MARFValue, MarfTrieId, NodeDecodeScratch, NodeParking, ReadNodeBacking,
    ReadTrieNode, ReadTrieNodeCursorStep, TrieLeaf, TrieMerkleProof, TrieNodeReadState,
    TrieReadSession, TrieReadStorage,
};
use crate::util_lib::db::Error as db_error;

pub const BLOCK_HASH_TO_HEIGHT_MAPPING_KEY: &str = "__MARF_BLOCK_HASH_TO_HEIGHT";
pub const BLOCK_HEIGHT_TO_HASH_MAPPING_KEY: &str = "__MARF_BLOCK_HEIGHT_TO_HASH";
pub const OWN_BLOCK_HEIGHT_KEY: &str = "__MARF_BLOCK_HEIGHT_SELF";

#[cfg(any(test, feature = "testing"))]
/// Global default override for MARF compression used in tests.
///
/// This constant allows forcing *all* MARF instances created in tests
/// to use compression (`Some(true)`) or to disable it (`Some(false)`),
/// regardless of the test’s local configuration.
///
/// When set to `None`, test's own MARF configuration is used.
const TEST_MARF_COMPRESSION_DEFAULT: Option<bool> = None;

#[cfg(any(test, feature = "testing"))]
/// Test flag used to override MARF compression during test execution.
///
/// This flag enables tests to dynamically enable or disable MARF compression
/// *after* process startup, allowing scenarios where compression is switched
/// on and off within the same test.
static TEST_MARF_COMPRESSION_FLAG: LazyLock<TestFlag<Option<bool>>> =
    LazyLock::new(TestFlag::default);

#[cfg(any(test, feature = "testing"))]
/// Inject a runtime override for MARF compression in tests.
pub fn fault_injection_marf_compression(enabled: bool) {
    TEST_MARF_COMPRESSION_FLAG.set(Some(enabled));
}

#[cfg(any(test, feature = "testing"))]
/// Apply test-specific overrides to the MARF compression configuration.
///
/// This function mutates the provided [`MARFOpenOpts`], according to the
/// following precedence order:
///
/// 1. Runtime test override via [`TEST_MARF_COMPRESSION_FLAG`]
/// 2. Global test default via [`TEST_MARF_COMPRESSION_DEFAULT`]
/// 3. The original value in [`MARFOpenOpts`] (no override)
///
/// In non-test builds, this function is compiled to a no-op.
pub fn test_override_marf_compression(marf_opts: &mut MARFOpenOpts) {
    if let Some(enabled) = TEST_MARF_COMPRESSION_FLAG.get() {
        marf_opts.compress = enabled;
        info!("Test flag used. MARF Compression overridden to {enabled}");
        return;
    }

    if let Some(enabled) = TEST_MARF_COMPRESSION_DEFAULT {
        marf_opts.compress = enabled;
        info!("Test default used. MARF Compression overridden to {enabled}");
    }
}

#[cfg(not(any(test, feature = "testing")))]
/// No-op stub for non-test builds.
pub fn test_override_marf_compression(_marf_opts: &mut MARFOpenOpts) {}

/// Merklized Adaptive-Radix Forest -- a collection of Merklized Adaptive-Radix Tries.
pub struct MARF<T: MarfTrieId> {
    pub(crate) storage: TrieFileStorage<T>,
    open_chain_tip: Option<WriteChainTip<T>>,
    read_cursor: Option<TrieCursor<T>>,
    read_state: MarfReadState,
}

pub struct MarfTransaction<'a, T: MarfTrieId> {
    storage: TrieStorageTransaction<'a, T>,
    open_chain_tip: &'a mut Option<WriteChainTip<T>>,
    read_cursor: &'a mut Option<TrieCursor<T>>,
    read_state: &'a mut MarfReadState,
}

pub struct MarfReadCtx<'a, T: MarfTrieId, S: TrieNodeReadState, R: TrieReadStorage<T> + ?Sized> {
    storage: &'a mut R,
    read_cursor: &'a mut Option<TrieCursor<T>>,
    read_state: &'a mut S,
}

pub trait MarfCore<T: MarfTrieId> {
    type ReadStorage<'a>: TrieReadStorage<T> + ?Sized
    where
        Self: 'a;
    type ReadState: TrieNodeReadState;

    fn with_storage<'a, F, Ret>(&'a mut self, exec: F) -> Ret
    where
        F: FnOnce(&mut Self::ReadStorage<'a>) -> Ret;

    fn with_read_ctx<'a, F, Ret>(&'a mut self, exec: F) -> Ret
    where
        F: for<'ctx> FnOnce(
            &mut MarfReadCtx<'ctx, T, Self::ReadState, Self::ReadStorage<'a>>,
        ) -> Ret;
}

fn with_read_storage_read_ctx<'ctx, T, S, R, F, Ret>(
    storage: &'ctx mut R,
    cursor: &'ctx mut Option<TrieCursor<T>>,
    read_state: &'ctx mut S,
    exec: F,
) -> Ret
where
    T: MarfTrieId,
    S: TrieNodeReadState,
    R: TrieReadStorage<T> + ?Sized,
    F: FnOnce(&mut MarfReadCtx<'ctx, T, S, R>) -> Ret,
{
    let mut read_ctx = MarfReadCtx::<T, S, R>::new(storage, cursor, read_state);
    exec(&mut read_ctx)
}

pub trait MarfInternals<T: MarfTrieId>: MarfCore<T> {
    /// Hard cap on the number of times a read entry point will retry after observing an
    /// internal [`Error::RetryAfterSquash`] before returning a fatal `CorruptionError`.
    /// Squashes are infrequent relative to reads, so exceeding a handful of retries
    /// indicates pathological churn — at which point failing fast is preferable to a
    /// silent livelock.
    const MAX_READ_RETRIES: usize = 16;

    /// Bounded retry wrapper for read entry points. Re-invokes `exec` up to
    /// [`MAX_READ_RETRIES`](Self::MAX_READ_RETRIES) times, resetting per-traversal state
    /// between attempts so each retry runs against fresh squash metadata with no
    /// inherited cursor / parked-node state.
    ///
    /// See [`Error::RetryAfterSquash`] for the protocol and why every public read entry
    /// point MUST be wrapped in this helper — otherwise the internal sentinel would leak
    /// into user code.
    fn with_read_retry<F, R>(&mut self, mut exec: F) -> Result<R, Error>
    where
        F: FnMut(&mut Self) -> Result<R, Error>,
    {
        for attempt in 0..Self::MAX_READ_RETRIES {
            match exec(self) {
                Ok(v) => return Ok(v),
                Err(ref e) if e.is_retry_after_squash() => {
                    self.reset_read_state_for_retry()?;
                    if attempt >= 3 {
                        warn!(
                            "MARF read retry attempt {}/{} after concurrent squash",
                            attempt + 1,
                            Self::MAX_READ_RETRIES,
                        );
                    }
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        error!(
            "MARF read retry exhausted after {} attempts — persistent squash churn",
            Self::MAX_READ_RETRIES
        );
        Err(Error::CorruptionError(format!(
            "squash-retry-exhausted after {} attempts",
            Self::MAX_READ_RETRIES,
        )))
    }

    /// Reset per-traversal state between retry attempts. Refreshes squash metadata on the
    /// storage backend, drops any parked nodes / current-node scratch, and clears the walk
    /// cursor so a fresh traversal starts from the re-synced root.
    fn reset_read_state_for_retry(&mut self) -> Result<(), Error> {
        self.with_read_ctx(|ctx| {
            ctx.with_read_state(|storage, cursor, read_state| {
                storage.refresh_after_concurrent_squash()?;
                read_state.clear_parked_nodes();
                read_state.clear_current_node();
                *cursor = None;
                Ok(())
            })
        })
    }

    fn get_path(&mut self, block_hash: &T, path: &TrieHash) -> Result<Option<TrieLeaf>, Error> {
        self.with_read_ctx(|ctx| {
            ctx.get_path(block_hash, path).inspect_err(|_e| {
                trace!("Failed to look up key {block_hash:?} {path:?}: {_e:?}");
            })
        })
    }

    /// Open the MARF's storage to a given block, optionally with a specific block ID.
    fn open_block(&mut self, bhh: &T, block_id: Option<u32>) -> Result<(), Error> {
        self.with_read_ctx(|ctx| ctx.open_block(bhh, block_id))
    }

    fn with_restored_block_context<F, R>(&mut self, exec: F) -> Result<R, Error>
    where
        F: FnOnce(&mut Self) -> Result<R, Error>,
        R: core::fmt::Debug,
    {
        let block_ctx = self.with_read_ctx(|ctx| ctx.storage().get_cur_block_and_id());

        let result = exec(self);

        // Restore the original block context, in case exec changed it.
        self.with_read_ctx(|ctx| ctx.storage().open_block_maybe_id(&block_ctx.0, block_ctx.1))
            .inspect_err(|_| {
                warn!("Result of exec with changed block context: {result:?}");
            })?;

        result
    }

    fn get_by_path(&mut self, block_hash: &T, path: &TrieHash) -> Result<Option<MARFValue>, Error> {
        self.with_read_retry(|this| {
            this.with_restored_block_context(|this| {
                this.get_path(block_hash, path)
                    .or_else(|e| match e {
                        Error::NotFoundError => Ok(None),
                        _ => Err(e),
                    })
                    .map(|opt| opt.map(|leaf| leaf.data))
            })
        })
    }

    fn get_by_key(&mut self, block_hash: &T, key: &str) -> Result<Option<MARFValue>, Error> {
        let path = TrieHash::from_key(key);
        self.with_read_retry(|this| {
            this.with_restored_block_context(|this| {
                this.get_path(block_hash, &path)
                    .or_else(|e| match e {
                        Error::NotFoundError => Ok(None),
                        other => Err(other),
                    })
                    .map(|opt| opt.map(|leaf| leaf.data))
            })
        })
    }

    fn prove_path(
        &mut self,
        block_hash: &T,
        path: &TrieHash,
        marf_value: &MARFValue,
    ) -> Result<TrieMerkleProof<T>, Error> {
        self.with_read_retry(|this| {
            this.with_read_ctx(|ctx| TrieMerkleProof::from_path(ctx, path, marf_value, block_hash))
        })
    }

    fn prove_raw_entry(
        &mut self,
        block_hash: &T,
        key: &str,
        marf_value: &MARFValue,
    ) -> Result<TrieMerkleProof<T>, Error> {
        self.with_read_retry(|this| {
            this.with_read_ctx(|ctx| {
                let path = &TrieHash::from_key(key);
                TrieMerkleProof::from_path(ctx, path, marf_value, block_hash)
            })
        })
    }

    fn get_block_height_miner_tip(
        &mut self,
        block_hash: &T,
        current_block_hash: &T,
    ) -> Result<Option<u32>, Error> {
        self.with_read_retry(|this| {
            this.with_read_ctx(|ctx| ctx.get_block_height_miner_tip(block_hash, current_block_hash))
        })
    }

    fn get_block_height(
        &mut self,
        block_hash: &T,
        current_block_hash: &T,
    ) -> Result<Option<u32>, Error> {
        self.with_read_retry(|this| {
            this.with_read_ctx(|ctx| ctx.get_block_height(block_hash, current_block_hash))
        })
    }

    fn get_block_at_height(
        &mut self,
        height: u32,
        current_block_hash: &T,
    ) -> Result<Option<T>, Error> {
        self.with_read_retry(|this| {
            this.with_read_ctx(|ctx| ctx.get_block_at_height(height, current_block_hash))
        })
    }
}

impl<T: MarfTrieId, U: MarfCore<T> + ?Sized> MarfInternals<T> for U {}

impl<'ctx, T: MarfTrieId, S: TrieNodeReadState, R: TrieReadStorage<T> + ?Sized> MarfCore<T>
    for MarfReadCtx<'ctx, T, S, R>
{
    type ReadStorage<'a>
        = R
    where
        Self: 'a;
    type ReadState = S;

    fn with_storage<'a, F, Ret>(&'a mut self, exec: F) -> Ret
    where
        F: FnOnce(&mut Self::ReadStorage<'a>) -> Ret,
    {
        exec(self.storage)
    }

    fn with_read_ctx<'a, F, Ret>(&'a mut self, exec: F) -> Ret
    where
        F: for<'read> FnOnce(&mut MarfReadCtx<'read, T, S, Self::ReadStorage<'a>>) -> Ret,
    {
        exec(self)
    }
}

impl<T: MarfTrieId> MarfCore<T> for MARF<T> {
    type ReadStorage<'a>
        = TrieStorageConnection<'a, T>
    where
        Self: 'a;
    type ReadState = MarfReadState;

    fn with_storage<'a, F, Ret>(&'a mut self, exec: F) -> Ret
    where
        F: FnOnce(&mut Self::ReadStorage<'a>) -> Ret,
    {
        let mut conn = self.storage.connection();
        exec(&mut conn)
    }

    fn with_read_ctx<'a, F, Ret>(&'a mut self, exec: F) -> Ret
    where
        F: for<'ctx> FnOnce(
            &mut MarfReadCtx<'ctx, T, Self::ReadState, Self::ReadStorage<'a>>,
        ) -> Ret,
    {
        let mut conn = self.storage.connection();
        with_read_storage_read_ctx(&mut conn, &mut self.read_cursor, &mut self.read_state, exec)
    }
}

impl<'tx, T: MarfTrieId> MarfCore<T> for MarfTransaction<'tx, T> {
    type ReadStorage<'a>
        = TrieStorageConnection<'tx, T, Transaction<'tx>>
    where
        Self: 'a;
    type ReadState = MarfReadState;

    fn with_storage<'a, F, Ret>(&'a mut self, exec: F) -> Ret
    where
        F: FnOnce(&mut Self::ReadStorage<'a>) -> Ret,
    {
        exec(&mut self.storage)
    }

    fn with_read_ctx<'a, F, Ret>(&'a mut self, exec: F) -> Ret
    where
        F: for<'ctx> FnOnce(
            &mut MarfReadCtx<'ctx, T, Self::ReadState, Self::ReadStorage<'a>>,
        ) -> Ret,
    {
        with_read_storage_read_ctx(
            &mut self.storage,
            &mut self.read_cursor,
            &mut *self.read_state,
            exec,
        )
    }
}

impl<'conn, T: MarfTrieId> MarfCore<T> for ReopenedTrieStorageConnection<'conn, T> {
    type ReadStorage<'a>
        = TrieStorageConnection<'a, T>
    where
        Self: 'a;
    type ReadState = MarfReadState;

    fn with_storage<'a, F, Ret>(&'a mut self, exec: F) -> Ret
    where
        F: FnOnce(&mut Self::ReadStorage<'a>) -> Ret,
    {
        let mut conn = self.connection();
        exec(&mut conn)
    }

    fn with_read_ctx<'a, F, Ret>(&'a mut self, exec: F) -> Ret
    where
        F: for<'ctx> FnOnce(
            &mut MarfReadCtx<'ctx, T, Self::ReadState, Self::ReadStorage<'a>>,
        ) -> Ret,
    {
        let mut conn = self.connection();
        let mut read_cursor = None;
        let mut read_state = MarfReadState::new();
        with_read_storage_read_ctx(&mut conn, &mut read_cursor, &mut read_state, exec)
    }
}

#[derive(Clone)]
struct WriteChainTip<T> {
    block_hash: T,
    height: u32,
}

/// Options for opening a MARF
#[derive(Debug, PartialEq, Clone)]
pub struct MARFOpenOpts {
    /// Hash calculation mode for calculating a trie root hash
    pub hash_calculation_mode: TrieHashCalculationMode,
    /// Cache strategy to use
    pub cache_strategy: String,
    /// store trie blobs externally from the DB, in a flat file
    pub external_blobs: bool,
    /// unconditionally do a DB migration (used for testing)
    pub force_db_migrate: bool,
    /// compress the MARF
    pub compress: bool,
    /// use memory-mapped I/O for reading trie blobs
    pub mmap: bool,
    /// Squash mode preference. `TipOnly` stores only tip-era values;
    /// `FullHistory` preserves per-key value-transition history for
    /// historical reads. The effective mode may be upgraded to
    /// `FullHistory` for pre-epoch-3.4 squash ranges regardless of
    /// this setting.
    pub squash_mode: SquashMode,
}

impl MARFOpenOpts {
    pub fn default() -> MARFOpenOpts {
        MARFOpenOpts {
            hash_calculation_mode: TrieHashCalculationMode::Deferred,
            cache_strategy: "noop".to_string(),
            external_blobs: false,
            force_db_migrate: false,
            compress: false,
            mmap: false,
            squash_mode: SquashMode::TipOnly,
        }
    }

    pub fn new(
        hash_calculation_mode: TrieHashCalculationMode,
        cache_strategy: &str,
        external_blobs: bool,
    ) -> MARFOpenOpts {
        MARFOpenOpts {
            hash_calculation_mode,
            cache_strategy: cache_strategy.to_string(),
            external_blobs,
            force_db_migrate: false,
            compress: false,
            mmap: false,
            squash_mode: SquashMode::TipOnly,
        }
    }

    pub fn with_compression(mut self, compression: bool) -> Self {
        self.compress = compression;
        self
    }

    pub fn with_mmap(mut self, mmap: bool) -> Self {
        self.mmap = mmap;
        self
    }

    pub fn with_squash_mode(mut self, mode: SquashMode) -> Self {
        self.squash_mode = mode;
        self
    }
}

///
/// This trait defines functions that are defined for both
///  MARF structs and MarfTransactions
///
pub trait MarfConnection<T: MarfTrieId>: MarfInternals<T> + Sized {
    fn sqlite_conn(&self) -> &Connection;

    /// Get and check a value against get_from_hash
    /// (test only)
    ///
    /// This helper runs two *unwrapped* reads inside a single fresh `with_read_ctx`,
    /// bypassing `MarfInternals::with_read_retry`. That is deliberate for the cross-check
    /// itself (we want to compare raw walk results), but it means any retry-wrapper
    /// regression test that exercises injected-fault behavior via [`Self::get`] will have
    /// counter credits consumed here before the wrapped entry point fires. New retry
    /// regressions should call `MarfInternals::get_by_key` / `get_by_path` directly to
    /// avoid that interaction — see `test_tier8_*` / `test_tier9_*` in
    /// `index/test/squash.rs` for the pattern.
    #[cfg(test)]
    fn get_and_check_with_hash(&mut self, block_hash: &T, key: &str) {
        let trie_hash = TrieHash::from_key(key);
        let (leaf, leaf_with_hash) = self.with_read_ctx(|ctx| {
            let leaf = ctx.get_by_key(block_hash, key);
            let leaf_with_hash = ctx.get_by_path(block_hash, &trie_hash);
            (leaf, leaf_with_hash)
        });

        match (&leaf, &leaf_with_hash) {
            (Ok(Some(x)), Ok(Some(y))) => assert_eq!(x, y),
            (Ok(None), Ok(None)) => {}
            (Err(_), Err(_)) => {}
            // A concurrent squash on another handle may land between the two reads above,
            // so only one side sees the internal `RetryAfterSquash` sentinel. The outer
            // `get()` retry wrapper handles that for the real call; skip the consistency
            // cross-check rather than panic on the race.
            (Err(e), _) | (_, Err(e)) if e.is_retry_after_squash() => {}
            (x, y) => {
                panic!("Inconsistency: {x:?} != {y:?}");
            }
        }
    }

    #[cfg(not(test))]
    fn get_and_check_with_hash(&mut self, _block_hash: &T, _key: &str) {}

    /// Resolve a key from the MARF to a MARFValue with respect to the given block height.
    fn get(&mut self, block_hash: &T, key: &str) -> Result<Option<MARFValue>, Error> {
        self.get_and_check_with_hash(block_hash, key);
        <Self as MarfInternals<T>>::get_by_key(self, block_hash, key)
    }

    /// Resolve a TrieHash from the MARF to a MARFValue with respect to the given block height.
    fn get_from_hash(&mut self, block_hash: &T, th: &TrieHash) -> Result<Option<MARFValue>, Error> {
        <Self as MarfInternals<T>>::get_by_path(self, block_hash, th)
    }

    fn get_with_proof(
        &mut self,
        block_hash: &T,
        key: &str,
    ) -> Result<Option<(MARFValue, TrieMerkleProof<T>)>, Error> {
        let marf_value = match <Self as MarfInternals<T>>::get_by_key(self, block_hash, key)? {
            None => return Ok(None),
            Some(x) => x,
        };
        let proof =
            <Self as MarfInternals<T>>::prove_raw_entry(self, block_hash, key, &marf_value)?;
        Ok(Some((marf_value, proof)))
    }

    fn get_with_proof_from_hash(
        &mut self,
        block_hash: &T,
        hash: &TrieHash,
    ) -> Result<Option<(MARFValue, TrieMerkleProof<T>)>, Error> {
        let marf_value = match <Self as MarfInternals<T>>::get_by_path(self, block_hash, hash)? {
            None => return Ok(None),
            Some(x) => x,
        };
        let proof = <Self as MarfInternals<T>>::prove_path(self, block_hash, hash, &marf_value)?;
        Ok(Some((marf_value, proof)))
    }

    fn get_block_at_height(&mut self, height: u32, tip: &T) -> Result<Option<T>, Error> {
        <Self as MarfInternals<T>>::get_block_at_height(self, height, tip)
    }

    fn get_block_height(&mut self, ancestor: &T, tip: &T) -> Result<Option<u32>, Error> {
        <Self as MarfInternals<T>>::get_block_height(self, ancestor, tip)
    }

    /// Get the root trie hash at a particular block
    fn get_root_hash_at(&mut self, block_hash: &T) -> Result<TrieHash, Error> {
        self.with_read_retry(|this| {
            this.with_read_ctx(|ctx| {
                let (cur_block_hash, cur_block_id) = ctx.storage().get_cur_block_and_id();
                ctx.open_block(block_hash, None)?;
                let root_ptr = ctx.storage().root_trieptr();
                let root_hash = ctx.storage().read_node_hash(&root_ptr);
                ctx.storage()
                    .open_block_maybe_id(&cur_block_hash, cur_block_id)?;
                root_hash
            })
        })
    }

    /// Check if a block can open successfully, i.e.,
    ///   it's a known block, the storage system isn't issueing IOErrors, _and_ it's in the same fork
    ///   as the current block
    /// The MARF _must_ be open to a valid block for this check to be evaluated.
    fn check_ancestor_block_hash(&mut self, bhh: &T) -> Result<(), Error> {
        self.with_read_retry(|this| {
            this.with_read_ctx(|ctx| {
                let cur_block_hash = ctx.storage().get_cur_block();
                if cur_block_hash == *bhh {
                    // a block is in its own fork
                    return Ok(());
                }

                let bhh_height = ctx
                    .get_block_height(bhh, &cur_block_hash)?
                    .ok_or_else(|| {
                        Error::NonMatchingForks(bhh.clone().to_bytes(), cur_block_hash.clone().to_bytes())
                    })?;

                let actual_block_at_height = ctx
                    .get_block_at_height(bhh_height, &cur_block_hash)?
                    .ok_or_else(|| Error::CorruptionError(format!(
                        "ERROR: Could not find block for height {}, but it was returned by MARF::get_block_height()", bhh_height)))?;

                if bhh != &actual_block_at_height {
                    test_debug!("non-matching forks: {} != {}", bhh, &actual_block_at_height);
                    return Err(Error::NonMatchingForks(
                        bhh.clone().to_bytes(),
                        cur_block_hash.to_bytes(),
                    ));
                }

                // test open
                let result = ctx.storage().open_block(bhh);

                // restore
                ctx
                    .storage()
                    .open_block(&cur_block_hash)
                    .map_err(|e| Error::RestoreMarfBlockError(Box::new(e)))?;

                result
            })
        })
    }
}

impl<T: MarfTrieId> MarfConnection<T> for MarfTransaction<'_, T> {
    fn sqlite_conn(&self) -> &Connection {
        self.storage.sqlite_tx()
    }
}

impl<T: MarfTrieId> ReopenedTrieStorageConnection<'_, T> {
    pub fn get(&mut self, block_hash: &T, key: &str) -> Result<Option<MARFValue>, Error> {
        // Delegate to the `MarfInternals` default impl, which wraps reads in the
        // bounded `with_read_retry` loop that absorbs the internal
        // `Error::RetryAfterSquash` sentinel from concurrent squashes.
        <Self as MarfInternals<T>>::get_by_key(self, block_hash, key)
    }

    pub fn get_from_hash(
        &mut self,
        block_hash: &T,
        hash: &TrieHash,
    ) -> Result<Option<MARFValue>, Error> {
        <Self as MarfInternals<T>>::get_by_path(self, block_hash, hash)
    }

    pub fn get_with_proof(
        &mut self,
        block_hash: &T,
        key: &str,
    ) -> Result<Option<(MARFValue, TrieMerkleProof<T>)>, Error> {
        let marf_value = match self.get(block_hash, key)? {
            None => return Ok(None),
            Some(x) => x,
        };
        let proof =
            <Self as MarfInternals<T>>::prove_raw_entry(self, block_hash, key, &marf_value)?;
        Ok(Some((marf_value, proof)))
    }

    pub fn get_with_proof_from_hash(
        &mut self,
        block_hash: &T,
        hash: &TrieHash,
    ) -> Result<Option<(MARFValue, TrieMerkleProof<T>)>, Error> {
        let marf_value = match self.get_from_hash(block_hash, hash)? {
            None => return Ok(None),
            Some(x) => x,
        };
        let proof = <Self as MarfInternals<T>>::prove_path(self, block_hash, hash, &marf_value)?;
        Ok(Some((marf_value, proof)))
    }

    pub fn get_block_at_height(&mut self, height: u32, tip: &T) -> Result<Option<T>, Error> {
        <Self as MarfInternals<T>>::get_block_at_height(self, height, tip)
    }

    pub fn get_block_height(&mut self, ancestor: &T, tip: &T) -> Result<Option<u32>, Error> {
        <Self as MarfInternals<T>>::get_block_height(self, ancestor, tip)
    }
}

impl<T: MarfTrieId> MarfConnection<T> for ReopenedTrieStorageConnection<'_, T> {
    fn sqlite_conn(&self) -> &Connection {
        self.db_conn()
    }
}

impl<T: MarfTrieId> MarfConnection<T> for MARF<T> {
    fn sqlite_conn(&self) -> &Connection {
        self.storage.sqlite_conn()
    }

    fn get_with_proof(
        &mut self,
        block_hash: &T,
        key: &str,
    ) -> Result<Option<(MARFValue, TrieMerkleProof<T>)>, Error> {
        // Check if the target block is within a squash range
        if self.is_in_squash_range(block_hash) {
            return Err(Error::NotSupportedError(
                "Merkle proofs not supported for blocks within squash range".into(),
            ));
        }
        // Delegate to default implementation
        let marf_value = match <Self as MarfInternals<T>>::get_by_key(self, block_hash, key)? {
            None => return Ok(None),
            Some(x) => x,
        };
        let proof =
            <Self as MarfInternals<T>>::prove_raw_entry(self, block_hash, key, &marf_value)?;
        Ok(Some((marf_value, proof)))
    }

    fn get_with_proof_from_hash(
        &mut self,
        block_hash: &T,
        hash: &TrieHash,
    ) -> Result<Option<(MARFValue, TrieMerkleProof<T>)>, Error> {
        if self.is_in_squash_range(block_hash) {
            return Err(Error::NotSupportedError(
                "Merkle proofs not supported for blocks within squash range".into(),
            ));
        }
        let marf_value = match <Self as MarfInternals<T>>::get_by_path(self, block_hash, hash)? {
            None => return Ok(None),
            Some(x) => x,
        };
        let proof = <Self as MarfInternals<T>>::prove_path(self, block_hash, hash, &marf_value)?;
        Ok(Some((marf_value, proof)))
    }
}

impl<'a, T: MarfTrieId, S: TrieNodeReadState, R: TrieReadStorage<T> + ?Sized>
    MarfReadCtx<'a, T, S, R>
{
    pub fn new(
        storage: &'a mut R,
        cursor: &'a mut Option<TrieCursor<T>>,
        scratch: &'a mut S,
    ) -> Self {
        Self {
            storage,
            read_cursor: cursor,
            read_state: scratch,
        }
    }

    pub fn storage(&mut self) -> &mut R {
        self.storage
    }

    pub fn read_node(&mut self, ptr: &TriePtr) -> Result<ReadTrieNode<'_>, Error> {
        self.storage.read_node_with_state(ptr, self.read_state)
    }

    pub fn with_read_state<F, Ret>(&mut self, exec: F) -> Ret
    where
        F: FnOnce(&mut R, &mut Option<TrieCursor<T>>, &mut S) -> Ret,
    {
        exec(self.storage, self.read_cursor, self.read_state)
    }

    fn with_preserved_read_cursor<F, Ret>(&mut self, exec: F) -> Ret
    where
        F: FnOnce(&mut Self) -> Ret,
    {
        let saved_cursor = self.read_cursor.take();
        let result = exec(self);
        *self.read_cursor = saved_cursor;
        result
    }

    fn with_restored_block_context<F, Ret>(&mut self, exec: F) -> Result<Ret, Error>
    where
        F: FnOnce(&mut Self) -> Result<Ret, Error>,
    {
        let block_ctx = self.storage.get_cur_block_and_id();
        let result = exec(self);

        self.storage
            .open_block_maybe_id(&block_ctx.0, block_ctx.1)
            .inspect_err(|e| {
                warn!(
                    "Failed to restore original block context {} {:?}: {e:?}",
                    block_ctx.0, block_ctx.1
                );
            })?;

        result
    }

    pub fn open_block(&mut self, bhh: &T, block_id: Option<u32>) -> Result<(), Error> {
        self.storage.open_block_maybe_id(bhh, block_id)
    }

    pub fn get_path(&mut self, block_hash: &T, path: &TrieHash) -> Result<Option<TrieLeaf>, Error> {
        MARF::walk(self, block_hash, path)
            .inspect_err(|_e| {
                trace!("Failed to look up key {block_hash:?} {path:?}: {_e:?}");
            })
            .map(Some)
    }

    pub fn get_by_path(
        &mut self,
        block_hash: &T,
        path: &TrieHash,
    ) -> Result<Option<MARFValue>, Error> {
        self.with_restored_block_context(|this| {
            this.get_path(block_hash, path)
                .or_else(|e| match e {
                    Error::NotFoundError => Ok(None),
                    _ => Err(e),
                })
                .map(|opt| opt.map(|leaf| leaf.data))
        })
    }

    pub fn get_by_key(&mut self, block_hash: &T, key: &str) -> Result<Option<MARFValue>, Error> {
        let path = TrieHash::from_key(key);
        self.with_restored_block_context(|this| {
            this.get_path(block_hash, &path)
                .or_else(|e| match e {
                    Error::NotFoundError => Ok(None),
                    other => Err(other),
                })
                .map(|opt| opt.map(|leaf| leaf.data))
        })
    }

    pub fn get_block_height_miner_tip(
        &mut self,
        block_hash: &T,
        current_block_hash: &T,
    ) -> Result<Option<u32>, Error> {
        self.with_preserved_read_cursor(|this| {
            let hash_key = format!("{BLOCK_HASH_TO_HEIGHT_MAPPING_KEY}::{block_hash}");
            #[cfg(test)]
            {
                let test_genesis_block = this.storage().test_genesis_block();
                if test_genesis_block.as_ref() == Some(current_block_hash) {
                    return Ok(Some(0));
                }
            }

            // In-squash override for self-lookup of `OWN_BLOCK_HEIGHT_KEY`.
            //
            // The squash blob is a single MERGED tip trie shared by every block in the
            // squash range. There is exactly one leaf per path, so reading
            // `OWN_BLOCK_HEIGHT_KEY` from any in-squash block returns the SQUASH TIP's
            // height (the value from the highest-height block in the range), not the
            // requested block's per-block height.
            //
            // Without this override, a fork extending a non-tip squashed block (e.g.
            // canonical_810 inside a 0..=1000 squash) would compute
            // `new_block_height = squash_tip + 1 = 1001` instead of `parent + 1 = 811`.
            // The wrong height then propagates into `set_block_heights`, into the
            // sealed MARF root via `get_trie_ancestor_hashes_bytes`, and panics when
            // a `value_at_height(parent_height_810)` lookup misses entries written at
            // heights {1000, 999}.
            //
            // The fix: read the per-block height from the squash trailer (via
            // `squash_opened_height()`) instead of the merged-trie lookup. The trailer
            // records the correct per-block height for every in-squash block.
            //
            // Filter: only apply when `cur_block_id` is `Some(_)` after open. That
            // distinguishes a true in-squash block (case we want) from an uncommitted
            // block whose parent is in-squash (Tier 10 sets `squash_opened_height` to
            // the *parent's* height in that case, which is NOT this block's height —
            // its TrieRAM has the correct value via the regular lookup below).
            if block_hash == current_block_hash {
                let in_squash_height = this.with_restored_block_context(|this| {
                    this.open_block(current_block_hash, None)?;
                    let storage = this.storage();
                    let cur_block_id = storage.get_cur_block_and_id().1;
                    Ok(if cur_block_id.is_some() {
                        storage.squash_opened_height()
                    } else {
                        None
                    })
                })?;
                if let Some(h) = in_squash_height {
                    return Ok(Some(h));
                }
            }

            let marf_value = if block_hash == current_block_hash {
                this.get_by_key(current_block_hash, OWN_BLOCK_HEIGHT_KEY)?
            } else {
                this.get_by_key(current_block_hash, &hash_key)?
            };

            Ok(marf_value.map(u32::from))
        })
    }

    pub fn get_block_height(
        &mut self,
        block_hash: &T,
        current_block_hash: &T,
    ) -> Result<Option<u32>, Error> {
        self.get_block_height_miner_tip(block_hash, current_block_hash)
    }

    pub fn get_block_at_height(
        &mut self,
        height: u32,
        current_block_hash: &T,
    ) -> Result<Option<T>, Error> {
        self.with_preserved_read_cursor(|this| {
            #[cfg(test)]
            if height == 0 {
                let test_genesis_block = this.storage().test_genesis_block();
                if let Some(s) = test_genesis_block {
                    return Ok(Some(s));
                }
            }

            let current_block_height = match this
                .get_block_height(current_block_hash, current_block_hash)?
            {
                Some(x) => x,
                None => {
                    error!(
                            "Could not fetch block height for {current_block_hash}, likely not a known block",
                        );
                    return Ok(None);
                }
            };

            if height == current_block_height {
                return Ok(Some(current_block_hash.clone()));
            }

            let height_key = format!("{BLOCK_HEIGHT_TO_HASH_MAPPING_KEY}::{height}");

            this.get_by_key(current_block_hash, &height_key)
                .map(|option_result| option_result.map(T::from))
        })
    }

    pub fn get_trie_ancestor_hashes_bytes(&mut self) -> Result<Vec<TrieHash>, Error> {
        self.with_read_state(|storage, cursor_opt, decode_scratch| {
            Trie::get_trie_ancestor_hashes_bytes(storage, cursor_opt, decode_scratch)
        })
    }
}

#[cfg(test)]
impl<'a, 'conn, T: MarfTrieId, Db: Deref<Target = Connection>>
    MarfReadCtx<'a, T, MarfReadState, TrieStorageConnection<'conn, T, Db>>
{
    pub fn with_ephemeral<F, R>(storage: &'a mut TrieStorageConnection<'conn, T, Db>, exec: F) -> R
    where
        F: for<'ephemeral> FnOnce(
            &mut MarfReadCtx<'ephemeral, T, MarfReadState, TrieStorageConnection<'conn, T, Db>>,
        ) -> R,
    {
        let mut cursor = None;
        let mut scratch = MarfReadState::new();
        let mut ephemeral_ctx = MarfReadCtx::new(storage, &mut cursor, &mut scratch);
        exec(&mut ephemeral_ctx)
    }
}

///
/// MarfTransaction represents a connection to a MARF index,
///   with an open storage transaction. If this struct is
///   dropped without calling commit(), the storage transaction is
///   aborted
///
impl<'a, T: MarfTrieId> MarfTransaction<'a, T> {
    pub fn commit(mut self) -> Result<(), Error> {
        if self.storage.readonly() {
            return Err(Error::ReadOnlyError);
        }
        if let Some(_tip) = self.open_chain_tip.take() {
            self.storage.flush()?;
        }
        self.storage.commit_tx();
        Ok(())
    }

    /// Finish writing the next trie in the MARF, but change the hash of the current Trie's
    /// block hash to something other than what we opened it as.  This persists all changes.
    pub fn commit_to(mut self, real_bhh: &T) -> Result<(), Error> {
        if self.storage.readonly() {
            return Err(Error::ReadOnlyError);
        }
        if self.storage.unconfirmed() {
            return Err(Error::UnconfirmedError);
        }
        if let Some(_tip) = self.open_chain_tip.take() {
            self.storage.flush_to(real_bhh)?;
            self.storage.commit_tx();
        }
        Ok(())
    }

    /// Finish writing the next trie in the MARF -- this is used by miners
    ///   to commit the mined block, but write it to the mined_block table,
    ///   rather than out to the marf_data table (this prevents the
    ///   miner's block from getting stepped on after the sortition).
    pub fn commit_mined(mut self, bhh: &T) -> Result<(), Error> {
        if self.storage.readonly() {
            return Err(Error::ReadOnlyError);
        }
        if self.storage.unconfirmed() {
            return Err(Error::UnconfirmedError);
        }
        if let Some(_tip) = self.open_chain_tip.take() {
            self.storage.flush_mined(bhh)?;
            self.storage.commit_tx();
        }
        Ok(())
    }

    pub fn get_open_chain_tip(&self) -> Option<&T> {
        self.open_chain_tip.as_ref().map(|tip| &tip.block_hash)
    }

    pub fn get_open_chain_tip_height(&self) -> Option<u32> {
        self.open_chain_tip.as_ref().map(|tip| tip.height)
    }

    pub fn get_block_height_of(
        &mut self,
        bhh: &T,
        current_block_hash: &T,
    ) -> Result<Option<u32>, Error> {
        if Some(bhh) == self.get_open_chain_tip() {
            return Ok(self.get_open_chain_tip_height());
        } else {
            <Self as MarfInternals<T>>::get_block_height_miner_tip(self, bhh, current_block_hash)
        }
    }

    #[cfg(test)]
    fn commit_tx(self) {
        self.storage.commit_tx()
    }

    pub fn sqlite_tx(&self) -> &Transaction<'a> {
        self.storage.sqlite_tx()
    }

    pub fn sqlite_tx_mut(&mut self) -> &mut Transaction<'a> {
        self.storage.sqlite_tx_mut()
    }

    /// Reopen this MARF transaction with readonly storage.
    ///   NOTE: any pending operations in the SQLite transaction _will not_
    ///         have materialized in the reopened view.
    pub fn reopen_readonly(&self) -> Result<MARF<T>, Error> {
        if self.open_chain_tip.is_some() {
            error!(
                "MARF at {} is already in the process of writing",
                &self.storage.db_path
            );
            return Err(Error::InProgressError);
        }

        let ro_storage = self.storage.reopen_readonly()?;
        Ok(MARF {
            storage: ro_storage,
            open_chain_tip: None,
            read_cursor: None,
            read_state: MarfReadState::new(),
        })
    }

    /// Begin writing the next trie in the MARF, given the block header hash that will contain the
    /// associated block's new state.  Call commit() or commit_to() to persist the changes.
    /// Fails if the block already exists.
    /// Storage will point to new chain tip on success.
    pub fn begin(&mut self, chain_tip: &T, next_chain_tip: &T) -> Result<(), Error> {
        if self.storage.readonly() {
            return Err(Error::ReadOnlyError);
        }
        if self.open_chain_tip.is_some() {
            error!(
                "MARF at {} is already in the process of writing",
                &self.storage.db_path
            );
            return Err(Error::InProgressError);
        }
        if self.storage.has_block(next_chain_tip)? {
            error!("Block data already exists: {}", next_chain_tip);
            return Err(Error::ExistsError);
        }

        let block_height = self.inner_get_extension_height(chain_tip, next_chain_tip)?;
        MARF::extend_trie(&mut self.storage, next_chain_tip, self.read_state)?;
        self.inner_setup_extension(chain_tip, next_chain_tip, block_height, true)
    }

    /// Set up the trie extension we're making.
    /// Sets storage pointer to chain_tip.
    /// Returns the height next_chain_tip would be at.
    fn inner_get_extension_height(
        &mut self,
        chain_tip: &T,
        next_chain_tip: &T,
    ) -> Result<u32, Error> {
        // current chain tip must exist if it's not the "sentinel"
        let is_parent_sentinel = chain_tip == &T::sentinel();
        if !is_parent_sentinel {
            debug!("Extending off of existing node {}", chain_tip);
        } else {
            debug!("First-ever block {}", next_chain_tip; "block" => %next_chain_tip);
        }

        self.storage.open_block(chain_tip)?;

        let block_height = if !is_parent_sentinel {
            let height =
                <Self as MarfInternals<T>>::get_block_height_miner_tip(self, chain_tip, chain_tip)?
                    .ok_or(Error::CorruptionError(format!(
                        "Failed to find block height for `{:?}`",
                        chain_tip
                    )))?;
            height
                .checked_add(1)
                .expect("FATAL: block height overflow!")
        } else {
            0
        };

        Ok(block_height)
    }

    /// Set up a new extension.
    /// Opens storage to chain_tip/
    fn inner_setup_extension(
        &mut self,
        chain_tip: &T,
        next_chain_tip: &T,
        block_height: u32,
        new_extension: bool,
    ) -> Result<(), Error> {
        self.storage.open_block(next_chain_tip)?;
        self.open_chain_tip.replace(WriteChainTip {
            block_hash: next_chain_tip.clone(),
            height: block_height,
        });

        if new_extension {
            self.set_block_heights(chain_tip, next_chain_tip, block_height)
                .inspect_err(|_e| {
                    self.open_chain_tip.take();
                })?;
        }

        debug!("Opened {chain_tip} to {next_chain_tip}");
        Ok(())
    }

    pub fn set_block_heights(
        &mut self,
        block_hash: &T,
        next_block_hash: &T,
        height: u32,
    ) -> Result<(), Error> {
        if self.storage.readonly() {
            return Err(Error::ReadOnlyError);
        }
        let mut keys = vec![];
        let mut values = vec![];

        let height_key = format!("{}::{}", BLOCK_HEIGHT_TO_HASH_MAPPING_KEY, height);
        let hash_key = format!("{}::{}", BLOCK_HASH_TO_HEIGHT_MAPPING_KEY, next_block_hash);

        debug!(
            "Set {}::{} = {}",
            BLOCK_HEIGHT_TO_HASH_MAPPING_KEY, height, next_block_hash
        );
        debug!(
            "Set {}::{} = {}",
            BLOCK_HASH_TO_HEIGHT_MAPPING_KEY, next_block_hash, height
        );
        debug!("Set {} = {}", OWN_BLOCK_HEIGHT_KEY, height);

        keys.push(OWN_BLOCK_HEIGHT_KEY.to_string());
        values.push(MARFValue::from(height));

        keys.push(height_key);
        values.push(MARFValue::from(next_block_hash.clone()));

        keys.push(hash_key);
        values.push(MARFValue::from(height));

        if height > 0 {
            let prev_height_key = format!("{}::{}", BLOCK_HEIGHT_TO_HASH_MAPPING_KEY, height - 1);
            let prev_hash_key = format!("{}::{}", BLOCK_HASH_TO_HEIGHT_MAPPING_KEY, block_hash);

            debug!(
                "Set {}::{} = {}",
                BLOCK_HEIGHT_TO_HASH_MAPPING_KEY,
                height - 1,
                block_hash
            );
            debug!(
                "Set {}::{} = {}",
                BLOCK_HASH_TO_HEIGHT_MAPPING_KEY,
                block_hash,
                height - 1
            );

            keys.push(prev_height_key);
            values.push(MARFValue::from(block_hash.clone()));

            keys.push(prev_hash_key);
            values.push(MARFValue::from(height - 1));
        }

        self.insert_batch(&keys, &values)?;
        Ok(())
    }

    /// Insert a batch of key/value pairs.  More efficient than inserting them individually, since
    /// the trie root hash will only be calculated once (which is an O(log B) operation).
    pub fn insert_batch(
        &mut self,
        keys: impl AsRef<[String]>,
        values: impl AsRef<[MARFValue]>,
    ) -> Result<(), Error> {
        let keys = keys.as_ref();
        let values = values.as_ref();

        if self.storage.readonly() {
            return Err(Error::ReadOnlyError);
        }
        assert_eq!(keys.len(), values.len());

        let block_hash = match self.open_chain_tip {
            None => Err(Error::WriteNotBegunError),
            Some(WriteChainTip { ref block_hash, .. }) => Ok(block_hash.clone()),
        }?;

        if keys.is_empty() {
            return Ok(());
        }

        MARF::inner_insert_batch(
            &mut self.storage,
            &block_hash,
            keys,
            values,
            self.read_state,
        )?;
        Ok(())
    }

    /// Begin extending the MARF to an unconfirmed trie. The resulting trie will have a block hash
    /// equal to `MARF::make_unconfirmed_chain_tip(chain_tip)` to avoid collision and block hash
    /// reuse.
    pub fn begin_unconfirmed(&mut self, chain_tip: &T) -> Result<T, Error> {
        if self.storage.readonly() {
            return Err(Error::ReadOnlyError);
        }
        if self.open_chain_tip.is_some() {
            error!(
                "MARF at {} is already in the process of writing",
                &self.storage.db_path
            );
            return Err(Error::InProgressError);
        }
        if !self.storage.unconfirmed() {
            return Err(Error::UnconfirmedError);
        }

        // chain_tip must exist and must be confirmed
        if !self.storage.has_confirmed_block(chain_tip)? {
            error!("No such confirmed block {}", chain_tip);
            return Err(Error::NotFoundError);
        }

        let unconfirmed_tip = MARF::make_unconfirmed_chain_tip(chain_tip);

        let block_height = self.inner_get_extension_height(chain_tip, &unconfirmed_tip)?;

        let created = self.storage.extend_to_unconfirmed_block(&unconfirmed_tip)?;
        if created {
            MARF::root_copy(&mut self.storage, chain_tip, self.read_state)?;
        }

        self.inner_setup_extension(chain_tip, &unconfirmed_tip, block_height, created)?;
        Ok(unconfirmed_tip)
    }

    /// Drop the current trie from the MARF. This rolls back all
    ///   changes in the block, and closes the current chain tip.
    pub fn drop_current(mut self) {
        if !self.storage.readonly() {
            self.storage.drop_extending_trie();
            self.open_chain_tip.take();
            self.storage
                .open_block(&T::sentinel())
                .expect("BUG: should never fail to open the block sentinel");
            self.storage.rollback()
        }
    }

    /// Drop the current trie from the MARF, and roll back all unconfirmed state
    pub fn drop_unconfirmed(mut self) {
        if !self.storage.readonly() && self.storage.unconfirmed() {
            if let Some(tip) = self.open_chain_tip.take() {
                trace!("Dropping unconfirmed trie {}", &tip.block_hash);
                self.storage.drop_unconfirmed_trie(&tip.block_hash);
                self.storage
                    .open_block(&T::sentinel())
                    .expect("BUG: should never fail to open the block sentinel");
                // Dropping unconfirmed state cannot be done with a tx rollback,
                //   because the unconfirmed state may already have been written
                //   to the sqlite table before this transaction began
                self.storage.commit_tx()
            } else {
                trace!("drop_unconfirmed() noop");
            }
        }
    }

    /// Seal the in-RAM MARF state so that no subsequent writes will be permitted.
    /// Returns the new root hash of the MARF.
    /// Runtime-panics if the MARF was already sealed.
    pub fn seal(&mut self) -> Result<TrieHash, Error> {
        if self.storage.readonly() {
            return Err(Error::ReadOnlyError);
        }
        let root_hash = self.storage.seal()?;
        Ok(root_hash)
    }
}

// static methods
impl<T: MarfTrieId> MARF<T> {
    #[cfg(test)]
    pub fn from_storage_opened(storage: TrieFileStorage<T>, opened_to: &T) -> MARF<T> {
        MARF {
            storage,
            open_chain_tip: Some(WriteChainTip {
                block_hash: opened_to.clone(),
                height: 0,
            }),
            read_cursor: None,
            read_state: MarfReadState::new(),
        }
    }

    #[cfg(test)]
    pub fn begin(&mut self, chain_tip: &T, next_chain_tip: &T) -> Result<(), Error> {
        let mut tx = self.begin_tx()?;
        tx.begin(chain_tip, next_chain_tip)?;
        tx.commit_tx();
        Ok(())
    }

    #[cfg(test)]
    pub fn begin_unconfirmed(&mut self, chain_tip: &T) -> Result<T, Error> {
        let mut tx = self.begin_tx()?;
        let result = tx.begin_unconfirmed(chain_tip)?;
        tx.commit_tx();
        Ok(result)
    }

    #[cfg(test)]
    pub fn seal(&mut self) -> Result<TrieHash, Error> {
        let mut tx = self.begin_tx()?;
        let h = tx.seal()?;
        Ok(h)
    }

    // helper method for resolving a backptr child while walking a MARF
    fn walk_backptr<'a, S: TrieNodeReadState, Db: Deref<Target = Connection>>(
        storage: &'a mut TrieStorageConnection<T, Db>,
        child_backptr: TriePtr,
        cursor: &mut TrieCursor<T>,
        decode_scratch: &'a mut S,
    ) -> Result<(ReadTrieNode<'a>, TriePtr, u32), Error> {
        trace!("Walk backptrs for {:?} to {:?}", cursor, &child_backptr);

        let (read, node_ptr) = Trie::walk_backptr(storage, &child_backptr, cursor, decode_scratch)?;
        Ok((read, node_ptr, child_backptr.back_block))
    }

    fn node_copy_update(node: &mut TrieNodeType, child_block_id: u32) -> Result<TrieHash, Error> {
        let hash = match node {
            TrieNodeType::Leaf(leaf) => bits::get_leaf_hash(leaf),
            TrieNodeType::LeafSquashed(ref sq) => {
                // Hash as a plain leaf using the tip value
                bits::get_leaf_hash(&TrieLeaf {
                    path: sq.path,
                    data: sq.tip_value()?.clone(),
                })
            }
            _ => {
                node_copy_update_ptrs(node.ptrs_mut(), child_block_id);
                TrieHash::EMPTY
            }
        };

        Ok(hash)
    }

    /// Given a node, and the chr of one of its children, go find the last instance of that child in
    /// the MARF and copy it forward.  Update its ptrs to point to its descendents.
    /// s must point to the block hash in which this node lives, to which the child will be copied.
    fn node_child_copy<S: TrieNodeReadState, Db: Deref<Target = Connection>>(
        storage: &mut TrieStorageConnection<T, Db>,
        child_backptr: TriePtr,
        cursor: &mut TrieCursor<T>,
        decode_scratch: &mut S,
    ) -> Result<(TrieNodeType, TrieHash, TriePtr, T), Error> {
        trace!(
            "Copy to {:?} child {:?}",
            storage.get_cur_block(),
            &child_backptr,
        );

        let (cur_block_hash, cur_block_id) = storage.get_cur_block_and_id();
        let chr = child_backptr.chr();

        let (child_read, child_ptr, _) =
            MARF::walk_backptr(storage, child_backptr, cursor, decode_scratch)?;
        let (mut child_node, _) = child_read.into_owned_node()?;

        // Flatten LeafSquashed → Leaf for per-block COW. Squash history
        // must not be carried forward into per-block blobs. If the copied
        // child was reached inside a reclaimed FullHistory squash, preserve
        // the value at the opened snapshot height, not the merged squash tip.
        if let TrieNodeType::LeafSquashed(ref sq) = child_node {
            let value = match storage.squash_opened_height() {
                Some(height) => sq.value_at_height(height).cloned().ok_or_else(|| {
                    Error::CorruptionError(format!(
                        "LeafSquashed COW copy could not resolve value at opened \
                         squash height {height} for path {}",
                        crate::util::hash::to_hex(sq.path.as_slice())
                    ))
                })?,
                None => sq.tip_value()?.clone(),
            };
            child_node = TrieNodeType::Leaf(TrieLeaf {
                path: sq.path,
                data: value,
            });
        }

        let child_block_hash = storage.get_cur_block();
        let child_block_identifier = storage.get_cur_block_identifier()?;

        child_node.set_cow_ptr(TrieCowPtr::new(child_block_hash.clone(), child_backptr));

        // update child_node with new ptrs and hashes
        storage.open_block_maybe_id(&cur_block_hash, cur_block_id)?;
        let child_hash = MARF::<T>::node_copy_update(&mut child_node, child_block_identifier)?;

        // store it in this trie
        storage.open_block_maybe_id(&cur_block_hash, cur_block_id)?;
        let child_disk_ptr = storage.last_ptr()?;
        let child_ptr = TriePtr::new(child_ptr.id(), chr, child_disk_ptr);
        storage.write_nodetype(child_disk_ptr, &child_node, child_hash)?;

        trace!(
            "Copied child 0x{:02x} to {:?}: ptr={:?} child={:?}",
            chr,
            &cur_block_hash,
            &child_ptr,
            &child_node
        );
        Ok((child_node, child_hash, child_ptr, child_block_hash))
    }

    /// Copy the root node from the previous Trie to this Trie, updating its ptrs.
    /// s must point to the target Trie
    fn root_copy<S: TrieNodeReadState, Db: Deref<Target = Connection>>(
        storage: &mut TrieStorageConnection<T, Db>,
        prev_block_hash: &T,
        decode_scratch: &mut S,
    ) -> Result<(), Error> {
        let (cur_block_hash, cur_block_id) = storage.get_cur_block_and_id();
        storage.open_block(prev_block_hash)?;
        let prev_block_identifier = storage.get_cur_block_identifier().unwrap_or_else(|_| {
            panic!(
                "called open_block on {}, but found no identifier",
                prev_block_hash
            )
        });

        // If the parent block is in a reclaim-squash level, the squash blob
        // has only one materialized root (the merged tip's), so reading via
        // `Trie::read_root` would return the merged shape regardless of
        // which block we opened — leaving the fork's seal hash structurally
        // wrong. Use the per-height root snapshot captured in the squash
        // trailer instead. The captured body is post-remap, so its child
        // ptrs already resolve into this level's blob, and `node_copy_update`
        // below converts direct ptrs into backptrs targeting
        // `prev_block_identifier` exactly as it does in the unsquashed path.
        //
        // `squash_opened_root_node_bytes` fails closed: it returns `None`
        // for blocks not in a squash level and for no-reclaim levels (whose
        // original blobs still serve the per-block root via
        // `ROOT_PTR_DISK`), but errors if a reclaim level somehow lacks a
        // saved snapshot. We propagate that error rather than silently
        // falling back.
        let saved_root_node: Option<TrieNodeType> = match storage.squash_opened_root_node_bytes()? {
            Some(body) => {
                let head = *body.first().ok_or_else(|| {
                    Error::CorruptionError("squash sidecar per-height root body is empty".into())
                })?;
                let node_id = clear_backptr(head) & 0x3f;
                let (node, _consumed) = bits::decode_nodetype_from_slice_at_head(&body, node_id)?;
                Some(node)
            }
            None => None,
        };
        let using_saved_root_node = saved_root_node.is_some();
        let mut prev_root = match saved_root_node {
            Some(n) => n,
            None => {
                let root_read = Trie::read_root(storage, decode_scratch)?;
                root_read.into_owned_node()?.0
            }
        };
        if prev_block_hash != &T::sentinel() {
            if !using_saved_root_node {
                // Normal roots are addressable at ROOT_PTR_DISK in the
                // parent block, so the flush path can encode this copied root
                // as a patch against that base. Saved sidecar roots are not
                // addressable there: opening ROOT_PTR_DISK for any reclaimed
                // in-squash block yields the merged-tip root. Patching a
                // per-height root against that merged root produces bogus
                // diffs, so saved roots are written as full nodes.
                let mut prev_root_backptr = TriePtr::new(
                    set_backptr(TrieNodeID::Node256 as u8),
                    0,
                    storage.root_ptr(),
                );
                prev_root_backptr.back_block = prev_block_identifier;
                prev_root.set_cow_ptr(TrieCowPtr::new(prev_block_hash.clone(), prev_root_backptr));
            }
        }
        let new_root_hash = Self::node_copy_update(&mut prev_root, prev_block_identifier)?;

        storage.open_block_maybe_id(&cur_block_hash, cur_block_id)?;

        let root_ptr = storage.root_ptr();
        storage.write_nodetype(root_ptr, &prev_root, new_root_hash)?;
        Ok(())
    }

    /// create or open a particular Trie.
    /// If the trie doesn't exist, then extend it from the current Trie and create a root node that
    /// has back pointers to its immediate children in the current trie.
    /// On Ok, s will point to new_bhh and will be open for reading.
    /// Returns true/false, based on whether or not the trie will be created (this can return false
    /// if we're resuming work on an unconfirmed trie)
    pub fn extend_trie<S: TrieNodeReadState>(
        storage: &mut TrieStorageTransaction<T>,
        new_bhh: &T,
        decode_scratch: &mut S,
    ) -> Result<(), Error> {
        if storage.readonly() {
            unreachable!("CORRUPTION: constructed read-only TrieStorageTransaction instance");
        }

        let (cur_bhh, cur_block_id) = storage.get_cur_block_and_id();
        if storage.num_blocks() == 0 || cur_bhh == T::sentinel() {
            // brand new storage
            trace!("Brand new storage -- start with {:?}", new_bhh);
            storage.extend_to_block(new_bhh)?;
            let node = TrieNode256::new(&[]);
            let hash = bits::get_node_hash(&node, &[], storage);
            let root_ptr = storage.root_ptr();
            storage.write_nodetype(root_ptr, &TrieNodeType::Node256(Box::new(node)), hash)?;
            Ok(())
        } else {
            // existing storage
            match storage.open_block(new_bhh) {
                Ok(_) => {
                    trace!("Switch to Trie {:?}", new_bhh);
                    Ok(())
                }
                Err(e) => {
                    match e {
                        Error::NotFoundError => {
                            // bring root forward
                            debug!("Extend {:?} to {:?}", &cur_bhh, new_bhh);
                            storage.open_block_maybe_id(&cur_bhh, cur_block_id)?;
                            storage.extend_to_block(new_bhh)?;
                            MARF::root_copy(storage, &cur_bhh, decode_scratch)?;
                            storage.open_block(new_bhh)?;
                            Ok(())
                        }
                        _ => Err(e),
                    }
                }
            }
        }
    }

    /// Walk down this MARF at the given block hash, doing a copy-on-write for intermediate nodes in
    /// this block's Trie from any prior Tries.
    ///
    /// `storage` must point to the last filled-in Trie -- i.e. block_hash points to the _new_ Trie
    /// that is being filled in.
    fn walk_cow<S: TrieNodeReadState>(
        storage: &mut TrieStorageTransaction<T>,
        block_hash: &T,
        path: &TrieHash,
        decode_scratch: &mut S,
    ) -> Result<TrieCursor<T>, Error> {
        let block_id = storage.get_block_identifier(block_hash);
        MARF::extend_trie(storage, block_hash, decode_scratch)?;
        decode_scratch.clear_parked_nodes();

        let mut cursor = TrieCursor::new(path, storage.root_trieptr());

        let mut node_ptr = storage.root_trieptr();
        let mut owned_node: Option<TrieNodeType> = None;

        for _ in 0..(cursor.path.len() + 1) {
            let cur_block = storage.get_cur_block();
            let action = if let Some(node) = owned_node.as_ref() {
                cursor.walk_step(node, &cur_block)
            } else {
                decode_scratch.clear_current_node();
                let read = storage.read_node_with_state(&node_ptr, decode_scratch)?;
                match read.backing {
                    ReadNodeBacking::VolatileDecoded(node) => {
                        let action = cursor.walk_ref_step(&node, &cur_block);
                        let parked_handle = decode_scratch.park_current_node()?;
                        cursor.promote_last_node_to_parked(parked_handle);
                        action
                    }
                    ReadNodeBacking::PersistedDecoded(node) => {
                        cursor.walk_ref_step(&node, &cur_block)
                    }
                    ReadNodeBacking::PersistedBytes(node) => {
                        return Err(Error::CorruptionError(format!(
                            "Stable byte-backed {:?} nodes cannot be walked in COW mode yet",
                            node.node_type()
                        )));
                    }
                    ReadNodeBacking::Owned(node) => {
                        let parked_handle = decode_scratch.park_owned_node(node);
                        let parked_node = decode_scratch.get_parked_ref(parked_handle);
                        cursor.walk_parked_step(&parked_node, parked_handle, &cur_block)
                    }
                }
            };

            match action {
                ReadTrieNodeCursorStep::Next(next_node_ptr) => {
                    owned_node = None;
                    node_ptr = next_node_ptr;
                    continue;
                }
                ReadTrieNodeCursorStep::EndOfPath { is_leaf } => {
                    let ptr_base = clear_backptr(node_ptr.id());
                    if !is_leaf
                        || (ptr_base != TrieNodeID::Leaf as u8
                            && ptr_base != TrieNodeID::LeafSquashed as u8)
                    {
                        trace!("Out-of-path but encountered a non-leaf at {:?}", &node_ptr);
                        error!("Out-of-path but encountered a non-leaf");
                        return Err(Error::CorruptionError(
                            "Non-leaf encountered at end of path".to_string(),
                        ));
                    }

                    trace!(
                        "Out of path in {:?} -- we're done. Node at {:?}",
                        storage.get_cur_block(),
                        &node_ptr
                    );
                    storage.open_block_maybe_id(block_hash, block_id)?;
                    return Ok(cursor);
                }
                ReadTrieNodeCursorStep::Diverged => {
                    trace!("Path diverged -- we're done.");
                    storage.open_block_maybe_id(block_hash, block_id)?;
                    return Ok(cursor);
                }
                ReadTrieNodeCursorStep::ChrNotFound => {
                    trace!(
                        "ChrNotFound encountered at {:?} -- we're done (node not found)",
                        storage.get_cur_block()
                    );
                    storage.open_block_maybe_id(block_hash, block_id)?;
                    return Ok(cursor);
                }
                ReadTrieNodeCursorStep::FollowBackptr(ptr) => {
                    storage.open_block_maybe_id(block_hash, block_id)?;
                    let (next_node, _, next_node_ptr, next_node_block_hash) =
                        MARF::node_child_copy(storage, ptr, &mut cursor, decode_scratch)?;

                    cursor.repair_backptr_finish(&next_node_ptr, next_node_block_hash);

                    owned_node = Some(next_node);
                    node_ptr = next_node_ptr;

                    storage.open_block_maybe_id(block_hash, block_id)?;
                }
            }
        }

        trace!("Trie has a cycle");
        return Err(Error::CorruptionError("Trie has a cycle".to_string()));
    }

    /// Walk down this MARF at the given block hash, resolving backptrs to previous tries.
    /// Return the cursor and the last node visited.
    /// s will point to the block in which the leaf was found, or the last block visited.
    fn walk<S: TrieNodeReadState, R: TrieReadStorage<T> + ?Sized>(
        ctx: &mut MarfReadCtx<'_, T, S, R>,
        block_hash: &T,
        path: &TrieHash,
    ) -> Result<TrieLeaf, Error> {
        ctx.with_read_state(|storage, cursor_opt, decode_scratch| {
            let cursor =
                cursor_opt.get_or_insert_with(|| TrieCursor::new(path, TriePtr::default()));

            storage.open_block(block_hash)?;
            cursor.reset(path, storage.root_trieptr());

            // Capture the user's target block identity AND any eagerly-set snapshot height NOW,
            // before backptr resolution can mutate them mid-walk. The parent-chain *walk* itself is
            // deferred to the `LeafSquashed` branch — most reads never touch a squashed leaf, so
            // paying for that walk up-front would be wasted work on canonical-only and post-squash
            // key reads.
            //
            // What's captured here:
            //   - `user_block_hash` / `user_block_id`: the user's open target. Backptr resolution
            //     calls `open_block_known_id` and mutates `cur_block_id`, so `snapshot_height_for_block`
            //     in the LeafSquashed branch must use *these* (not the post-mutation cur_block).
            //   - `eager_user_height`: O(1) field read of `data.squash_opened_height`. Set
            //     non-None for in-squash user blocks (`read_node_hash` per-block root-hash override
            //     consumer) AND for uncommitted blocks whose parent is in the squash (Tier 10 fix).
            //     For uncommitted blocks `user_block_id` is `None`, so the LeafSquashed branch
            //     can't fall back to a block-id-keyed walk — the eager capture is the only signal.
            let (user_block_hash, user_block_id) = storage.get_cur_block_and_id();
            let eager_user_height = storage.squash_opened_height();

            let mut node_ptr = storage.root_trieptr();

            for _ in 0..(cursor.path.len() + 1) {
                enum WalkAction {
                    Next(TriePtr),
                    FoundLeaf(TrieLeaf),
                    /// `LeafSquashed` deferred so the `read_session` borrow can be released before
                    /// we call `snapshot_height_for_block` on storage (which reborrows it). Carries
                    /// only the small `path` + `tip_value` clones — NOT the (potentially large)
                    /// `entries` vector — and the original `node_ptr` for a *conditional* re-read.
                    ///
                    /// Hot path (dormant tip read on canonical chain past a squash):
                    /// snapshot-height resolves to `None` and `tip_value` is used directly, so
                    /// `entries` is never materialized and the leaf isn't re-read. Historical/fork
                    /// path (height = `Some`): re-decodes this same `node_ptr` into the scratch
                    /// buffer to look up `entries[idx]`. The re-read is one decode pass — cheaper
                    /// than cloning a potentially large `Vec<(u32, MARFValue)>` and bounded
                    /// regardless of how frequently the key was overwritten across the squash
                    /// range.
                    FoundSquashedLeaf {
                        path: Vec<u8>,
                        tip_value: MARFValue,
                        node_ptr: TriePtr,
                    },
                    FollowBackptr(TriePtr),
                    NotFound,
                }

                let cur_block = storage.get_cur_block();
                storage.bench_mut().marf_walk_from_start();
                let action = {
                    let mut read_session = TrieReadSession::new(storage, decode_scratch);
                    let read = read_session.read_node(&node_ptr)?;
                    match cursor.walk_read(&read, &cur_block) {
                        Ok(Some(next_ptr)) => WalkAction::Next(next_ptr),
                        Ok(None) => {
                            // Ptr-hint sanity check (unchanged)
                            let ptr_base = clear_backptr(cursor.ptr().id());
                            if ptr_base != TrieNodeID::Leaf as u8
                                && ptr_base != TrieNodeID::LeafSquashed as u8
                            {
                                return Err(Error::CorruptionError(
                                    "Non-leaf encountered at end of path".to_string(),
                                ));
                            }

                            // Branch on the decoded node type (ground truth from the
                            // blob), not the ptr hint which can be stale.
                            match read.node_type() {
                                Some(TrieNodeID::LeafSquashed) => {
                                    let sq = read.as_leaf_squashed_ref()?.ok_or_else(|| {
                                        Error::CorruptionError(
                                            "LeafSquashed node_type but \
                                                 as_leaf_squashed_ref failed"
                                                .into(),
                                        )
                                    })?;
                                    // Phase 1: extract only the small fixed-size data — no
                                    // `entries` clone. Save `node_ptr` so Phase 2 can conditionally
                                    // re-read this exact node if a height resolves and
                                    // `entries[idx]` is needed.
                                    WalkAction::FoundSquashedLeaf {
                                        path: sq.path.to_vec(),
                                        tip_value: sq.tip_value.clone(),
                                        node_ptr,
                                    }
                                }
                                _ => {
                                    let lr = read.as_leaf()?.ok_or_else(|| {
                                        Error::CorruptionError(
                                            "Path reached a non-leaf".to_string(),
                                        )
                                    })?;
                                    WalkAction::FoundLeaf(TrieLeaf::from_value(
                                        lr.path,
                                        lr.data.clone(),
                                    ))
                                }
                            }
                        }
                        Err(Error::CursorError(CursorError::PathDiverged))
                        | Err(Error::CursorError(CursorError::ChrNotFound)) => WalkAction::NotFound,
                        Err(Error::CursorError(CursorError::BackptrEncountered(ptr))) => {
                            WalkAction::FollowBackptr(ptr)
                        }
                        Err(e) => return Err(e),
                    }
                    // read_session dropped here, releasing the storage borrow so the
                    // FoundSquashedLeaf branch below can call snapshot_height_for_block.
                };

                match action {
                    WalkAction::Next(next_ptr) => {
                        node_ptr = next_ptr;
                        continue;
                    }
                    WalkAction::FoundLeaf(leaf) => {
                        storage.bench_mut().marf_walk_from_finish();
                        return Ok(leaf);
                    }
                    WalkAction::FoundSquashedLeaf {
                        path,
                        tip_value,
                        node_ptr: leaf_node_ptr,
                    } => {
                        // Snapshot-height resolution, in priority order:
                        //   1. `eager_user_height` (captured before walk): covers in-squash and
                        //      uncommitted-of-squash users — backptr resolution may have mutated
                        //      `data.squash_opened_height` since.
                        //   2. Lazy parent-chain walk for committed non-squash users (forks past
                        //      the squash). Memoized per user_block_id; fires at most once per
                        //      user-level open, only when this branch is reached.
                        //   3. None — uncommitted with no eager set (no squash exists or parent
                        //      isn't in one) → tip-read fallback.
                        let user_query_height = match (eager_user_height, user_block_id) {
                            (Some(h), _) => Some(h),
                            (None, Some(id)) => {
                                storage.snapshot_height_for_block(&user_block_hash, id)
                            }
                            (None, None) => None,
                        };
                        let leaf = if let Some(height) = user_query_height {
                            // Historical/fork path: re-read the leaf to access `entries[idx]`.
                            // `cur_block` is unchanged since Phase 1 (the snapshot-height walker
                            // doesn't open blocks), so `leaf_node_ptr` resolves to the same
                            // squashed leaf we just decoded. Cost: one decode pass on bytes
                            // typically still resident in mmap/page cache. Bounded re-read, unlike
                            // cloning a potentially large entries vector.
                            #[cfg(test)]
                            storage.bump_squashed_entries_reread_count();
                            let mut read_session = TrieReadSession::new(storage, decode_scratch);
                            let read = read_session.read_node(&leaf_node_ptr)?;
                            let sq = read.as_leaf_squashed_ref()?.ok_or_else(|| {
                                Error::CorruptionError(
                                    "LeafSquashed node_type lost between phase-1 decode \
                                     and phase-2 re-read"
                                        .into(),
                                )
                            })?;
                            let value = sq.value_at_height(height).cloned().ok_or_else(|| {
                                // `debug!` (not `warn!`): None here is an explicit signal
                                // to the caller that the key didn't exist at the requested
                                // snapshot height — semantically valid (e.g. for a key
                                // first written above `height`). For unexpected cases (the
                                // genesis-sync seal panic), this debug line provides the
                                // entries vector + resolved height, queryable with
                                // `STACKS_LOG_DEBUG=1` if a regression resurfaces.
                                let entry_heights: Vec<u32> =
                                    sq.entries.iter().map(|(h, _)| *h).collect();
                                debug!(
                                    "MARF::walk LeafSquashed value_at_height returned None: \
                                     user_block_hash={user_block_hash}, user_block_id={user_block_id:?}, \
                                     eager_user_height={eager_user_height:?}, \
                                     resolved_height={height}, \
                                     leaf_path={}, entries_heights={entry_heights:?}",
                                    crate::util::hash::to_hex(&path)
                                );
                                Error::NotFoundError
                            })?;
                            TrieLeaf::from_value(&path, value)
                        } else {
                            // Hot path: dormant tip read on canonical chain past a squash, or
                            // pruned-ancestor walk fallback. `tip_value` is already in hand; no
                            // entries materialization, no node re-read.
                            #[cfg(test)]
                            storage.bump_squashed_tip_fallback_count();
                            TrieLeaf::from_value(&path, tip_value)
                        };
                        storage.bench_mut().marf_walk_from_finish();
                        return Ok(leaf);
                    }
                    WalkAction::NotFound => {
                        trace!("Path diverged or chr not found -- we're done.");
                        storage.bench_mut().marf_walk_from_finish();
                        return Err(Error::NotFoundError);
                    }
                    WalkAction::FollowBackptr(ptr) => {
                        storage.bench_mut().marf_walk_backptr_start();
                        let next_node_ptr = Trie::resolve_backptr(storage, &ptr)?;
                        storage.bench_mut().marf_walk_backptr_finish();

                        cursor.repair_backptr_finish(&next_node_ptr, storage.get_cur_block());
                        node_ptr = next_node_ptr;
                        continue;
                    }
                }
            }

            trace!("Trie has a cycle");
            Err(Error::CorruptionError("Trie has a cycle".to_string()))
        })
    }

    pub fn format(
        storage: &mut TrieStorageTransaction<T>,
        first_block_hash: &T,
    ) -> Result<(), Error> {
        if storage.readonly() {
            unreachable!("CORRUPTION: constructed read-only TrieStorageTransaction instance");
        }

        storage.format()?;
        storage.extend_to_block(first_block_hash)?;
        let node = TrieNode256::new(&[]);
        let hash = bits::get_node_hash(&node, &[], storage);
        let root_ptr = storage.root_ptr();
        let node_type = TrieNodeType::Node256(Box::new(node));
        storage.write_nodetype(root_ptr, &node_type, hash)
    }

    fn do_insert_leaf<S: TrieNodeReadState>(
        storage: &mut TrieStorageTransaction<T>,
        block_hash: &T,
        path: &TrieHash,
        leaf_value: &TrieLeaf,
        update_skiplist: bool,
        decode_scratch: &mut S,
    ) -> Result<(), Error> {
        let mut value = leaf_value.clone();
        let mut cursor = MARF::walk_cow(storage, block_hash, path, decode_scratch)?;

        if cursor.block_hashes.len() + 1 != cursor.node_ptrs.len() {
            trace!("c.block_hashes = {:?}", &cursor.block_hashes);
            trace!("c.node_ptrs = {:?}", cursor.node_ptrs);
            panic!();
        }

        debug!(
            "MARF Insert in {block_hash}: '{path}' = '{}' (...{:?})",
            leaf_value.data, &leaf_value.path
        );

        Trie::add_value(storage, &mut cursor, &mut value, decode_scratch)?;

        if update_skiplist {
            Trie::update_root_hash(storage, &cursor, decode_scratch)?;
        } else {
            Trie::update_root_node_hash(storage, &cursor, decode_scratch)?;
        }
        Ok(())
    }

    pub fn insert_leaf<S: TrieNodeReadState>(
        storage: &mut TrieStorageTransaction<T>,
        block_hash: &T,
        path: &TrieHash,
        value: &TrieLeaf,
        decode_scratch: &mut S,
    ) -> Result<(), Error> {
        if storage.readonly() {
            unreachable!("CORRUPTION: constructed read-only TrieStorageTransaction instance");
        }
        MARF::do_insert_leaf(storage, block_hash, path, value, true, decode_scratch)
    }

    // like insert_leaf, but don't update the merkle skiplist
    pub fn insert_leaf_in_batch<S: TrieNodeReadState>(
        storage: &mut TrieStorageTransaction<T>,
        block_hash: &T,
        path: &TrieHash,
        value: &TrieLeaf,
        decode_scratch: &mut S,
    ) -> Result<(), Error> {
        if storage.readonly() {
            unreachable!("CORRUPTION: constructed read-only TrieStorageTransaction instance");
        }

        MARF::do_insert_leaf(storage, block_hash, path, value, false, decode_scratch)
    }

    /// Instantiate the MARF from a TrieFileStorage instance
    pub fn from_storage(storage: TrieFileStorage<T>) -> MARF<T> {
        MARF {
            storage,
            open_chain_tip: None,
            read_cursor: None,
            read_state: MarfReadState::new(),
        }
    }

    /// Instantiate the MARF using a TrieFileStorage instance, from the given path on disk.
    /// This will have the side-effect of instantiating a new fork table from the tries encoded on
    /// disk. Performant code should call this method sparingly.
    pub fn from_path(path: &str, open_opts: MARFOpenOpts) -> Result<MARF<T>, Error> {
        let file_storage = TrieFileStorage::open(path, open_opts)?;
        Ok(MARF::from_storage(file_storage))
    }

    /// Instantiate an unconfirmed MARF using a TrieFileStorage instance, from the given path on disk.
    /// This will have the side-effect of instantiating a new fork table from the tries encoded on
    /// disk. Performant code should call this method sparingly.
    pub fn from_path_unconfirmed(path: &str, open_opts: MARFOpenOpts) -> Result<MARF<T>, Error> {
        let file_storage = TrieFileStorage::open_unconfirmed(path, open_opts)?;
        Ok(MARF::from_storage(file_storage))
    }

    /// Make an unconfirmed chain tip from an existing chain tip, so that it won't conflict with
    /// the "true" chain tip after the state it represents is later reprocessed and confirmed.
    pub fn make_unconfirmed_chain_tip(chain_tip: &T) -> T {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(chain_tip.as_bytes());
        bytes[32..64].copy_from_slice(chain_tip.as_bytes());

        let h = Sha512Trunc256Sum::from_data(&bytes);
        let mut res_bytes = [0u8; 32];
        res_bytes[0..32].copy_from_slice(h.as_bytes());

        T::from_bytes(res_bytes)
    }

    /// Insert a batch of key/value pairs.  More efficient than inserting them individually, since
    /// the trie root hash will only be calculated once (which is an O(log B) operation).
    fn inner_insert_batch<S: TrieNodeReadState>(
        conn: &mut TrieStorageTransaction<T>,
        block_hash: &T,
        keys: &[String],
        values: &[MARFValue],
        decode_scratch: &mut S,
    ) -> Result<(), Error> {
        assert_eq!(keys.len(), values.len());

        let (Some(last_key), Some(last_value)) = (keys.last(), values.last()) else {
            // if empty, nothing to do
            return Ok(());
        };

        let (cur_block_hash, cur_block_id) = conn.get_cur_block_and_id();

        let last = keys.len() - 1;
        let mut progress = 0;
        let eta_enabled = keys.len() > 10_000;
        let mut result =
            keys.iter()
                .enumerate()
                .zip(values.iter())
                .try_for_each(|((index, key), value)| {
                    let marf_leaf = TrieLeaf::from_value(&[], value.clone());
                    let path = TrieHash::from_key(key);

                    if eta_enabled {
                        let updated_progress = 100 * index / last;
                        if updated_progress > progress {
                            progress = updated_progress;
                            info!(
                                "Batching insertions in MARF: {}% ({} out of {})",
                                progress, index, last
                            );
                        }
                    }
                    MARF::insert_leaf_in_batch(conn, block_hash, &path, &marf_leaf, decode_scratch)
                });

        if result.is_ok() {
            // last insert updates the root with the skiplist hash
            let marf_leaf = TrieLeaf::from_value(&[], last_value.clone());
            let path = TrieHash::from_key(last_key);
            result = MARF::insert_leaf(conn, block_hash, &path, &marf_leaf, decode_scratch);
        }

        // restore
        conn.open_block_maybe_id(&cur_block_hash, cur_block_id)?;

        result
    }
}

// instance methods
impl<T: MarfTrieId> MARF<T> {
    /// Check if a block hash falls within any loaded squash level's range.
    pub fn is_in_squash_range(&self, block_hash: &T) -> bool {
        let bhh_key: [u8; 32] = block_hash
            .as_bytes()
            .get(..32)
            .and_then(|s| s.try_into().ok())
            .unwrap_or([0u8; 32]);
        self.storage
            .data
            .squash_meta
            .block_index
            .contains_key(&bhh_key)
    }

    pub fn begin_tx(&mut self) -> Result<MarfTransaction<'_, T>, Error> {
        let storage = self.storage.transaction()?;
        Ok(MarfTransaction {
            storage,
            open_chain_tip: &mut self.open_chain_tip,
            read_cursor: &mut self.read_cursor,
            read_state: &mut self.read_state,
        })
    }

    /// Target the MARF's storage at a given block.
    pub fn open_block(&mut self, block_hash: &T) -> Result<(), Error> {
        <Self as MarfInternals<T>>::open_block(self, block_hash, None)
    }

    pub fn get_with_proof(
        &mut self,
        block_hash: &T,
        key: &str,
    ) -> Result<Option<(MARFValue, TrieMerkleProof<T>)>, Error> {
        if self.is_in_squash_range(block_hash) {
            return Err(Error::NotSupportedError(
                "Merkle proofs not supported for blocks within squash range".into(),
            ));
        }
        let marf_value = match <Self as MarfInternals<T>>::get_by_key(self, block_hash, key)? {
            None => return Ok(None),
            Some(x) => x,
        };
        let proof =
            <Self as MarfInternals<T>>::prove_raw_entry(self, block_hash, key, &marf_value)?;
        Ok(Some((marf_value, proof)))
    }

    pub fn get_with_proof_from_hash(
        &mut self,
        block_hash: &T,
        path: &TrieHash,
    ) -> Result<Option<(MARFValue, TrieMerkleProof<T>)>, Error> {
        if self.is_in_squash_range(block_hash) {
            return Err(Error::NotSupportedError(
                "Merkle proofs not supported for blocks within squash range".into(),
            ));
        }
        let marf_value = match <Self as MarfInternals<T>>::get_by_path(self, block_hash, path)? {
            None => return Ok(None),
            Some(x) => x,
        };
        let proof = <Self as MarfInternals<T>>::prove_path(self, block_hash, path, &marf_value)?;
        Ok(Some((marf_value, proof)))
    }

    pub fn get_bhh_at_height(&mut self, block_hash: &T, height: u32) -> Result<Option<T>, Error> {
        <Self as MarfInternals<T>>::get_block_at_height(self, height, block_hash)
    }

    /// Insert a batch of key/value pairs.  More efficient than inserting them individually, since
    /// the trie root hash will only be calculated once (which is an O(log B) operation).
    pub fn insert_batch(
        &mut self,
        keys: impl AsRef<[String]>,
        values: impl AsRef<[MARFValue]>,
    ) -> Result<(), Error> {
        let keys = keys.as_ref();
        let values = values.as_ref();

        if self.storage.readonly() {
            return Err(Error::ReadOnlyError);
        }
        assert_eq!(keys.len(), values.len());

        let block_hash = match self.open_chain_tip {
            None => Err(Error::WriteNotBegunError),
            Some(WriteChainTip { ref block_hash, .. }) => Ok(block_hash.clone()),
        }?;

        if keys.is_empty() {
            return Ok(());
        }

        let mut tx = self.storage.transaction()?;
        MARF::inner_insert_batch(&mut tx, &block_hash, keys, values, &mut self.read_state)?;
        tx.commit_tx();
        Ok(())
    }

    pub fn insert(&mut self, key: &str, value: MARFValue) -> Result<(), Error> {
        if self.storage.readonly() {
            return Err(Error::ReadOnlyError);
        }
        let marf_leaf = TrieLeaf::from_value(&[], value);
        let path = TrieHash::from_key(key);
        self.insert_raw(path, marf_leaf)
    }

    /// Insert the given (key, value) pair into the MARF.  Inserting the same key twice silently
    /// overwrites the existing key.  Succeeds if there are no storage errors.
    /// Must be called after a call to .begin() (will fail otherwise)
    pub fn insert_raw(&mut self, path: TrieHash, marf_leaf: TrieLeaf) -> Result<(), Error> {
        if self.storage.readonly() {
            return Err(Error::ReadOnlyError);
        }
        match self.open_chain_tip {
            None => Err(Error::WriteNotBegunError),
            Some(WriteChainTip { ref block_hash, .. }) => {
                let mut tx = self.storage.transaction()?;
                let (cur_block_hash, cur_block_id) = tx.get_cur_block_and_id();

                let result =
                    MARF::insert_leaf(&mut tx, block_hash, &path, &marf_leaf, &mut self.read_state);

                // restore
                tx.open_block_maybe_id(&cur_block_hash, cur_block_id)?;
                tx.commit_tx();

                result
            }
        }
    }

    /// Drop the current trie from the MARF. This rolls back all
    ///   changes in the block, and closes the current chain tip.
    pub fn drop_current(&mut self) {
        if !self.storage.readonly() {
            let mut tx = self
                .storage
                .transaction()
                .expect("BUG: failed to start transaction to drop trie");
            tx.drop_extending_trie();
            self.open_chain_tip.take();
            tx.open_block(&T::sentinel())
                .expect("BUG: should never fail to open the block sentinel");
            tx.commit_tx();
        }
    }

    /// Drop the current trie from the MARF, and roll back all unconfirmed state
    pub fn drop_unconfirmed(&mut self) {
        if !self.storage.readonly() && self.storage.unconfirmed() {
            if let Some(tip) = self.open_chain_tip.take() {
                let mut tx = self
                    .storage
                    .transaction()
                    .expect("BUG: failed to start transaction to drop trie");
                tx.drop_unconfirmed_trie(&tip.block_hash);
                tx.open_block(&T::sentinel())
                    .expect("BUG: should never fail to open the block sentinel");
                tx.commit_tx();
            }
        }
    }

    /// Finish writing the next trie in the MARF.  This persists all changes.
    /// Works for both confirmed and unconfirmed tries
    pub fn commit(&mut self) -> Result<(), Error> {
        if self.storage.readonly() {
            return Err(Error::ReadOnlyError);
        }
        if let Some(_tip) = self.open_chain_tip.take() {
            let mut tx = self.storage.transaction()?;
            tx.flush()?;
            tx.commit_tx();
        }
        Ok(())
    }

    /// Finish writing the next trie in the MARF -- this is used by miners
    ///   to commit the mined block, but write it to the mined_block table,
    ///   rather than out to the marf_data table (this prevents the
    ///   miner's block from getting stepped on after the sortition).
    pub fn commit_mined(&mut self, bhh: &T) -> Result<(), Error> {
        if self.storage.readonly() {
            return Err(Error::ReadOnlyError);
        }
        if self.storage.unconfirmed() {
            return Err(Error::UnconfirmedError);
        }
        if let Some(_tip) = self.open_chain_tip.take() {
            let mut tx = self.storage.transaction()?;
            tx.flush_mined(bhh)?;
            tx.commit_tx();
        }
        Ok(())
    }

    /// Finish writing the next trie in the MARF, but change the hash of the current Trie's
    /// block hash to something other than what we opened it as.  This persists all changes.
    pub fn commit_to(&mut self, real_bhh: &T) -> Result<(), Error> {
        if self.storage.readonly() {
            return Err(Error::ReadOnlyError);
        }
        if self.storage.unconfirmed() {
            return Err(Error::UnconfirmedError);
        }
        if let Some(_tip) = self.open_chain_tip.take() {
            let mut tx = self.storage.transaction()?;
            tx.flush_to(real_bhh)?;
            tx.commit_tx();
        }
        Ok(())
    }

    /// Dump diagnostic information about the MARF's current transient state.
    /// Used to debug the `get_current_block_height` panic.
    pub fn dump_diagnostics(&mut self) {
        let (cur_block, cur_block_id) = {
            let conn = self.storage.connection();
            conn.get_cur_block_and_id()
        };
        error!(
            "MARF diagnostics: cur_block={cur_block}, cur_block_id={cur_block_id:?}, \
             readonly={read_only}, unconfirmed={unconfirmed}, \
             has_uncommitted_writes={has_uncommitted_writes}, \
             open_chain_tip={open_tip}",
            read_only = self.storage.readonly(),
            unconfirmed = self.storage.unconfirmed(),
            has_uncommitted_writes = self.storage.has_uncommitted_writes(),
            open_tip = self
                .open_chain_tip
                .as_ref()
                .map(|t| format!("Some({})", t.block_hash))
                .unwrap_or_else(|| "None".to_string()),
        );
    }

    // Comes from the marf.
    pub fn get_block_height_of(
        &mut self,
        bhh: &T,
        current_block_hash: &T,
    ) -> Result<Option<u32>, Error> {
        if Some(bhh) == self.get_open_chain_tip() {
            return Ok(self.get_open_chain_tip_height());
        } else {
            <Self as MarfInternals<T>>::get_block_height_miner_tip(self, bhh, current_block_hash)
        }
    }

    /// Get open chain tip
    pub fn get_open_chain_tip(&self) -> Option<&T> {
        self.open_chain_tip.as_ref().map(|x| &x.block_hash)
    }

    /// Get open chain tip block height
    pub fn get_open_chain_tip_height(&self) -> Option<u32> {
        self.open_chain_tip.as_ref().map(|x| x.height)
    }

    /// Access internal storage as a [`TrieStorageConnection`].
    #[cfg(test)]
    pub fn borrow_storage_backend(&mut self) -> TrieStorageConnection<'_, T> {
        self.storage.connection()
    }

    #[cfg(test)]
    pub fn borrow_storage_transaction(&mut self) -> TrieStorageTransaction<'_, T> {
        self.storage.transaction().unwrap()
    }

    /// Borrow the underlying [`TrieFileStorage`] mutably.
    ///
    /// Used by the squash pipeline to read from and write to the raw storage.
    pub(crate) fn storage_backend_mut(&mut self) -> &mut TrieFileStorage<T> {
        &mut self.storage
    }

    /// Make a raw transaction to the underlying storage
    pub fn storage_tx(&mut self) -> Result<Transaction<'_>, db_error> {
        self.storage.sqlite_tx()
    }

    /// Reopen storage read-only
    pub fn reopen_storage_readonly(&self) -> Result<TrieFileStorage<T>, Error> {
        self.storage.reopen_readonly()
    }

    /// Reopen this MARF with readonly storage.
    ///
    /// Returns Err if:
    ///   1) This class is already in the process of writing.
    ///   2) A new underlying SQLite database connection cannot be established.
    pub fn reopen_readonly(&self) -> Result<MARF<T>, Error> {
        if self.open_chain_tip.is_some() {
            error!(
                "MARF at {} is already in the process of writing",
                &self.storage.db_path
            );
            return Err(Error::InProgressError);
        }

        let ro_storage = self.storage.reopen_readonly()?;
        Ok(MARF {
            storage: ro_storage,
            open_chain_tip: None,
            read_cursor: None,
            read_state: MarfReadState::new(),
        })
    }

    /// Build a read-only storage connection which can be used for reads without modifying the
    ///  calling MARF struct (i.e., the tip pointer is only changed in the connection)
    ///  but reusing self's existing SQLite Connection (avoiding the overhead of
    ///   `reopen_readonly`).
    pub fn reopen_connection(&self) -> Result<ReopenedTrieStorageConnection<'_, T>, Error> {
        if self.open_chain_tip.is_some() {
            error!(
                "MARF at {} is already in the process of writing",
                &self.storage.db_path
            );
            return Err(Error::InProgressError);
        }
        self.storage.reopen_connection()
    }

    /// Get the root trie hash at a particular block
    pub fn get_root_hash_at(&mut self, block_hash: &T) -> Result<TrieHash, Error> {
        self.storage.connection().get_root_hash_at(block_hash)
    }

    /// Convert to the inner sqlite connection
    pub fn into_sqlite_conn(self) -> Connection {
        self.storage.into_sqlite_conn()
    }

    /// Get the underlying storage DB path
    pub fn get_db_path(&self) -> &str {
        &self.storage.db_path
    }

    /// Reload squash level metadata and remap the blob file after an
    /// external squash modified the underlying storage.
    pub fn refresh_after_squash(&mut self) -> Result<(), Error> {
        self.storage.refresh_after_squash()
    }
}

// --- Leaf traversal -----------------------------------------------------------

#[allow(unused)] // To be used in MARF squash
impl<T: MarfTrieId> MARF<T> {
    /// Walk all leaves in the trie at `block_hash`, yielding full paths and values.
    ///
    /// Follows backpointers to resolve nodes living in earlier blocks, so the
    /// returned set represents the complete state visible at `block_hash`.
    pub(crate) fn for_each_leaf<F>(
        storage: &mut TrieStorageConnection<T>,
        block_hash: &T,
        handle_leaf: F,
    ) -> Result<u64, Error>
    where
        F: Fn(TrieHash, MARFValue) -> Result<(), Error>,
    {
        let (original_block_hash, original_block_id) = storage.get_cur_block_and_id();
        let mut decode_scratch = MarfReadState::new();
        let result = Self::inner_each_leaf(storage, block_hash, &mut decode_scratch, &handle_leaf);

        storage
            .open_block_maybe_id(&original_block_hash, original_block_id)
            .inspect_err(|e| {
                warn!("Failed to re-open {original_block_hash} {original_block_id:?}: {e:?}");
            })?;

        let (restored_block_hash, _) = storage.get_cur_block_and_id();
        assert_eq!(
            restored_block_hash, original_block_hash,
            "for_each_leaf: open block changed after traversal"
        );

        result
    }

    fn inner_each_leaf<S: TrieNodeReadState, F>(
        storage: &mut TrieStorageConnection<T>,
        block_hash: &T,
        decode_scratch: &mut S,
        handle_leaf: &F,
    ) -> Result<u64, Error>
    where
        F: Fn(TrieHash, MARFValue) -> Result<(), Error>,
    {
        storage.open_block(block_hash)?;
        let (cur_block, cur_id) = storage.get_cur_block_and_id();
        let root_read = Trie::read_root(storage, decode_scratch)?;

        let mut leaf_count = 0u64;
        let mut stack: Vec<(TriePtr, Vec<u8>, T, Option<u32>)> = Vec::new();

        // Process a node: emit leaf or push children onto the stack.
        let process_node = |node: &ReadTrieNode<'_>,
                            prefix: Vec<u8>,
                            block_hash: T,
                            block_id: Option<u32>,
                            stack: &mut Vec<(TriePtr, Vec<u8>, T, Option<u32>)>|
         -> Result<bool, Error> {
            let mut full_prefix = prefix;
            full_prefix.extend_from_slice(node.path_bytes()?);

            if let Some(leaf) = node.as_leaf()? {
                if full_prefix.len() != TRIEHASH_ENCODED_SIZE {
                    return Err(Error::CorruptionError(
                        "Leaf path length invalid".to_string(),
                    ));
                }
                let path = TrieHash::from_bytes(&full_prefix).ok_or_else(|| {
                    Error::CorruptionError("Failed to decode leaf path".to_string())
                })?;
                handle_leaf(path, leaf.data.clone())?;
                Ok(true)
            } else {
                for ptr in node.ptrs()?.iter() {
                    if ptr.id() != TrieNodeID::Empty as u8 {
                        let mut child_prefix = full_prefix.clone();
                        child_prefix.push(ptr.chr());
                        stack.push((*ptr, child_prefix, block_hash.clone(), block_id));
                    }
                }
                Ok(false)
            }
        };

        if process_node(&root_read, vec![], cur_block, cur_id, &mut stack)? {
            leaf_count += 1;
        }

        let walk_start = Instant::now();
        let mut last_walk_log = Instant::now();
        let mut nodes_visited: u64 = 0;

        while let Some((ptr, prefix, return_block, return_block_id)) = stack.pop() {
            nodes_visited += 1;
            if last_walk_log.elapsed().as_secs() >= 30 {
                info!(
                    "for_each_leaf: {nodes_visited} nodes visited, {leaf_count} leaves found, stack {}, {:?} elapsed",
                    stack.len(),
                    walk_start.elapsed()
                );
                last_walk_log = Instant::now();
            }

            let (cur_block_hash, _) = storage.get_cur_block_and_id();
            if cur_block_hash != return_block {
                storage.open_block_maybe_id(&return_block, return_block_id)?;
            }

            let mut read_session = TrieReadSession::new(storage, decode_scratch);
            let (node_read, node_block_hash, node_block_id) =
                Self::read_node_for_ptr(&mut read_session, &ptr)?;
            if process_node(
                &node_read,
                prefix,
                node_block_hash,
                node_block_id,
                &mut stack,
            )? {
                leaf_count += 1;
            }
        }

        Ok(leaf_count)
    }

    /// Read a node referenced by `ptr`, following backpointers when necessary.
    fn read_node_for_ptr<'a, S: TrieNodeReadState, R: TrieReadStorage<T>>(
        read_session: &'a mut TrieReadSession<'_, T, S, R>,
        ptr: &TriePtr,
    ) -> Result<(ReadTrieNode<'a>, T, Option<u32>), Error> {
        if is_backptr(ptr.id()) {
            let back_block_id = ptr.back_block();
            let back_block_hash = read_session
                .storage()
                .get_block_from_local_id(back_block_id)?;
            read_session
                .storage()
                .open_block_known_id(&back_block_hash, back_block_id)?;
            let backptr = ptr.from_backptr();
            let read = read_session.read_node(&backptr)?;
            Ok((read, back_block_hash, Some(back_block_id)))
        } else {
            let (cur_block_hash, cur_block_id) = read_session.storage().get_cur_block_and_id();
            let read = read_session.read_node(ptr)?;
            Ok((read, cur_block_hash, cur_block_id))
        }
    }
}
