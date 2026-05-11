// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

use std::collections::HashMap;

use clarity::vm::costs::ExecutionCost;
use rusqlite::{params, Connection, OptionalExtension, Row};
use stacks_common::types::chainstate::{StacksBlockId, StacksWorkScore};

use crate::chainstate::burn::ConsensusHash;
use crate::chainstate::stacks::db::*;
use crate::chainstate::stacks::{Error, *};
use crate::core::{FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH};
use crate::util_lib::db::{
    query_row, query_row_columns, query_row_panic, query_rows, DBConn, Error as db_error,
    FromColumn, FromRow,
};

impl FromRow<StacksBlockHeader> for StacksBlockHeader {
    fn from_row(row: &Row) -> Result<StacksBlockHeader, db_error> {
        let version: u8 = row.get_unwrap("version");
        let total_burn_str: String = row.get_unwrap("total_burn");
        let total_work_str: String = row.get_unwrap("total_work");
        let proof: VRFProof = VRFProof::from_column(row, "proof")?;
        let parent_block = BlockHeaderHash::from_column(row, "parent_block")?;
        let parent_microblock = BlockHeaderHash::from_column(row, "parent_microblock")?;
        let parent_microblock_sequence: u16 = row.get_unwrap("parent_microblock_sequence");
        let tx_merkle_root = Sha512Trunc256Sum::from_column(row, "tx_merkle_root")?;
        let state_index_root = TrieHash::from_column(row, "state_index_root")?;
        let microblock_pubkey_hash = Hash160::from_column(row, "microblock_pubkey_hash")?;

        let block_hash = BlockHeaderHash::from_column(row, "block_hash")?;

        let total_burn = total_burn_str
            .parse::<u64>()
            .map_err(|_e| db_error::ParseError)?;
        let total_work = total_work_str
            .parse::<u64>()
            .map_err(|_e| db_error::ParseError)?;

        let header = StacksBlockHeader {
            version,
            total_work: StacksWorkScore {
                burn: total_burn,
                work: total_work,
            },
            proof,
            parent_block,
            parent_microblock,
            parent_microblock_sequence,
            tx_merkle_root,
            state_index_root,
            microblock_pubkey_hash,
        };

        if block_hash != FIRST_STACKS_BLOCK_HASH && header.block_hash() != block_hash {
            return Err(db_error::ParseError);
        }

        Ok(header)
    }
}

impl FromRow<StacksMicroblockHeader> for StacksMicroblockHeader {
    fn from_row(row: &Row) -> Result<StacksMicroblockHeader, db_error> {
        let version: u8 = row.get_unwrap("version");
        let sequence: u16 = row.get_unwrap("sequence");
        let prev_block = BlockHeaderHash::from_column(row, "prev_block")?;
        let tx_merkle_root = Sha512Trunc256Sum::from_column(row, "tx_merkle_root")?;
        let signature = MessageSignature::from_column(row, "signature")?;

        let microblock_hash = BlockHeaderHash::from_column(row, "microblock_hash")?;

        let microblock_header = StacksMicroblockHeader {
            version,
            sequence,
            prev_block,
            tx_merkle_root,
            signature,
        };

        if microblock_hash != microblock_header.block_hash() {
            return Err(db_error::ParseError);
        }

        Ok(microblock_header)
    }
}

impl StacksChainState {
    /// Insert a block header that is paired with an already-existing block commit and snapshot
    pub fn insert_stacks_block_header(
        tx: &DBTx,
        parent_id: &StacksBlockId,
        tip_info: &StacksHeaderInfo,
        anchored_block_cost: &ExecutionCost,
    ) -> Result<(), Error> {
        let StacksBlockHeaderTypes::Epoch2(header) = &tip_info.anchored_header else {
            return Err(Error::InvalidChildOfNakomotoBlock);
        };

        assert_eq!(tip_info.stacks_block_height, header.total_work.work);
        assert!(tip_info.burn_header_timestamp < i64::MAX as u64);

        let index_root = &tip_info.index_root;
        let consensus_hash = &tip_info.consensus_hash;
        let burn_header_hash = &tip_info.burn_header_hash;
        let block_height = tip_info.stacks_block_height;
        let burn_header_height = tip_info.burn_header_height;
        let burn_header_timestamp = tip_info.burn_header_timestamp;

        let total_work_str = format!("{}", header.total_work.work);
        let total_burn_str = format!("{}", header.total_work.burn);
        let block_size_str = format!("{}", tip_info.anchored_block_size);

        let block_hash = header.block_hash();

        let index_block_hash =
            StacksBlockHeader::make_index_block_hash(consensus_hash, &block_hash);

        assert!(block_height < (i64::MAX as u64));

        let args = params![
            header.version,
            total_burn_str,
            total_work_str,
            header.proof,
            header.parent_block,
            header.parent_microblock,
            header.parent_microblock_sequence,
            header.tx_merkle_root,
            header.state_index_root,
            header.microblock_pubkey_hash,
            block_hash,
            index_block_hash,
            consensus_hash,
            burn_header_hash,
            (burn_header_height as i64),
            (burn_header_timestamp as i64),
            (block_height as i64),
            index_root,
            anchored_block_cost,
            block_size_str,
            parent_id
        ];

        tx.execute("INSERT INTO block_headers \
                    (version, \
                    total_burn, \
                    total_work, \
                    proof, \
                    parent_block, \
                    parent_microblock, \
                    parent_microblock_sequence, \
                    tx_merkle_root, \
                    state_index_root, \
                    microblock_pubkey_hash, \
                    block_hash, \
                    index_block_hash, \
                    consensus_hash, \
                    burn_header_hash, \
                    burn_header_height, \
                    burn_header_timestamp, \
                    block_height, \
                    index_root,
                    cost,
                    block_size,
                    parent_block_id) \
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)", args)
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        Ok(())
    }

    pub fn get_stacks_block_anchored_cost(
        conn: &DBConn,
        block: &StacksBlockId,
    ) -> Result<Option<ExecutionCost>, Error> {
        let qry = "SELECT cost FROM block_headers WHERE index_block_hash = ?";
        conn.query_row(qry, &[block], |row| row.get(0))
            .optional()
            .map_err(|e| Error::from(db_error::from(e)))
    }

    pub fn is_stacks_block_processed(
        conn: &Connection,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
    ) -> Result<bool, Error> {
        let sql = "SELECT 1 FROM block_headers WHERE consensus_hash = ?1 AND block_hash = ?2";
        let args = params![consensus_hash, block_hash];
        match conn.query_row(sql, args, |_| Ok(true)) {
            Ok(_) => Ok(true),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
            Err(e) => Err(Error::DBError(e.into())),
        }
    }

    /// Get a stacks header info by burn block and block hash (i.e. by primary key).
    /// Does not get back data about the parent microblock stream.
    pub fn get_anchored_block_header_info(
        conn: &Connection,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
    ) -> Result<Option<StacksHeaderInfo>, Error> {
        let sql = "SELECT * FROM block_headers WHERE consensus_hash = ?1 AND block_hash = ?2";
        let args = params![consensus_hash, block_hash];
        query_row_panic(conn, sql, args, || {
            "FATAL: multiple rows for the same block hash".to_string()
        })
        .map_err(Error::DBError)
    }

    /// Get a stacks header info by index block hash (i.e. by the hash of the burn block header
    /// hash and the block hash -- the hash of the primary key)
    pub fn get_stacks_block_header_info_by_index_block_hash(
        conn: &Connection,
        index_block_hash: &StacksBlockId,
    ) -> Result<Option<StacksHeaderInfo>, Error> {
        let sql = "SELECT * FROM block_headers WHERE index_block_hash = ?1";
        query_row_panic(conn, sql, &[&index_block_hash], || {
            "FATAL: multiple rows for the same block hash".to_string()
        })
        .map_err(Error::DBError)
    }

    /// Get a stacks header info by its sortition's consensus hash.
    /// Because the consensus hash mixes in the burnchain header hash and the PoX bit vector,
    /// it's guaranteed to be unique across all burnchain forks and all PoX forks, and thus all
    /// Stacks forks.
    pub fn get_stacks_block_header_info_by_consensus_hash(
        conn: &Connection,
        consensus_hash: &ConsensusHash,
    ) -> Result<Option<StacksHeaderInfo>, Error> {
        let sql = "SELECT * FROM block_headers WHERE consensus_hash = ?1";
        query_row_panic(conn, sql, &[&consensus_hash], || {
            "FATAL: multiple rows for the same consensus hash".to_string()
        })
        .map_err(Error::DBError)
    }

    /// Get a stacks header info by its sortition's burnchain header hash.
    /// If there are multiple at a given burn view, all will be returned by stacks block height descending.
    pub fn get_stacks_block_header_info_by_burn_header_hash(
        conn: &Connection,
        burnchain_header_hash: &BurnchainHeaderHash,
    ) -> Result<Vec<StacksHeaderInfo>, Error> {
        let sql = "
            SELECT *
            FROM block_headers
            WHERE burn_header_hash = ?1
            ORDER BY block_height DESC
        ";
        let out = query_rows(conn, sql, &[&burnchain_header_hash])?;
        if !out.is_empty() {
            return Ok(out);
        }
        Err(Error::NoSuchBlockError)
    }

    /// Get a stacks header info by its sortition's burn block height
    /// If there are multiple at a given burn height, all will be returned by stacks block height descending.
    pub fn get_stacks_block_header_info_by_burn_header_height(
        conn: &Connection,
        burn_header_height: u64,
    ) -> Result<Vec<StacksHeaderInfo>, Error> {
        let sql = "
            SELECT * 
            FROM block_headers 
            WHERE burn_header_height = ?1
            ORDER BY block_height DESC
        ";
        let out = query_rows(conn, sql, &[&burn_header_height])?;
        if !out.is_empty() {
            return Ok(out);
        }
        Err(Error::NoSuchBlockError)
    }

    /// Get an ancestor block header
    pub fn get_tip_ancestor(
        tx: &mut StacksDBTx,
        tip: &StacksHeaderInfo,
        height: u64,
    ) -> Result<Option<StacksHeaderInfo>, Error> {
        assert!(tip.stacks_block_height >= height);
        StacksChainState::get_index_tip_ancestor(tx, &tip.index_block_hash(), height)
    }

    /// Get an ancestor block header given an index hash
    pub fn get_index_tip_ancestor(
        tx: &mut StacksDBTx,
        tip_index_hash: &StacksBlockId,
        height: u64,
    ) -> Result<Option<StacksHeaderInfo>, Error> {
        match tx
            .get_ancestor_block_hash(height, tip_index_hash)
            .map_err(Error::DBError)?
        {
            Some(bhh) => {
                StacksChainState::get_stacks_block_header_info_by_index_block_hash(tx, &bhh)
            }
            None => Ok(None),
        }
    }

    /// Get a segment of headers from the canonical chain
    pub fn get_ancestors_headers(
        conn: &Connection,
        upper_bound_header: StacksHeaderInfo,
        lower_bound_height: u64,
    ) -> Result<Vec<StacksHeaderInfo>, Error> {
        let mut ancestors = vec![];
        let mut ancestry_cursor = Some(upper_bound_header);
        while let Some(cursor) = ancestry_cursor.take() {
            if cursor.stacks_block_height < lower_bound_height {
                break;
            }
            let block_id = cursor.index_block_hash();
            ancestors.push(cursor.clone());
            let parent_block_id = StacksChainState::get_parent_block_id(conn, &block_id)?;
            if let Some(parent_block_id) = parent_block_id {
                ancestry_cursor =
                    StacksChainState::get_stacks_block_header_info_by_index_block_hash(
                        conn,
                        &parent_block_id,
                    )?;
            } else {
                ancestry_cursor = None;
            }
        }
        Ok(ancestors)
    }

    /// Get the genesis (boot code) block header
    pub fn get_genesis_header_info(conn: &Connection) -> Result<StacksHeaderInfo, Error> {
        // by construction, only one block can have height 0 in this DB
        let sql = "SELECT * FROM block_headers WHERE consensus_hash = ?1 AND block_height = 0";
        let args = params![FIRST_BURNCHAIN_CONSENSUS_HASH];
        let row_opt = query_row(conn, sql, args)?;
        Ok(row_opt.expect("BUG: no genesis header info"))
    }

    /// Get the parent block ID for this block
    pub fn get_parent_block_id(
        conn: &Connection,
        block_id: &StacksBlockId,
    ) -> Result<Option<StacksBlockId>, Error> {
        let sql = "SELECT parent_block_id FROM block_headers WHERE index_block_hash = ?1 LIMIT 1";
        let args = params![block_id];
        let mut rows = query_row_columns::<StacksBlockId, _>(conn, sql, args, "parent_block_id")?;
        Ok(rows.pop())
    }

    /// Is this block present and processed?
    pub fn has_stacks_block(conn: &Connection, block_id: &StacksBlockId) -> Result<bool, Error> {
        let sql = "SELECT 1 FROM block_headers WHERE index_block_hash = ?1 LIMIT 1";
        let args = params![block_id];
        Ok(conn
            .query_row(sql, args, |_r| Ok(()))
            .optional()
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?
            .is_some())
    }

    /// Load up the past N ancestors' index block hashes of a given block, *including* the given
    /// index_block_hash.  The returned vector will contain the following hashes, in this order
    ///     * index_block_hash
    ///     * 1st ancestor of index_block_hash
    ///     * 2nd ancestor of index_block_hash
    ///     ...
    ///     * Nth ancestor of index_block_hash
    pub fn get_ancestor_index_hashes(
        conn: &Connection,
        index_block_hash: &StacksBlockId,
        count: u64,
    ) -> Result<Vec<StacksBlockId>, Error> {
        let mut ret = vec![index_block_hash.clone()];
        for _i in 0..count {
            let parent_index_block_hash = {
                let cur_index_block_hash = ret.last().expect("FATAL: empty list of ancestors");
                match StacksChainState::get_parent_block_id(conn, cur_index_block_hash)? {
                    Some(ibhh) => ibhh,
                    None => {
                        // out of ancestors
                        break;
                    }
                }
            };
            ret.push(parent_index_block_hash);
        }
        Ok(ret)
    }

    /// Get the highest known header height
    pub fn get_max_header_height(conn: &Connection) -> Result<u64, Error> {
        let qry = "SELECT block_height FROM block_headers ORDER BY block_height DESC LIMIT 1";
        query_row(conn, qry, NO_PARAMS)
            .map(|row_opt: Option<i64>| row_opt.map(|h| h as u64).unwrap_or(0))
            .map_err(|e| e.into())
    }
}

/// Concrete [`crate::chainstate::stacks::index::squash_recover::CanonicalView`] implementation
/// backed by the chainstate's headers tables. Builds a `height -> index_block_hash` map by walking
/// back from a supplied tip through `block_headers` / `nakamoto_block_headers` (both tables are
/// consulted; the row that matches by `index_block_hash` wins regardless of which table holds it).
///
/// Lives in the chainstate-domain headers module rather than the MARF index module because the
/// `block_headers` / `nakamoto_block_headers` schemas are chainstate concepts; the MARF stays
/// agnostic about *which* DB supplies the canonical view by depending only on the
/// `CanonicalView` trait.
///
/// **Tip resolution is the caller's job.** The view doesn't know which tip is canonical — that
/// determination lives in the SortitionDB (per
/// [`crate::chainstate::burn::db::sortdb::SortitionDB::get_canonical_stacks_chain_tip_hash_and_height`]).
/// Production startup wires this together by opening the SortitionDB first, asking it for the
/// canonical tip, then constructing this view from the headers connection.
///
/// **Walk bound.** The constructor takes a `low_height` and walks at most
/// `tip_height - low_height + 1` steps. For squash recovery, `low_height` is set to the lowest
/// height across all pending plans; truncated ancestry (the walker hits a row whose parent
/// doesn't exist in headers) terminates the walk early without erroring — recovery's three-state
/// predicate treats unmapped heights as "skip".
pub struct HeadersCanonicalView {
    map: HashMap<u32, [u8; 32]>,
}

impl HeadersCanonicalView {
    /// Precompute the canonical chain map for `[low_height ..= tip_height]` by walking back from
    /// `tip` through the headers tables.
    pub fn precompute(
        conn: &Connection,
        tip: [u8; 32],
        tip_height: u32,
        low_height: u32,
    ) -> Result<Self, crate::chainstate::stacks::index::Error> {
        if low_height > tip_height {
            return Ok(Self {
                map: HashMap::new(),
            });
        }
        let walk_steps = tip_height.saturating_sub(low_height).saturating_add(1) as usize;
        let mut map: HashMap<u32, [u8; 32]> = HashMap::with_capacity(walk_steps);
        let mut current = tip;
        for _ in 0..walk_steps {
            let Some((height, parent)) = canonical_view_lookup_height_and_parent(conn, &current)?
            else {
                // Truncated ancestry — return whatever we've built so far. The recovery-side
                // divergence check treats unmapped heights as "skip", not as non-canonical.
                break;
            };
            if height < low_height {
                break;
            }
            map.insert(height, current);
            if parent == [0u8; 32] {
                break;
            }
            current = parent;
        }
        Ok(Self { map })
    }

    /// Number of (height -> hash) entries in the precomputed map. Diagnostic only.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Compute the lowest `min_height` across pending squash promotion plans on the given MARF
    /// database paths (typically the headers MARF and the clarity MARF). Used to bound the
    /// canonical-view walk in [`Self::from_sortdb_and_headers`]: only heights at or above the
    /// lowest pending plan need to be in the map, since the validation only consults heights
    /// inside `[plan.header.min_height ..= plan.header.max_height]`.
    ///
    /// Returns `Ok(0)` if no pending plans exist on any of the given paths — the canonical view
    /// will then walk the full chain, which is correct (just unnecessarily wide). Propagates a
    /// hard error if a plan file exists but can't be decoded; recovery itself would fail on the
    /// same plan, so surfacing the failure here is consistent with the recovery contract.
    pub fn lowest_pending_plan_height(
        marf_db_paths: &[&str],
    ) -> Result<u32, crate::chainstate::stacks::index::Error> {
        use crate::chainstate::stacks::index::squash_plan::{
            discover_pending_plans, read_plan_file,
        };
        let mut lowest: Option<u32> = None;
        for path in marf_db_paths {
            let plans = discover_pending_plans(path)?;
            for (_, plan_path) in plans {
                let plan = read_plan_file(&plan_path)?;
                let h = plan.header.min_height;
                lowest = Some(lowest.map(|x| x.min(h)).unwrap_or(h));
            }
        }
        Ok(lowest.unwrap_or(0))
    }

    /// Convenience constructor for the common run-loop pattern: derive the canonical Stacks tip
    /// from a [`crate::chainstate::burn::db::sortdb::SortitionDB`], then walk the supplied headers
    /// connection back to populate the view's `height -> hash` map.
    ///
    /// `low_height` bounds the walk — typically the lowest `min_height` across pending squash
    /// plans on the system. Pass `0` if no plan-driven lower bound is available; the precompute
    /// will then walk the full canonical chain. See [`Self::precompute`] for walk semantics.
    ///
    /// **Bootstrap signal**: returns `Ok(None)` ONLY when the SortitionDB explicitly reports no
    /// canonical Stacks tip (`db_error::NotFoundError`) — i.e., pristine bootstrap before any
    /// sortition has elected a Stacks block. Real SortitionDB errors propagate as `Err(...)`;
    /// callers must NOT silently fall through to `DrainPolicy::TrustPlan` on transient SQL
    /// errors, which would reintroduce the stale-plan publish bug this refactor closes.
    ///
    /// **Tip-resolution constraint**: this calls
    /// [`crate::chainstate::burn::db::sortdb::SortitionDB::get_canonical_stacks_chain_tip_hash_and_height`],
    /// which is documented as unsafe to call during Stacks block processing because it returns
    /// latest-data-known-to-the-node, not historical-block-assembly state. At startup this is
    /// fine (no block processing thread exists). Don't call this from a chains-coordinator
    /// context — see the warning on `chainstate.recover()`.
    pub fn from_sortdb_and_headers(
        sortdb: &crate::chainstate::burn::db::sortdb::SortitionDB,
        headers_conn: &Connection,
        low_height: u32,
    ) -> Result<Option<Self>, crate::chainstate::stacks::index::Error> {
        match crate::chainstate::burn::db::sortdb::SortitionDB::get_canonical_stacks_chain_tip_hash_and_height(
            sortdb.conn(),
        ) {
            Ok((consensus_hash, block_header_hash, tip_height)) => {
                let stacks_tip = StacksBlockHeader::make_index_block_hash(
                    &consensus_hash,
                    &block_header_hash,
                );
                let tip_bytes: [u8; 32] = *stacks_tip.as_bytes();
                if tip_bytes == [0u8; 32] {
                    // Sentinel tip — no canonical chain yet.
                    return Ok(None);
                }
                let view = Self::precompute(
                    headers_conn,
                    tip_bytes,
                    tip_height as u32,
                    low_height,
                )?;
                Ok(Some(view))
            }
            // Bootstrap-no-tip-yet is the ONLY error condition that falls through to None.
            // Anything else (SQLite error, schema mismatch, etc.) propagates so the run loop
            // surfaces the failure instead of silently downgrading to `DrainPolicy::TrustPlan`.
            Err(db_error::NotFoundError) => Ok(None),
            Err(e) => Err(crate::chainstate::stacks::index::Error::from(e)),
        }
    }

    /// Constructor for the **runtime publish gate** (chains-coordinator context, called inside
    /// [`crate::chainstate::stacks::db::StacksChainState::poll_pending_promotions`]). Anchors
    /// the view at the chainstate's just-advanced canonical Stacks tip + height — the SAME
    /// values [`crate::chainstate::stacks::db::StacksChainState::assert_squash_consistency`]
    /// uses to walk its divergence-detection map.
    ///
    /// **Why not [`Self::from_sortdb_and_headers`] in this context**: the sortdb-anchored
    /// constructor calls `SortitionDB::get_canonical_stacks_chain_tip_hash_and_height`, which
    /// returns latest-data-known-to-the-node (NOT historical-block-assembly state). During
    /// block processing the sortdb's view of canonical can disagree with the chainstate's
    /// just-advanced tip — they may walk back through *different forks* at intermediate
    /// heights. If the publish gate validates against the sortdb's fork while
    /// `assert_squash_consistency` later validates against the chainstate's fork, a level
    /// that passed the gate can still trip divergence detection on a subsequent block. This
    /// is the runtime stale-tip bug surfaced by mainnet sync at level-18 / clarity height
    /// 33190 (`a26614da...` recorded vs live canonical `1281f99b...`).
    ///
    /// `low_height` bounds the walk — typically the lowest `min_height` across pending squash
    /// plans on the system (see [`Self::lowest_pending_plan_height`]).
    pub fn from_chainstate_tip(
        headers_conn: &Connection,
        tip: &StacksBlockId,
        tip_height: u32,
        low_height: u32,
    ) -> Result<Self, crate::chainstate::stacks::index::Error> {
        let tip_bytes: [u8; 32] = *tip.as_bytes();
        Self::precompute(headers_conn, tip_bytes, tip_height, low_height)
    }
}

impl crate::chainstate::stacks::index::squash_recover::CanonicalView for HeadersCanonicalView {
    fn canonical_at_height(
        &self,
        height: u32,
    ) -> Result<Option<[u8; 32]>, crate::chainstate::stacks::index::Error> {
        Ok(self.map.get(&height).copied())
    }
}

/// Look up `(height, parent_index_block_hash)` for the given index_block_hash. Consults both
/// the 2.x `block_headers` and Nakamoto `nakamoto_block_headers` tables; the first match wins.
/// Returns `Ok(None)` if the hash isn't recorded in either table — the caller treats this as
/// truncated ancestry and stops walking.
///
/// **Production schema**: both tables store `index_block_hash` and `parent_block_id` as
/// `TEXT` (lowercase hex strings, 64 chars), NOT as `BLOB` ([db/mod.rs](`block_headers`
/// schema), [db/mod.rs](`nakamoto_block_headers` schema)). Queries that bind raw 32-byte
/// `&[u8]` against these TEXT columns silently return zero rows because SQLite's type
/// affinity treats the binding as a BLOB and the WHERE comparison fails. The previous
/// implementation hit exactly that mismatch — its unit tests used a synthetic BLOB schema
/// and passed, but production reads of `HeadersCanonicalView` returned an empty map (every
/// height "unmapped"), causing the divergence detector and the publish gate to skip every
/// validation. Mainnet sync at clarity level 5 / height 19141 surfaced this as a
/// post-publish divergence panic.
///
/// `StacksBlockId` (as a `MarfTrieId`) implements `ToSql` as the lowercase hex string, so
/// binding via `params![&block_id]` matches production rows. The returned `parent_block_id`
/// is read as `String` (hex) and decoded back to `[u8; 32]`.
///
/// Mirrors the private `StacksChainState::lookup_height_and_parent` but returns the index
/// Error type used by the [`crate::chainstate::stacks::index::squash_recover::CanonicalView`]
/// trait.
fn canonical_view_lookup_height_and_parent(
    conn: &Connection,
    index_block_hash: &[u8; 32],
) -> Result<Option<(u32, [u8; 32])>, crate::chainstate::stacks::index::Error> {
    let bhh = StacksBlockId(*index_block_hash);
    let sql_2x = "SELECT block_height, parent_block_id FROM block_headers \
                  WHERE index_block_hash = ?1";
    if let Some(row) = conn
        .query_row(sql_2x, params![&bhh], |r| {
            let height: i64 = r.get(0)?;
            let parent_hex: String = r.get(1)?;
            Ok((height, parent_hex))
        })
        .optional()?
    {
        let parent_arr = canonical_view_decode_index_block_hash_hex(&row.1)?;
        return Ok(Some((row.0 as u32, parent_arr)));
    }
    let sql_nak = "SELECT block_height, parent_block_id FROM nakamoto_block_headers \
                   WHERE index_block_hash = ?1";
    let row = conn
        .query_row(sql_nak, params![&bhh], |r| {
            let height: i64 = r.get(0)?;
            let parent_hex: String = r.get(1)?;
            Ok((height, parent_hex))
        })
        .optional()?;
    Ok(row
        .map(|(h, p_hex)| {
            canonical_view_decode_index_block_hash_hex(&p_hex)
                .map(|parent_arr| (h as u32, parent_arr))
        })
        .transpose()?)
}

/// Decode a `parent_block_id` value read from `block_headers` / `nakamoto_block_headers` as
/// a 64-char lowercase hex string (production schema) into 32 raw bytes. Returns
/// `CorruptionError` if the string isn't valid hex of the expected length.
fn canonical_view_decode_index_block_hash_hex(
    hex_str: &str,
) -> Result<[u8; 32], crate::chainstate::stacks::index::Error> {
    if hex_str.len() != 64 {
        return Err(crate::chainstate::stacks::index::Error::CorruptionError(
            format!(
                "headers table row has parent_block_id of unexpected length {} (expected 64 \
                 hex chars)",
                hex_str.len(),
            ),
        ));
    }
    let bytes = stacks_common::util::hash::hex_bytes(hex_str).map_err(|e| {
        crate::chainstate::stacks::index::Error::CorruptionError(format!(
            "headers table row parent_block_id is not valid hex: {e}"
        ))
    })?;
    bytes.as_slice().try_into().map_err(|_| {
        crate::chainstate::stacks::index::Error::CorruptionError(format!(
            "headers table row parent_block_id decoded to unexpected length {} (expected 32)",
            bytes.len(),
        ))
    })
}

#[cfg(test)]
mod canonical_view_tests {
    use rusqlite::{params, Connection};

    use super::HeadersCanonicalView;
    use crate::chainstate::stacks::index::squash_recover::CanonicalView;

    /// Minimal schema mirroring the **production** column types: `index_block_hash` and
    /// `parent_block_id` are `TEXT` (lowercase hex strings), NOT `BLOB`. Avoids pulling in
    /// the full chainstate migration chain — these tests target the SQL-walk + decode logic
    /// in isolation, but they MUST match the production column types so query bindings
    /// behave identically. The earlier BLOB-based test schema let the queries pass in tests
    /// while silently no-matching on production rows (mainnet level-5 divergence panic).
    fn fresh_minimal_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute(
            "CREATE TABLE block_headers (\
                index_block_hash TEXT PRIMARY KEY, \
                block_height INTEGER NOT NULL, \
                parent_block_id TEXT NOT NULL\
            )",
            params![],
        )
        .unwrap();
        conn.execute(
            "CREATE TABLE nakamoto_block_headers (\
                index_block_hash TEXT PRIMARY KEY, \
                block_height INTEGER NOT NULL, \
                parent_block_id TEXT NOT NULL\
            )",
            params![],
        )
        .unwrap();
        conn
    }

    fn hex_str(bytes: &[u8; 32]) -> String {
        stacks_common::util::hash::to_hex(bytes)
    }

    fn insert_2x(conn: &Connection, hash: [u8; 32], height: u32, parent: [u8; 32]) {
        conn.execute(
            "INSERT INTO block_headers (index_block_hash, block_height, parent_block_id) \
             VALUES (?1, ?2, ?3)",
            params![hex_str(&hash), height as i64, hex_str(&parent)],
        )
        .unwrap();
    }

    fn insert_nak(conn: &Connection, hash: [u8; 32], height: u32, parent: [u8; 32]) {
        conn.execute(
            "INSERT INTO nakamoto_block_headers (index_block_hash, block_height, parent_block_id) \
             VALUES (?1, ?2, ?3)",
            params![hex_str(&hash), height as i64, hex_str(&parent)],
        )
        .unwrap();
    }

    /// 4-block chain: sentinel → b1@0 → b2@1 → b3@2 → b4@3. Walk from tip down to height 0.
    #[test]
    fn precompute_full_chain_in_2x_table() {
        let conn = fresh_minimal_db();
        let sentinel = [0u8; 32];
        let b1 = [0x01; 32];
        let b2 = [0x02; 32];
        let b3 = [0x03; 32];
        let b4 = [0x04; 32];
        insert_2x(&conn, b1, 0, sentinel);
        insert_2x(&conn, b2, 1, b1);
        insert_2x(&conn, b3, 2, b2);
        insert_2x(&conn, b4, 3, b3);

        let view = HeadersCanonicalView::precompute(&conn, b4, 3, 0).unwrap();

        assert_eq!(view.len(), 4);
        assert_eq!(view.canonical_at_height(0).unwrap(), Some(b1));
        assert_eq!(view.canonical_at_height(1).unwrap(), Some(b2));
        assert_eq!(view.canonical_at_height(2).unwrap(), Some(b3));
        assert_eq!(view.canonical_at_height(3).unwrap(), Some(b4));
    }

    /// `low_height` constrains the walk: only heights >= low_height end up in the map.
    #[test]
    fn precompute_respects_low_height() {
        let conn = fresh_minimal_db();
        let sentinel = [0u8; 32];
        let b1 = [0x01; 32];
        let b2 = [0x02; 32];
        let b3 = [0x03; 32];
        let b4 = [0x04; 32];
        insert_2x(&conn, b1, 0, sentinel);
        insert_2x(&conn, b2, 1, b1);
        insert_2x(&conn, b3, 2, b2);
        insert_2x(&conn, b4, 3, b3);

        let view = HeadersCanonicalView::precompute(&conn, b4, 3, /* low */ 2).unwrap();

        assert_eq!(view.len(), 2, "only heights 2 and 3 should land in the map");
        assert_eq!(view.canonical_at_height(2).unwrap(), Some(b3));
        assert_eq!(view.canonical_at_height(3).unwrap(), Some(b4));
        assert_eq!(view.canonical_at_height(0).unwrap(), None);
        assert_eq!(view.canonical_at_height(1).unwrap(), None);
    }

    /// `low_height > tip_height` returns an empty map (the height range is empty).
    #[test]
    fn precompute_low_height_above_tip_yields_empty_map() {
        let conn = fresh_minimal_db();
        let b1 = [0x01; 32];
        insert_2x(&conn, b1, 0, [0u8; 32]);

        let view = HeadersCanonicalView::precompute(&conn, b1, 0, 5).unwrap();
        assert_eq!(view.len(), 0);
        assert_eq!(view.canonical_at_height(0).unwrap(), None);
    }

    /// Truncated ancestry: tip points at a hash whose parent isn't recorded in either table.
    /// The walk records what it can, then terminates early.
    #[test]
    fn precompute_truncated_ancestry_terminates_early() {
        let conn = fresh_minimal_db();
        // b3 -> b2 -> (parent missing from headers)
        let b2 = [0x02; 32];
        let b3 = [0x03; 32];
        let phantom_parent = [0x77; 32];
        insert_2x(&conn, b2, 5, phantom_parent); // parent not in db
        insert_2x(&conn, b3, 6, b2);

        let view = HeadersCanonicalView::precompute(&conn, b3, 6, 0).unwrap();

        assert_eq!(view.len(), 2);
        assert_eq!(view.canonical_at_height(6).unwrap(), Some(b3));
        assert_eq!(view.canonical_at_height(5).unwrap(), Some(b2));
        // No height 0..4 present — the walker stopped when phantom_parent's lookup returned None.
        assert_eq!(view.canonical_at_height(4).unwrap(), None);
        assert_eq!(view.canonical_at_height(0).unwrap(), None);
    }

    /// Sentinel parent (all-zero bytes) terminates the walk.
    #[test]
    fn precompute_stops_on_sentinel_parent() {
        let conn = fresh_minimal_db();
        let b1 = [0x01; 32];
        insert_2x(&conn, b1, 0, [0u8; 32]); // sentinel parent

        let view = HeadersCanonicalView::precompute(&conn, b1, 0, 0).unwrap();
        assert_eq!(view.len(), 1);
        assert_eq!(view.canonical_at_height(0).unwrap(), Some(b1));
    }

    /// Tip in `nakamoto_block_headers` (epoch 3.x) instead of `block_headers`. The walker
    /// consults both tables, so this should produce identical results.
    #[test]
    fn precompute_walks_nakamoto_table() {
        let conn = fresh_minimal_db();
        let b1 = [0x01; 32];
        let b2 = [0x02; 32];
        insert_nak(&conn, b1, 0, [0u8; 32]);
        insert_nak(&conn, b2, 1, b1);

        let view = HeadersCanonicalView::precompute(&conn, b2, 1, 0).unwrap();
        assert_eq!(view.len(), 2);
        assert_eq!(view.canonical_at_height(0).unwrap(), Some(b1));
        assert_eq!(view.canonical_at_height(1).unwrap(), Some(b2));
    }

    /// Mixed-table chain: epoch 2.x ancestors with a Nakamoto tip. The walker hits Nakamoto
    /// first (recent), falls through to 2.x as it walks back. Validates that the table
    /// dispatch order doesn't lose ancestors.
    #[test]
    fn precompute_walks_mixed_2x_and_nakamoto() {
        let conn = fresh_minimal_db();
        let b1 = [0x01; 32]; // 2.x at height 10
        let b2 = [0x02; 32]; // 2.x at height 11
        let b3 = [0x03; 32]; // Nakamoto at height 12
        insert_2x(&conn, b1, 10, [0u8; 32]);
        insert_2x(&conn, b2, 11, b1);
        insert_nak(&conn, b3, 12, b2);

        let view = HeadersCanonicalView::precompute(&conn, b3, 12, 10).unwrap();
        assert_eq!(view.len(), 3);
        assert_eq!(view.canonical_at_height(10).unwrap(), Some(b1));
        assert_eq!(view.canonical_at_height(11).unwrap(), Some(b2));
        assert_eq!(view.canonical_at_height(12).unwrap(), Some(b3));
    }

    /// Heights outside the precomputed range return `None`. This is the contract recovery's
    /// three-state predicate relies on (None = "skip", not "non-canonical").
    #[test]
    fn canonical_at_height_outside_range_returns_none() {
        let conn = fresh_minimal_db();
        let b1 = [0x01; 32];
        insert_2x(&conn, b1, 5, [0u8; 32]);

        let view = HeadersCanonicalView::precompute(&conn, b1, 5, 5).unwrap();
        assert_eq!(view.canonical_at_height(5).unwrap(), Some(b1));
        assert_eq!(view.canonical_at_height(0).unwrap(), None);
        assert_eq!(view.canonical_at_height(100).unwrap(), None);
    }

    /// The walker's early-stop on `height < low_height` shouldn't drop a same-height entry.
    /// Pin the boundary: `low_height = N` means N is included, N-1 isn't.
    #[test]
    fn precompute_low_height_boundary_inclusive() {
        let conn = fresh_minimal_db();
        let sentinel = [0u8; 32];
        let b1 = [0x01; 32];
        let b2 = [0x02; 32];
        let b3 = [0x03; 32];
        insert_2x(&conn, b1, 0, sentinel);
        insert_2x(&conn, b2, 1, b1);
        insert_2x(&conn, b3, 2, b2);

        let view = HeadersCanonicalView::precompute(&conn, b3, 2, /* low */ 1).unwrap();
        assert_eq!(view.len(), 2);
        assert_eq!(view.canonical_at_height(1).unwrap(), Some(b2));
        assert_eq!(view.canonical_at_height(2).unwrap(), Some(b3));
        assert_eq!(view.canonical_at_height(0).unwrap(), None);
    }
}
