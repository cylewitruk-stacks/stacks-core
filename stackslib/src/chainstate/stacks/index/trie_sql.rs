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

use std::io::{Read, Seek, SeekFrom, Write};

use rusqlite::blob::Blob;
use rusqlite::{params, Connection, DatabaseName, OptionalExtension, Transaction};

use crate::chainstate::stacks::index::node::{TrieNodeID, TriePtr};
#[cfg(test)]
use crate::chainstate::stacks::index::storage;
use crate::chainstate::stacks::index::{
    bits, trie_sql, Error, MarfTrieId, NodeDecodeScratch, ReadTrieItem, ReadTrieNode,
};
use crate::types::chainstate::TrieHash;
use crate::types::sqlite::NO_PARAMS;
use crate::util_lib::db;

static SQL_MARF_DATA_TABLE: &str = "
CREATE TABLE IF NOT EXISTS marf_data (
   block_id INTEGER PRIMARY KEY, 
   block_hash TEXT UNIQUE NOT NULL,
   -- the trie itself.
   -- if not used, then set to a zero-byte entry.
   data BLOB NOT NULL,
   unconfirmed INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS block_hash_marf_data ON marf_data(block_hash);
CREATE INDEX IF NOT EXISTS unconfirmed_marf_data ON marf_data(unconfirmed);
";
static SQL_MARF_MINED_TABLE: &str = "
CREATE TABLE IF NOT EXISTS mined_blocks (
   block_id INTEGER PRIMARY KEY, 
   block_hash TEXT UNIQUE NOT NULL,
   data BLOB NOT NULL
);

CREATE INDEX IF NOT EXISTS block_hash_mined_blocks ON mined_blocks(block_hash);
";

static SQL_EXTENSION_LOCKS_TABLE: &str = "
CREATE TABLE IF NOT EXISTS block_extension_locks (block_hash TEXT PRIMARY KEY);
";

static SQL_MARF_DATA_TABLE_SCHEMA_2: &str = "
-- pointer to a .blobs file with the externally-stored blob data.
-- if not used, then set to 1.
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER DEFAULT 1 NOT NULL
);
CREATE TABLE IF NOT EXISTS migrated_version (
    version INTEGER DEFAULT 1 NOT NULL
);
ALTER TABLE marf_data ADD COLUMN external_offset INTEGER DEFAULT 0 NOT NULL;
ALTER TABLE marf_data ADD COLUMN external_length INTEGER DEFAULT 0 NOT NULL;
CREATE INDEX IF NOT EXISTS index_external_offset ON marf_data(external_offset);

DELETE FROM schema_version;
INSERT INTO schema_version (version) VALUES (2);
DELETE FROM migrated_version;
INSERT INTO migrated_version (version) VALUES (1);
";

pub static SQL_MARF_SCHEMA_VERSION: u64 = 3;

/// Schema 3 — squashing v1.5 consolidated DDL.
///
/// **Consolidation note (Phase D, 2026-05-03)**: this branch's earlier
/// development carried a v3 / v4 / v5 ladder of incremental migrations:
///
/// - v3 added `marf_squash_levels`.
/// - v4 added `marf_squash_levels.published_max_block_id`.
/// - v5 added `marf_data.storage_kind` / `storage_seq`, the
///   `idx_marf_data_hot` partial index, and the `marf_state` singleton.
///
/// Mainnet is on v2. Since this branch hasn't shipped to mainnet yet,
/// we collapse v3-v5 into a single v2→v3 jump rather than carrying three
/// migration steps no real chainstate ever ran. The `marf_retired_squash_levels`
/// table (B6.3 vestigial; no Phase A/B/C code reads or writes it) is
/// dropped entirely. See
/// [.docs/squashing-v1.5-phase-d.md](../../../../../.docs/squashing-v1.5-phase-d.md)
/// for the consolidation rationale.
///
/// Existing v2 chainstates migrate forward in one step:
///
/// 1. `marf_squash_levels` table created (with `published_max_block_id`
///    already in the DDL — no separate v4 ALTER).
/// 2. `marf_data` gains `storage_kind` + `storage_seq` (existing rows
///    get `storage_kind = 0`, treated as cold — preserves today's
///    `<db>.blobs`-only layout for any pre-v3 chainstate).
/// 3. `idx_marf_data_hot` partial index created (cheap on existing
///    storage_kind = 0 rows since they're filtered out).
/// 4. `marf_state` singleton row inserted.
static SQL_MARF_DATA_TABLE_SCHEMA_3: &str = "
CREATE TABLE IF NOT EXISTS marf_squash_levels (
    level_id INTEGER PRIMARY KEY,
    min_height INTEGER NOT NULL,
    max_height INTEGER NOT NULL,
    blob_offset INTEGER NOT NULL,
    blob_length INTEGER NOT NULL,
    reads_redirected INTEGER NOT NULL DEFAULT 0,
    -- Per-height root node sidecar tracking. `present`: true when this level
    -- has a published root sidecar file at the canonical path. `trimmed`:
    -- reserved for the eventual trim policy; v1 always 0.
    root_sidecar_present INTEGER NOT NULL DEFAULT 0,
    root_sidecar_trimmed INTEGER NOT NULL DEFAULT 0,
    -- TriePtr-style logical offset (relative to BLOB_HEADER_SIZE) at which
    -- orphan structural nodes begin. Tip-reachable nodes have all direct
    -- child ptrs in [BLOB_HEADER_SIZE .. orphan_split_offset); orphan nodes
    -- live in [orphan_split_offset ..). 0 means no split (no orphans).
    orphan_split_offset INTEGER NOT NULL DEFAULT 0,
    -- Per-MARF squash-work watermark. Backs the cadence policy's reconstruction
    -- of 'bytes since last squash' at startup (see
    -- .docs/adaptive-squash-cadence.md §3.2.1). Existing rows get 0; the next
    -- successful squash writes a real publish-time watermark.
    published_max_block_id INTEGER NOT NULL DEFAULT 0,
    -- Per-level FullHistory history-blob state. See
    -- .docs/full-history-history-blob-design.md §10.1 for the value semantics:
    --   'never_written' — TipOnly-mode level; no history blob file on disk
    --   'present'       — FullHistory level with a valid history blob file
    --   'trimmed'       — operator (or auto-trim §10.3) has unlinked the file;
    --                     at-block reads return Error::HistoryTrimmed
    -- The DEFAULT 'never_written' is correct for any row that doesn't
    -- explicitly set the column at insert time (TipOnly publish path).
    history_blob_state TEXT NOT NULL DEFAULT 'never_written'
        CHECK (history_blob_state IN ('never_written', 'present', 'trimmed'))
);

ALTER TABLE marf_data ADD COLUMN storage_kind INTEGER NOT NULL DEFAULT 0;
ALTER TABLE marf_data ADD COLUMN storage_seq INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_marf_data_hot
    ON marf_data(storage_seq) WHERE storage_kind = 1;

CREATE TABLE IF NOT EXISTS marf_state (
    id                          INTEGER PRIMARY KEY CHECK (id = 1),
    active_hot_seq              INTEGER NOT NULL DEFAULT 1,
    horizon_burn_blocks         INTEGER NOT NULL DEFAULT 6,
    -- Single-flight promotion lock (Phase B). Holds the level_id of an
    -- in-flight promotion or NULL when idle. The plan file's presence is
    -- the durable witness; this column is the in-process guard that
    -- prevents a second cadence tick from starting a second background
    -- promotion concurrently.
    promotion_in_progress       INTEGER          DEFAULT NULL,
    -- Reserved cold-blob extent for the in-flight promotion. The
    -- 'next cold append offset' computation is
    -- (committed level extents' end) + (this reservation when non-NULL).
    promotion_reserved_offset   INTEGER          DEFAULT NULL,
    promotion_reserved_length   INTEGER          DEFAULT NULL,
    -- One-shot gate for the post-epoch-3.4 history-blob auto-trim
    -- (.docs/full-history-history-blob-design.md §10.3). Default 0
    -- (false). Set to 1 (true) by the chains-coordinator after the
    -- auto-trim batch completes; subsequent boots skip the trigger
    -- check on seeing 1.
    auto_trim_done              INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO marf_state (id) VALUES (1);

DELETE FROM schema_version;
INSERT INTO schema_version (version) VALUES (3);
DELETE FROM migrated_version;
INSERT INTO migrated_version (version) VALUES (3);
";

pub fn create_tables_if_needed(conn: &mut Connection) -> Result<(), Error> {
    let tx = db::tx_begin_immediate(conn)?;

    tx.execute_batch(SQL_MARF_DATA_TABLE)?;
    tx.execute_batch(SQL_MARF_MINED_TABLE)?;
    tx.execute_batch(SQL_EXTENSION_LOCKS_TABLE)?;

    tx.commit().map_err(|e| e.into())
}

fn get_schema_version(conn: &Connection) -> u64 {
    // if the table doesn't exist, then the version is 1.
    let sql = "SELECT COALESCE(MAX(version), 1) AS version FROM schema_version";
    match conn.query_row(sql, NO_PARAMS, |row| row.get::<_, i64>("version")) {
        Ok(x) => x as u64,
        Err(e) => {
            debug!("Failed to get schema version: {:?}", &e);
            1u64
        }
    }
}

/// Get the last schema version before the last attempted migration
fn get_migrated_version(conn: &Connection) -> u64 {
    // if the table doesn't exist, then the version is 1.
    let sql = "SELECT COALESCE(MAX(version), 1) AS version FROM migrated_version";
    match conn.query_row(sql, NO_PARAMS, |row| row.get::<_, i64>("version")) {
        Ok(x) => x as u64,
        Err(e) => {
            debug!("Failed to get schema version: {:?}", &e);
            1u64
        }
    }
}

/// Migrate the MARF database to the currently-supported schema.
/// Returns the version of the DB prior to the migration.
pub fn migrate_tables_if_needed<T: MarfTrieId>(conn: &mut Connection) -> Result<u64, Error> {
    let first_version = get_schema_version(conn);
    loop {
        let version = get_schema_version(conn);
        match version {
            1 => {
                debug!("Migrate MARF data from schema 1 to schema 2");

                // add external_* fields
                let tx = db::tx_begin_immediate(conn)?;
                tx.execute_batch(SQL_MARF_DATA_TABLE_SCHEMA_2)?;
                tx.commit()?;
            }
            2 => {
                debug!("Migrate MARF data from schema 2 to schema 3(v1.5 consolidated)");

                // Squashing v1.5 consolidated migration: v3 + (formerly v4) +
                // (formerly v5), in one transaction. See SQL_MARF_DATA_TABLE_SCHEMA_3
                // doc comment for the consolidation rationale.
                let tx = db::tx_begin_immediate(conn)?;
                tx.execute_batch(SQL_MARF_DATA_TABLE_SCHEMA_3)?;
                tx.commit()?;
            }
            x if x == SQL_MARF_SCHEMA_VERSION => {
                // done
                debug!("Migrated MARF data to schema {}", &SQL_MARF_SCHEMA_VERSION);
                break;
            }
            x => {
                let msg = format!(
                    "Unable to migrate MARF data table: unrecognized schema {}",
                    x
                );
                error!("{}", &msg);
                panic!("{}", &msg);
            }
        }
    }
    if first_version == SQL_MARF_SCHEMA_VERSION
        && get_migrated_version(conn) != SQL_MARF_SCHEMA_VERSION
        && !trie_sql::detect_partial_migration(conn)?
    {
        // no migration will need to happen, so stop checking
        debug!("Marking MARF data as fully-migrated");
        set_migrated(conn)?;
    }
    Ok(first_version)
}

pub fn get_block_identifier<T: MarfTrieId>(conn: &Connection, bhh: &T) -> Result<u32, Error> {
    conn.query_row(
        "SELECT block_id FROM marf_data WHERE block_hash = ?",
        &[bhh],
        |row| row.get("block_id"),
    )
    .map_err(|e| e.into())
}

pub fn get_mined_block_identifier<T: MarfTrieId>(conn: &Connection, bhh: &T) -> Result<u32, Error> {
    conn.query_row(
        "SELECT block_id FROM mined_blocks WHERE block_hash = ?",
        &[bhh],
        |row| row.get("block_id"),
    )
    .map_err(|e| e.into())
}

pub fn get_confirmed_block_identifier<T: MarfTrieId>(
    conn: &Connection,
    bhh: &T,
) -> Result<Option<u32>, Error> {
    conn.query_row(
        "SELECT block_id FROM marf_data WHERE block_hash = ? AND unconfirmed = 0",
        &[bhh],
        |row| row.get("block_id"),
    )
    .optional()
    .map_err(|e| e.into())
}

pub fn get_unconfirmed_block_identifier<T: MarfTrieId>(
    conn: &Connection,
    bhh: &T,
) -> Result<Option<u32>, Error> {
    conn.query_row(
        "SELECT block_id FROM marf_data WHERE block_hash = ? AND unconfirmed = 1",
        &[bhh],
        |row| row.get("block_id"),
    )
    .optional()
    .map_err(|e| e.into())
}

pub fn get_block_hash<T: MarfTrieId>(conn: &Connection, local_id: u32) -> Result<T, Error> {
    let result = conn
        .query_row(
            "SELECT block_hash FROM marf_data WHERE block_id = ?",
            params![local_id],
            |row| row.get("block_hash"),
        )
        .optional()?;
    result.ok_or_else(|| {
        error!("Failed to get block header hash of local ID {}", local_id);
        Error::NotFoundError
    })
}

/// Write a serialized trie to sqlite
pub fn write_trie_blob<T: MarfTrieId>(
    conn: &Connection,
    block_hash: &T,
    data: &[u8],
) -> Result<u32, Error> {
    let args = params![block_hash, data, 0, 0, 0,];
    let mut s =
        conn.prepare("INSERT INTO marf_data (block_hash, data, unconfirmed, external_offset, external_length) VALUES (?, ?, ?, ?, ?)")?;
    let block_id = s
        .insert(args)?
        .try_into()
        .expect("EXHAUSTION: MARF cannot track more than 2**31 - 1 blocks");

    debug!("Wrote block trie {} to rowid {}", block_hash, block_id);
    Ok(block_id)
}

/// Storage tier for an external trie blob, mirroring the on-disk
/// `marf_data.storage_kind` column. See `.docs/squashing-v1.5.md` §4.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageKind {
    /// Cold zone: bytes live in `<db>.blobs`. `storage_seq` is unused
    /// (always 0). Today's behavior for promoted (squashed) blocks and
    /// for any pre-v5 chainstate's existing rows.
    Cold,
    /// Hot zone: bytes live in `<db>.hot.{seq:08}`. `storage_seq` names
    /// which rolling hot file holds the bytes. Phase A's new write
    /// path lands here.
    Hot,
}

impl StorageKind {
    /// On-disk integer encoding (matches `marf_data.storage_kind`).
    pub fn to_int(self) -> i64 {
        match self {
            StorageKind::Cold => 0,
            StorageKind::Hot => 1,
        }
    }

    /// Decode an integer read from `marf_data.storage_kind`. Returns
    /// `Err` for unrecognized values to surface schema corruption.
    pub fn from_int(v: i64) -> Result<Self, Error> {
        match v {
            0 => Ok(StorageKind::Cold),
            1 => Ok(StorageKind::Hot),
            _ => Err(Error::CorruptionError(format!(
                "marf_data.storage_kind has unrecognized value {v}"
            ))),
        }
    }
}

/// Write the offset/length of a trie blob that was stored to an external file.
/// Do this only once the trie is actually stored, since only the presence of this information is
/// what guarantees that the blob is persisted.
/// If block_id is Some(..), then an existing block ID's metadata will be updated.  Otherwise, a
/// new row will be created.
///
/// `kind` and `seq` populate the `storage_kind` / `storage_seq` columns
/// added in schema 5. Cold writes pass `StorageKind::Cold` + `seq = 0`;
/// hot writes pass `StorageKind::Hot` + the active hot-file sequence.
fn inner_write_external_trie_blob<T: MarfTrieId>(
    conn: &Connection,
    block_hash: &T,
    offset: u64,
    length: u64,
    block_id: Option<u32>,
    kind: StorageKind,
    seq: u32,
) -> Result<u32, Error> {
    let block_id = if let Some(block_id) = block_id {
        // existing entry (i.e. a migration)
        let empty_blob: &[u8] = &[];
        let args = params![
            block_hash,
            empty_blob,
            0,
            db::u64_to_sql(offset)?,
            db::u64_to_sql(length)?,
            kind.to_int(),
            seq as i64,
            block_id,
        ];
        let mut s =
            conn.prepare("UPDATE marf_data SET block_hash = ?1, data = ?2, unconfirmed = ?3, external_offset = ?4, external_length = ?5, storage_kind = ?6, storage_seq = ?7 WHERE block_id = ?8")?;
        s.execute(args)?;

        debug!(
            "Replaced block trie {} at rowid {} offset {} (kind={:?}, seq={})",
            block_hash, block_id, offset, kind, seq
        );
        block_id
    } else {
        // new entry
        let empty_blob: &[u8] = &[];
        let args = params![
            block_hash,
            empty_blob,
            0,
            db::u64_to_sql(offset)?,
            db::u64_to_sql(length)?,
            kind.to_int(),
            seq as i64,
        ];
        let mut s =
            conn.prepare("INSERT INTO marf_data (block_hash, data, unconfirmed, external_offset, external_length, storage_kind, storage_seq) VALUES (?, ?, ?, ?, ?, ?, ?)")?;
        let block_id = s
            .insert(args)?
            .try_into()
            .expect("EXHAUSTION: MARF cannot track more than 2**31 - 1 blocks");

        debug!(
            "Wrote block trie {} to rowid {} offset {} (kind={:?}, seq={})",
            block_hash, block_id, offset, kind, seq
        );
        block_id
    };

    Ok(block_id)
}

/// Update the row for an external trie blob -- i.e. we're migrating blobs from sqlite storage to
/// file storage.
///
/// **Cold-zone only.** Blob-migration is a one-time path that pulls
/// inline-blob rows out into `<db>.blobs`; v1.5 doesn't migrate into the
/// hot zone (new writes go there directly via [`write_external_trie_blob_hot`]),
/// so this helper writes `storage_kind = Cold, storage_seq = 0`.
pub fn update_external_trie_blob<T: MarfTrieId>(
    conn: &Connection,
    block_hash: &T,
    offset: u64,
    length: u64,
    block_id: u32,
) -> Result<u32, Error> {
    inner_write_external_trie_blob(
        conn,
        block_hash,
        offset,
        length,
        Some(block_id),
        StorageKind::Cold,
        0,
    )
}

/// Add a new row for an external trie blob in the **cold zone**
/// (`<db>.blobs`).
///
/// Used by the squash-publish path (which appends merged blobs to
/// `<db>.blobs`) and by legacy code paths that pre-date the hot tier.
/// New block-write traffic in v1.5 goes through
/// [`write_external_trie_blob_hot`] instead.
pub fn write_external_trie_blob<T: MarfTrieId>(
    conn: &Connection,
    block_hash: &T,
    offset: u64,
    length: u64,
) -> Result<u32, Error> {
    inner_write_external_trie_blob(conn, block_hash, offset, length, None, StorageKind::Cold, 0)
}

/// Add a new row for an external trie blob in the **hot zone**
/// (`<db>.hot.{seq:08}`).
///
/// Phase A's new block-write path: each block append lands at
/// `(seq, offset)` in the rolling hot file, then this helper inserts a
/// `marf_data` row with `storage_kind = Hot, storage_seq = seq`. A
/// later squash publish (Phase B) flips the row back to cold by
/// promoting the bytes into `<db>.blobs`.
pub fn write_external_trie_blob_hot<T: MarfTrieId>(
    conn: &Connection,
    block_hash: &T,
    seq: u32,
    offset: u64,
    length: u64,
) -> Result<u32, Error> {
    inner_write_external_trie_blob(
        conn,
        block_hash,
        offset,
        length,
        None,
        StorageKind::Hot,
        seq,
    )
}

/// Write a serialized trie blob for a trie that was mined
pub fn write_trie_blob_to_mined<T: MarfTrieId>(
    conn: &Connection,
    block_hash: &T,
    data: &[u8],
) -> Result<u32, Error> {
    if let Ok(block_id) = get_mined_block_identifier(conn, block_hash) {
        // already exists; update
        let args = params![data, block_id];
        let mut s = conn.prepare("UPDATE mined_blocks SET data = ? WHERE block_id = ?")?;
        s.execute(args)
            .expect("EXHAUSTION: MARF cannot track more than 2**31 - 1 blocks");
    } else {
        // doesn't exist yet; insert
        let args = params![block_hash, data];
        let mut s = conn.prepare("INSERT INTO mined_blocks (block_hash, data) VALUES (?, ?)")?;
        s.execute(args)
            .expect("EXHAUSTION: MARF cannot track more than 2**31 - 1 blocks");
    };

    let block_id = get_mined_block_identifier(conn, block_hash)?;

    debug!(
        "Wrote mined block trie {} to rowid {}",
        block_hash, block_id
    );
    Ok(block_id)
}

/// Write a serialized unconfirmed trie blob
pub fn write_trie_blob_to_unconfirmed<T: MarfTrieId>(
    conn: &Connection,
    block_hash: &T,
    data: &[u8],
) -> Result<u32, Error> {
    if let Ok(Some(_)) = get_confirmed_block_identifier(conn, block_hash) {
        panic!("BUG: tried to overwrite confirmed MARF trie {}", block_hash);
    }

    if let Ok(Some(block_id)) = get_unconfirmed_block_identifier(conn, block_hash) {
        // already exists; update
        let args = params![data, block_id];
        let mut s = conn.prepare("UPDATE marf_data SET data = ? WHERE block_id = ?")?;
        s.execute(args)
            .expect("EXHAUSTION: MARF cannot track more than 2**31 - 1 blocks");
    } else {
        // doesn't exist yet; insert
        let args = params![block_hash, data, 1];
        let mut s =
            conn.prepare("INSERT INTO marf_data (block_hash, data, unconfirmed, external_offset, external_length) VALUES (?, ?, ?, 0, 0)")?;
        s.execute(args)
            .expect("EXHAUSTION: MARF cannot track more than 2**31 - 1 blocks");
    };

    let block_id = get_unconfirmed_block_identifier(conn, block_hash)?
        .unwrap_or_else(|| panic!("BUG: stored {} but got no block ID", block_hash));

    debug!(
        "Wrote unconfirmed block trie {} to rowid {}",
        block_hash, block_id
    );
    Ok(block_id)
}

/// Open a trie blob in read-only mode. Returns a Blob<'a> readable handle to it.
pub fn open_trie_blob(conn: &Connection, block_id: u32) -> Result<Blob<'_>, Error> {
    let blob = conn.blob_open(
        DatabaseName::Main,
        "marf_data",
        "data",
        block_id.into(),
        true,
    )?;
    Ok(blob)
}

/// Open a trie blob in read-only mode. Returns a Blob<'a> readable handle to it.
/// Passes `read_only = true` to rusqlite, which maps to `flags = 0` in the
/// underlying sqlite3_blob_open call — safe to call on a read-only connection.
pub fn open_trie_blob_readonly(conn: &Connection, block_id: u32) -> Result<Blob<'_>, Error> {
    let blob = conn.blob_open(
        DatabaseName::Main,
        "marf_data",
        "data",
        block_id.into(),
        true,
    )?;
    Ok(blob)
}

#[cfg(test)]
pub fn read_all_block_hashes_and_roots<T: MarfTrieId>(
    conn: &Connection,
) -> Result<Vec<(TrieHash, T)>, Error> {
    let mut s = conn.prepare(
        "SELECT block_hash, data FROM marf_data WHERE unconfirmed = 0 ORDER BY block_hash",
    )?;
    let rows = s.query_and_then(NO_PARAMS, |row| {
        let block_hash: T = row.get_unwrap("block_hash");
        let data = row
            .get_ref("data")?
            .as_blob()
            .expect("DB Corruption: MARF data is non-blob");
        let start = storage::ROOT_PTR_DISK as usize;
        let trie_hash = TrieHash(bits::read_hash_bytes(&mut &data[start..])?);
        Ok((trie_hash, block_hash))
    })?;
    rows.collect()
}

/// Read a node's hash from a sqlite-stored blob, given the block ID
pub fn read_node_hash_bytes<W: Write>(
    conn: &Connection,
    w: &mut W,
    block_id: u32,
    ptr: &TriePtr,
) -> Result<(), Error> {
    let mut blob = conn.blob_open(
        DatabaseName::Main,
        "marf_data",
        "data",
        block_id.into(),
        true,
    )?;
    let hash_buff = bits::read_node_hash_bytes(&mut blob, ptr)?;
    w.write_all(&hash_buff).map_err(|e| e.into())
}

/// Read a node's hash from a sqlite-stored blob, given its block header hash
pub fn read_node_hash_bytes_by_bhh<W: Write, T: MarfTrieId>(
    conn: &Connection,
    w: &mut W,
    bhh: &T,
    ptr: &TriePtr,
) -> Result<(), Error> {
    let row_id: i64 = conn.query_row(
        "SELECT block_id FROM marf_data WHERE block_hash = ?",
        &[bhh],
        |r| r.get("block_id"),
    )?;
    let mut blob = conn.blob_open(DatabaseName::Main, "marf_data", "data", row_id, true)?;
    let hash_buff = bits::read_node_hash_bytes(&mut blob, ptr)?;
    w.write_all(&hash_buff).map_err(|e| e.into())
}

/// Read a node and its hash from a sqlite-stored trie blob into decode scratch.
pub fn read_node_type<'a>(
    conn: &Connection,
    block_id: u32,
    ptr: &TriePtr,
    scratch: &'a mut impl NodeDecodeScratch,
) -> Result<ReadTrieNode<'a>, Error> {
    read_trie_item(conn, block_id, ptr, scratch)?.into_node()
}

pub fn read_trie_item<'a>(
    conn: &Connection,
    block_id: u32,
    ptr: &TriePtr,
    scratch: &'a mut impl NodeDecodeScratch,
) -> Result<ReadTrieItem<'a>, Error> {
    let mut blob = conn.blob_open(
        DatabaseName::Main,
        "marf_data",
        "data",
        block_id.into(),
        true,
    )?;
    bits::read_trie_item(&mut blob, ptr, scratch)
}

pub fn read_trie_blob_bytes(conn: &Connection, block_id: u32) -> Result<Vec<u8>, Error> {
    let mut blob = open_trie_blob_readonly(conn, block_id)?;
    let mut trie_blob = Vec::new();
    blob.read_to_end(&mut trie_blob)
        .inspect_err(|e| error!("Failed to read sqlite trie blob {block_id}: {e:}"))?;
    Ok(trie_blob)
}

/// Get the offset and length of a trie blob in the trie blobs file.
///
/// **Cold-zone-only**, kept for callers that already know the block is
/// promoted (e.g. squash-publish bookkeeping). For the general read
/// path, use [`get_trie_storage_location`] instead — it returns the
/// `(kind, seq)` discriminator so the caller can dispatch to the right
/// file in the hot/cold tier model.
///
/// Returns the `external_offset` / `external_length` columns regardless
/// of the row's `storage_kind`. Hot rows have these populated relative
/// to their hot file, not `<db>.blobs`; passing the result of this
/// helper directly to a `TrieFile`-backed seek is **wrong** for hot
/// rows. (Pre-v5 chainstates always have `storage_kind = 0`, so callers
/// that haven't been ported yet still produce the same answer they did
/// before for those rows.)
pub fn get_external_trie_offset_length(
    conn: &Connection,
    block_id: u32,
) -> Result<(u64, u64), Error> {
    let qry = "SELECT external_offset, external_length FROM marf_data WHERE block_id = ?1";
    let args = params![block_id];
    let (offset, length): (u64, u64) =
        db::query_row(conn, qry, args)?.ok_or(Error::NotFoundError)?;
    Ok((offset, length))
}

/// Get the offset of a trie blob in the blobs file, given its block header hash.
///
/// Same caveat as [`get_external_trie_offset_length`]: cold-zone-aware
/// callers only.
pub fn get_external_trie_offset_length_by_bhh<T: MarfTrieId>(
    conn: &Connection,
    bhh: &T,
) -> Result<(u64, u64), Error> {
    let qry = "SELECT external_offset, external_length FROM marf_data WHERE block_hash = ?1";
    let args = params![bhh];
    let (offset, length): (u64, u64) =
        db::query_row(conn, qry, args)?.ok_or(Error::NotFoundError)?;
    Ok((offset, length))
}

/// Resolved storage location of a `marf_data` block: which tier holds
/// the bytes, where, and how long. Returned by
/// [`get_trie_storage_location`]; consumed by the read-path resolver
/// that routes between `<db>.blobs` (cold) and `<db>.hot.NNNN` (hot).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrieStorageLocation {
    pub kind: StorageKind,
    /// Hot files: the rolling-file sequence number. Cold files: always 0.
    pub seq: u32,
    /// Byte offset within the named file.
    pub offset: u64,
    /// Byte length within the named file.
    pub length: u64,
}

/// Look up the full `(storage_kind, storage_seq, external_offset,
/// external_length)` tuple for a `block_id`. This is the storage-tier-
/// aware analog of [`get_external_trie_offset_length`]; the read path
/// uses it to decide whether to dispatch the read to `<db>.blobs` or to
/// a hot file.
pub fn get_trie_storage_location(
    conn: &Connection,
    block_id: u32,
) -> Result<TrieStorageLocation, Error> {
    let row = conn
        .query_row(
            "SELECT storage_kind, storage_seq, external_offset, external_length \
             FROM marf_data WHERE block_id = ?1",
            params![block_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    let (kind_int, seq, offset, length) = row.ok_or(Error::NotFoundError)?;
    Ok(TrieStorageLocation {
        kind: StorageKind::from_int(kind_int)?,
        seq: seq as u32,
        offset: offset as u64,
        length: length as u64,
    })
}

/// Same as [`get_trie_storage_location`] but keyed by `block_hash`.
pub fn get_trie_storage_location_by_bhh<T: MarfTrieId>(
    conn: &Connection,
    bhh: &T,
) -> Result<TrieStorageLocation, Error> {
    let row = conn
        .query_row(
            "SELECT storage_kind, storage_seq, external_offset, external_length \
             FROM marf_data WHERE block_hash = ?1",
            params![bhh],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    let (kind_int, seq, offset, length) = row.ok_or(Error::NotFoundError)?;
    Ok(TrieStorageLocation {
        kind: StorageKind::from_int(kind_int)?,
        seq: seq as u32,
        offset: offset as u64,
        length: length as u64,
    })
}

/// Determine the offset in the **cold blob file (`<db>.blobs`)** at
/// which the last cold trie ends. This is the offset at which the next
/// cold append (e.g. a squash publish) will land.
///
/// **Filters on `storage_kind = 0`** so hot-zone rows — whose
/// `external_offset` / `external_length` describe a region inside
/// `<db>.hot.NNNN`, not `<db>.blobs` — don't poison the cold append
/// offset. This is Codex finding 2's namespace fix from the v1.5 review.
///
/// Uses two index-friendly `ORDER BY … DESC LIMIT 1` queries instead of
/// a `UNION ALL` + `MAX()` which would force full table scans on every
/// append.
pub fn get_external_blobs_length(conn: &Connection) -> Result<u64, Error> {
    let marf_end: u64 = db::query_row(
        conn,
        "SELECT (external_offset + external_length) AS end_offset \
         FROM marf_data \
         WHERE storage_kind = 0 \
         ORDER BY external_offset DESC LIMIT 1",
        NO_PARAMS,
    )?
    .unwrap_or(0);

    let squash_end: u64 = db::query_row(
        conn,
        "SELECT (blob_offset + blob_length) AS end_offset \
         FROM marf_squash_levels ORDER BY blob_offset DESC LIMIT 1",
        NO_PARAMS,
    )?
    .unwrap_or(0);

    Ok(marf_end.max(squash_end))
}

/// Determine the offset in the **active hot file** at which the last
/// hot trie ends. This is the offset at which the next hot append will
/// land for the given `storage_seq`.
///
/// Filters on `storage_kind = 1 AND storage_seq = ?` so the offset
/// computation is per-hot-file. Used by startup recovery (Slice A6) to
/// truncate any in-flight torn append on the active hot file.
pub fn get_hot_file_committed_length(conn: &Connection, seq: u32) -> Result<u64, Error> {
    let end: u64 = db::query_row(
        conn,
        "SELECT (external_offset + external_length) AS end_offset \
         FROM marf_data \
         WHERE storage_kind = 1 AND storage_seq = ?1 \
         ORDER BY external_offset DESC LIMIT 1",
        params![seq as i64],
    )?
    .unwrap_or(0);
    Ok(end)
}

/// One `marf_data` row that still references a hot file at sweep time.
///
/// Returned by [`hot_rows_for_seq`]; consumed by Phase C's
/// [`crate::chainstate::stacks::index::hot_reclaim::classify_hot_file`] to look up per-row block
/// height + canonical-set membership.
#[derive(Debug, Clone)]
pub struct LiveHotRow<T: MarfTrieId> {
    pub block_hash: T,
    pub external_offset: u64,
    pub external_length: u64,
}

/// List the live `marf_data` rows that still reference hot file `seq`.
///
/// Empty `Vec` means "no live rows" — under sweep semantics ([squashing-v1.5.md
/// §7.1(a)](../../../../../.docs/squashing-v1.5.md)) this is the unconditionally-unlinkable "all
/// blocks promoted" case and the file can be unlinked without per-row classification.
///
/// Used by Phase C's
/// [`crate::chainstate::stacks::index::hot_reclaim::enumerate_hot_files_for_sweep`] to attach SQL
/// row metadata after the file inventory has enumerated the candidate seq.
pub fn hot_rows_for_seq<T: MarfTrieId>(
    conn: &Connection,
    seq: u32,
) -> Result<Vec<LiveHotRow<T>>, Error> {
    let mut stmt = conn.prepare(
        "SELECT block_hash, external_offset, external_length \
         FROM marf_data \
         WHERE storage_kind = 1 AND storage_seq = ?1 \
         ORDER BY external_offset ASC",
    )?;
    let rows = stmt
        .query_map(params![seq as i64], |row| {
            Ok(LiveHotRow {
                block_hash: row.get::<_, T>("block_hash")?,
                external_offset: row.get::<_, i64>("external_offset")? as u64,
                external_length: row.get::<_, i64>("external_length")? as u64,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Enumerate every distinct hot-file sequence number referenced by a `marf_data` row, paired with
/// its committed extent `MAX(external_offset + external_length)`.
///
/// Used by [`crate::chainstate::stacks::index::hot_file::HotFileSet::open`] to validate that every
/// hot file the SQL state expects actually exists on disk and is at least as long as the committed
/// extent.
pub fn referenced_hot_seqs_with_committed_len(conn: &Connection) -> Result<Vec<(u32, u64)>, Error> {
    let mut stmt = conn.prepare(
        "SELECT storage_seq, MAX(external_offset + external_length) AS end_offset \
         FROM marf_data \
         WHERE storage_kind = 1 \
         GROUP BY storage_seq",
    )?;
    let rows = stmt
        .query_map(NO_PARAMS, |row| {
            Ok((row.get::<_, i64>(0)? as u32, row.get::<_, i64>(1)? as u64))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Do we have a partially-migrated database?
///
/// Either all tries have offset and length 0, or they all don't.  If we have a mixture, then we're
/// corrupted.
///
/// The check is **scoped to cold rows** (`storage_kind = 0`), because the v1 → v2 migration this
/// helper detects is specifically the "inline-blob → cold `<db>.blobs`" transition. Hot-zone rows
/// are always non-zero and `storage_kind = 1`, so including them in the "migrated/not-migrated"
/// counts would falsely flag a healthy mixed hot/cold v5 chainstate as corrupt.
pub fn detect_partial_migration(conn: &Connection) -> Result<bool, Error> {
    let migrated_version = get_migrated_version(conn);
    let schema_version = get_schema_version(conn);
    if migrated_version == schema_version {
        return Ok(false);
    }

    let num_migrated = db::query_count(
        conn,
        "SELECT COUNT(*) FROM marf_data \
         WHERE storage_kind = 0 \
         AND external_offset = 0 AND external_length = 0 \
         AND unconfirmed = 0",
        NO_PARAMS,
    )?;
    let num_not_migrated = db::query_count(
        conn,
        "SELECT COUNT(*) FROM marf_data \
         WHERE storage_kind = 0 \
         AND external_offset != 0 AND external_length != 0 \
         AND unconfirmed = 0",
        NO_PARAMS,
    )?;
    Ok(num_migrated > 0 && num_not_migrated > 0)
}

/// Mark a migration as completed
pub fn set_migrated(conn: &Connection) -> Result<(), Error> {
    conn.execute(
        "UPDATE migrated_version SET version = ?1",
        &[&db::u64_to_sql(SQL_MARF_SCHEMA_VERSION)?],
    )
    .map_err(|e| e.into())
    .map(|_| ())
}

pub fn get_node_hash_bytes(
    conn: &Connection,
    block_id: u32,
    ptr: &TriePtr,
) -> Result<TrieHash, Error> {
    let mut blob = conn.blob_open(
        DatabaseName::Main,
        "marf_data",
        "data",
        block_id.into(),
        true,
    )?;
    let hash_buff = bits::read_node_hash_bytes(&mut blob, ptr)?;
    Ok(TrieHash(hash_buff))
}

pub fn get_node_hash_bytes_by_bhh<T: MarfTrieId>(
    conn: &Connection,
    bhh: &T,
    ptr: &TriePtr,
) -> Result<TrieHash, Error> {
    let row_id: i64 = conn.query_row(
        "SELECT block_id FROM marf_data WHERE block_hash = ?",
        &[bhh],
        |r| r.get("block_id"),
    )?;
    let mut blob = conn.blob_open(DatabaseName::Main, "marf_data", "data", row_id, true)?;
    let hash_buff = bits::read_node_hash_bytes(&mut blob, ptr)?;
    Ok(TrieHash(hash_buff))
}

pub fn probe_node_type(
    conn: &Connection,
    block_id: u32,
    ptr: &TriePtr,
) -> Result<(TrieNodeID, TrieHash), Error> {
    let mut blob = conn.blob_open(
        DatabaseName::Main,
        "marf_data",
        "data",
        block_id.into(),
        true,
    )?;
    blob.seek(SeekFrom::Start(ptr.ptr() as u64))?;
    bits::read_stored_node_type_at_head(&mut blob).map_err(Into::into)
}

pub fn tx_lock_bhh_for_extension<T: MarfTrieId>(
    tx: &Connection,
    bhh: &T,
    unconfirmed: bool,
) -> Result<bool, Error> {
    if !unconfirmed {
        // confirmed tries can only be extended once.
        // unconfirmed tries can be overwritten.
        let is_bhh_committed = tx
            .query_row(
                "SELECT 1 FROM marf_data WHERE block_hash = ? LIMIT 1",
                &[bhh],
                |_row| Ok(()),
            )
            .optional()?
            .is_some();
        if is_bhh_committed {
            return Ok(false);
        }
    }

    let is_bhh_locked = tx
        .query_row(
            "SELECT 1 FROM block_extension_locks WHERE block_hash = ? LIMIT 1",
            &[bhh],
            |_row| Ok(()),
        )
        .optional()?
        .is_some();
    if is_bhh_locked {
        return Ok(false);
    }

    tx.execute(
        "INSERT INTO block_extension_locks (block_hash) VALUES (?)",
        &[bhh],
    )?;
    Ok(true)
}

pub fn lock_bhh_for_extension<T: MarfTrieId>(
    tx: &Transaction,
    bhh: &T,
    unconfirmed: bool,
) -> Result<bool, Error> {
    tx_lock_bhh_for_extension(tx, bhh, unconfirmed)?;
    Ok(true)
}

pub fn count_blocks(conn: &Connection) -> Result<u32, Error> {
    let result = conn.query_row(
        "SELECT IFNULL(MAX(block_id), 0) AS count FROM marf_data WHERE unconfirmed = 0",
        NO_PARAMS,
        |row| row.get("count"),
    )?;
    Ok(result)
}

pub fn is_unconfirmed_block(conn: &Connection, block_id: u32) -> Result<bool, Error> {
    let res: i64 = conn.query_row(
        "SELECT unconfirmed FROM marf_data WHERE block_id = ?1",
        &[&block_id],
        |row| row.get("unconfirmed"),
    )?;
    Ok(res != 0)
}

pub fn drop_lock<T: MarfTrieId>(conn: &Connection, bhh: &T) -> Result<(), Error> {
    conn.execute(
        "DELETE FROM block_extension_locks WHERE block_hash = ?",
        &[bhh],
    )?;
    Ok(())
}

pub fn drop_unconfirmed_trie<T: MarfTrieId>(conn: &Connection, bhh: &T) -> Result<(), Error> {
    debug!("Drop unconfirmed trie sqlite blob {}", bhh);
    conn.execute(
        "DELETE FROM marf_data WHERE block_hash = ? AND unconfirmed = 1",
        &[bhh],
    )?;
    debug!("Dropped unconfirmed trie sqlite blob {}", bhh);
    Ok(())
}

pub fn clear_lock_data(conn: &Connection) -> Result<(), Error> {
    conn.execute("DELETE FROM block_extension_locks", NO_PARAMS)?;
    Ok(())
}

pub fn clear_tables(tx: &Transaction) -> Result<(), Error> {
    tx.execute("DELETE FROM block_extension_locks", NO_PARAMS)?;
    tx.execute("DELETE FROM marf_data", NO_PARAMS)?;
    tx.execute("DELETE FROM mined_blocks", NO_PARAMS)?;
    Ok(())
}

// --- Squash level registry ---

use crate::chainstate::stacks::index::squash::{HistoryBlobState, SquashLevelRow};

// IMPORTANT: keep this DDL in sync with the v3 schema at
// `SQL_MARF_DATA_TABLE_SCHEMA_3` above (specifically the `marf_squash_levels`
// CREATE TABLE block). Both are the same table; this one is the
// belt-and-suspenders/test-helper path used by `create_squash_levels_table`,
// while the v3 DDL is what fresh chainstates open against. A drift between
// the two will silently produce a table missing the new column on any
// codepath that touches this DDL but not the v3 DDL.
static SQL_SQUASH_LEVELS_TABLE: &str = "
CREATE TABLE IF NOT EXISTS marf_squash_levels (
    level_id INTEGER PRIMARY KEY,
    min_height INTEGER NOT NULL,
    max_height INTEGER NOT NULL,
    blob_offset INTEGER NOT NULL,
    blob_length INTEGER NOT NULL,
    reads_redirected INTEGER NOT NULL DEFAULT 0,
    root_sidecar_present INTEGER NOT NULL DEFAULT 0,
    root_sidecar_trimmed INTEGER NOT NULL DEFAULT 0,
    orphan_split_offset INTEGER NOT NULL DEFAULT 0,
    -- Publish-time `MAX(block_id) FROM marf_data WHERE unconfirmed = 0`,
    -- snapshotted inside the squash publish transaction. Backs the per-MARF
    -- squash-work counter's reconstruction at startup: confirmed `marf_data`
    -- rows with `block_id > MAX(published_max_block_id)` are the
    -- post-publish open-suffix work that the next squash will absorb.
    -- Default 0 means \"reconstruct over the entire `marf_data` table\" —
    -- the conservative one-time over-count that levels predating this
    -- column produce on first read post-migration; cleared on the next
    -- successful squash.
    published_max_block_id INTEGER NOT NULL DEFAULT 0,
    -- Per-level FullHistory history-blob state. Mirrors the v3 schema
    -- column for the multipurpose `TrieLeafSquashed` carrier — see
    -- .docs/full-history-history-blob-design.md §10.1.
    history_blob_state TEXT NOT NULL DEFAULT 'never_written'
        CHECK (history_blob_state IN ('never_written', 'present', 'trimmed'))
);
";

/// Schema for retired squash levels — superseded by `Replace` publish but kept on disk so reads on
/// old-trailer block hashes (which may still be referenced by staged fork descendants) continue to
/// resolve correctly.
///
/// A retired row preserves the level's merged-blob extent and trailer metadata at the moment it was
/// replaced. The blob bytes themselves remain in the `.blobs` file as dead space until a future
/// reclaim pass (out of scope here) compacts them.
///
/// **Sidecar identity is keyed by `blob_offset`.** Active sidecar paths already include
/// `blob_offset` as a suffix (`marf-roots-level-...-blob-{blob_offset:016x}.dat`), so a `Replace`
/// publish writes its new sidecar at a different path from the OLD active level's sidecar. The
/// retired row's `blob_offset` field resolves to the OLD sidecar's path on read — no rename, copy,
/// Idempotent DDL for the squash-levels table. Called from squash entry points as a
/// belt-and-suspenders measure; the same table is also created by the v2→v3 migration in
/// [`SQL_MARF_DATA_TABLE_SCHEMA_3`], so this is a no-op on properly-migrated chainstates.
///
/// Phase D (2026-05-03): the `marf_retired_squash_levels` table + its idempotent
/// per-call ALTER series were removed alongside the v3-consolidation. The retired-levels
/// infrastructure was vestigial since B6.3 (no Phase A/B/C path read or wrote it); under v3
/// schema consolidation the table DDL is gone entirely. Per-call ALTERs for
/// `marf_squash_levels`'s extra columns were also removed — the v3 DDL puts every column in
/// the initial CREATE, so the ALTERs would never fire.
pub fn create_squash_levels_table(conn: &Connection) -> Result<(), Error> {
    conn.execute_batch(SQL_SQUASH_LEVELS_TABLE)?;
    Ok(())
}

/// Snapshot the publish-time watermark — `MAX(block_id) FROM marf_data WHERE
/// unconfirmed = 0`. Returns 0 when no confirmed rows exist (e.g. a freshly
/// created stub with an empty `marf_data`). Callers should run this *inside*
/// the squash publish transaction so the watermark reflects exactly the rows
/// observable at commit time.
pub fn current_published_max_block_id(conn: &Connection) -> Result<u32, Error> {
    let watermark: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(block_id), 0) FROM marf_data WHERE unconfirmed = 0",
            NO_PARAMS,
            |row| row.get::<_, i64>(0),
        )
        .map_err(Error::SQLError)?;
    Ok(watermark as u32)
}

/// Reconstruct the per-MARF squash-work counter from SQL: sum `external_length` over confirmed
/// `marf_data` rows with `block_id` strictly greater than the latest published level's watermark
/// (`MAX(published_max_block_id)` across `marf_squash_levels`). Returns 0 when no confirmed rows
/// have landed past the latest squash. The query uses the primary-key index on `block_id` so cost
/// is O(post-watermark rows).
///
/// On a freshly-migrated v2 -> v3 DB the watermark defaults to 0 for every pre-existing level; the
/// first reconstruction post-migration sums over the entire `marf_data` table — a documented
/// one-time over-count cleared by the next squash, which writes a real watermark and resets the
/// counter.
///
/// Pre-stub / pre-squash MARFs (no rows in `marf_squash_levels`) likewise sum over the full table;
/// the next stub or squash absorbs that into a real watermark.
pub fn current_external_bytes_since_last_squash(conn: &Connection) -> Result<u64, Error> {
    // `marf_squash_levels` may not exist yet on pre-squash-code DBs (the table is created by the v2
    // -> v3 migration; opens against older schemas may briefly observe its absence). Match the
    // `read_squash_levels` table-exists guard so this helper stays callable from those paths too.
    let table_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='marf_squash_levels'",
            NO_PARAMS,
            |row| row.get(0),
        )
        .unwrap_or(false);
    let watermark: i64 = if table_exists {
        conn.query_row(
            "SELECT COALESCE(MAX(published_max_block_id), 0) FROM marf_squash_levels",
            NO_PARAMS,
            |row| row.get::<_, i64>(0),
        )
        .map_err(Error::SQLError)?
    } else {
        0
    };
    let total: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(external_length), 0) FROM marf_data \
             WHERE block_id > ?1 AND unconfirmed = 0",
            params![watermark],
            |row| row.get::<_, i64>(0),
        )
        .map_err(Error::SQLError)?;
    Ok(total as u64)
}

pub fn write_squash_level(conn: &Connection, row: &SquashLevelRow) -> Result<(), Error> {
    conn.execute(
        "INSERT OR REPLACE INTO marf_squash_levels \
         (level_id, min_height, max_height, blob_offset, blob_length, \
          reads_redirected, root_sidecar_present, root_sidecar_trimmed, \
          orphan_split_offset, published_max_block_id, history_blob_state) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            row.level_id,
            row.min_height,
            row.max_height,
            row.blob_offset as i64,
            row.blob_length as i64,
            row.reads_redirected as i64,
            row.root_sidecar_present as i64,
            row.root_sidecar_trimmed as i64,
            row.orphan_split_offset as i64,
            row.published_max_block_id as i64,
            row.history_blob_state.as_sql_str(),
        ],
    )?;
    Ok(())
}

/// Update `history_blob_state` for an existing level. Used by the trim
/// flow (§10.2) — SQL update goes first, then the file unlink, so a crash
/// between steps leaves a sane state (recovery's `'trimmed'` branch
/// handles the leftover file). Idempotent.
pub fn set_history_blob_state(
    conn: &Connection,
    level_id: u32,
    state: HistoryBlobState,
) -> Result<(), Error> {
    conn.execute(
        "UPDATE marf_squash_levels SET history_blob_state = ?1 WHERE level_id = ?2",
        params![state.as_sql_str(), level_id],
    )?;
    Ok(())
}

/// Mark `root_sidecar_present` for a level. Used at squash publish time once the sidecar file has
/// been atomically renamed into place. Idempotent.
pub fn set_root_sidecar_present(
    conn: &Connection,
    level_id: u32,
    present: bool,
) -> Result<(), Error> {
    conn.execute(
        "UPDATE marf_squash_levels SET root_sidecar_present = ?1 WHERE level_id = ?2",
        params![present as i64, level_id],
    )?;
    Ok(())
}

/// Mark `root_sidecar_trimmed` for a level. Idempotent.
///
/// This is intentionally called at trim time **before** the sidecar file is `unlink`-ed: the SQL
/// flag is the load-bearing source of truth for the read path's `Error::SnapshotTrimmed` policy,
/// and flipping it first (followed by a `SquashMeta` republish) ensures that no live handle ever
/// observes the (file-missing, trimmed=false) corruption window. The subsequent `unlink` is
/// best-effort disk hygiene; if it fails, the file is reaped by
/// [`crate::chainstate::stacks::index::sidecar::reconcile_squash_sidecars`] on the next startup.
/// See `trim_aged_root_sidecars` in `squash.rs` for the full ordering rationale.
pub fn set_root_sidecar_trimmed(
    conn: &Connection,
    level_id: u32,
    trimmed: bool,
) -> Result<(), Error> {
    conn.execute(
        "UPDATE marf_squash_levels SET root_sidecar_trimmed = ?1 WHERE level_id = ?2",
        params![trimmed as i64, level_id],
    )?;
    Ok(())
}

/// Update an existing `marf_data` row by block hash to point to a new external blob location. Used
/// by the incremental squash pipeline to redirect per-block blob entries to the squash blob. The
/// inline `data` column is cleared.
///
/// **v1.5**: also flips `storage_kind = Cold, storage_seq = 0`. Squash publish promotes blocks from
/// the hot tier (`<db>.hot.NNNN`) into the cold merged blob (`<db>.blobs`); without resetting the
/// kind/seq, the row would still appear hot and the read-path resolver would try to look up the new
/// offset inside the wrong hot file.
///
/// **Bulk-redirecting an entire in-range block list?** Use
/// [`crate::chainstate::stacks::index::squash_promote::redirect_in_range_blocks_to_cold`] instead.
/// That helper prepares the statement once and reuses it across binds, materially shrinking the
/// publish window for large promotions.
pub fn update_external_trie_blob_by_hash<T: MarfTrieId>(
    conn: &Connection,
    block_hash: &T,
    offset: u64,
    length: u64,
) -> Result<(), Error> {
    let empty_blob: &[u8] = &[];
    conn.execute(
        "UPDATE marf_data SET external_offset = ?1, external_length = ?2, data = ?3, \
         storage_kind = 0, storage_seq = 0 \
         WHERE block_hash = ?4",
        params![offset as i64, length as i64, empty_blob, block_hash],
    )?;
    Ok(())
}

pub fn read_squash_levels(conn: &Connection) -> Result<Vec<SquashLevelRow>, Error> {
    // Table may not exist yet (pre-squash databases).
    let table_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='marf_squash_levels'",
            NO_PARAMS,
            |row| row.get(0),
        )
        .unwrap_or(false);

    if !table_exists {
        return Ok(Vec::new());
    }

    let mut stmt = conn.prepare(
        "SELECT level_id, min_height, max_height, blob_offset, blob_length, \
         COALESCE(reads_redirected, 0) AS reads_redirected, \
         COALESCE(root_sidecar_present, 0) AS root_sidecar_present, \
         COALESCE(root_sidecar_trimmed, 0) AS root_sidecar_trimmed, \
         COALESCE(orphan_split_offset, 0) AS orphan_split_offset, \
         COALESCE(published_max_block_id, 0) AS published_max_block_id, \
         COALESCE(history_blob_state, 'never_written') AS history_blob_state \
         FROM marf_squash_levels ORDER BY min_height ASC",
    )?;
    let mut rows = Vec::new();
    let mapped = stmt.query_map(NO_PARAMS, |row| {
        // Read history_blob_state as a text column and decode below; the
        // closure cannot propagate `Error` directly, so we keep the value
        // as a `String` and decode in the outer collect loop.
        let history_blob_state_str: String = row.get("history_blob_state")?;
        Ok((
            SquashLevelRow {
                level_id: row.get::<_, u32>("level_id")?,
                min_height: row.get::<_, u32>("min_height")?,
                max_height: row.get::<_, u32>("max_height")?,
                blob_offset: row.get::<_, i64>("blob_offset")? as u64,
                blob_length: row.get::<_, i64>("blob_length")? as u64,
                reads_redirected: row.get::<_, i64>("reads_redirected")? != 0,
                root_sidecar_present: row.get::<_, i64>("root_sidecar_present")? != 0,
                root_sidecar_trimmed: row.get::<_, i64>("root_sidecar_trimmed")? != 0,
                orphan_split_offset: row.get::<_, i64>("orphan_split_offset")? as u32,
                published_max_block_id: row.get::<_, i64>("published_max_block_id")? as u32,
                // Filled in below after decoding `history_blob_state_str`.
                history_blob_state: HistoryBlobState::NeverWritten,
            },
            history_blob_state_str,
        ))
    })?;
    for entry in mapped {
        let (mut row, state_str) = entry?;
        row.history_blob_state = HistoryBlobState::from_sql_str(&state_str)?;
        rows.push(row);
    }
    Ok(rows)
}

/// Validate that no live references point into the byte range `[from_offset, +∞)` in the blob file,
/// except for blocks whose `block_hash` is in `superseded_hashes`.
///
/// Returns:
/// - `Ok(())` if the truncation zone is safe to overwrite/truncate, or
/// - `Err(CorruptionError)` if any live reference would be destroyed.
///
/// Checks both `marf_data` and `marf_squash_levels`.
///
/// **Cold-zone scoped.** The query filters `storage_kind = 0` so hot-row extents — which name
/// regions inside `<db>.hot.NNNN`, not `<db>.blobs` — can't be misinterpreted as overlapping the
/// cold truncation zone by numeric coincidence (Codex finding 2 from the v1.5 review).
pub fn validate_truncation_zone<T: MarfTrieId>(
    conn: &Connection,
    from_offset: u64,
    superseded_hashes: &[T],
) -> Result<(), Error> {
    // Check each marf_data row that overlaps the truncation zone.
    // A blob overlaps if its extent (offset + length) exceeds from_offset.
    let mut stmt = conn.prepare(
        "SELECT block_hash, external_offset, external_length FROM marf_data \
         WHERE storage_kind = 0 \
         AND (external_offset + external_length) > ?1 \
         AND external_length > 0",
    )?;
    let dangling: Vec<(String, u64)> = stmt
        .query_map(params![from_offset as i64], |row| {
            Ok((
                row.get::<_, String>("block_hash")?,
                row.get::<_, i64>("external_offset")? as u64,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    if !dangling.is_empty() {
        // Build a lookup set from the superseded hashes' ToSql representation.
        let superseded_strs: std::collections::HashSet<String> =
            superseded_hashes.iter().map(|h| format!("{}", h)).collect();

        for (block_hash, offset) in &dangling {
            if !superseded_strs.contains(block_hash) {
                return Err(Error::CorruptionError(format!(
                    "Live marf_data row for block {block_hash} references offset {offset} \
                     (>= truncation boundary {from_offset}) but is not being superseded"
                )));
            }
        }
    }

    // Check marf_squash_levels: any level whose blob extent overlaps the truncation zone? A level
    // overlaps if blob_offset + blob_length > from_offset.
    let levels = read_squash_levels(conn)?;
    for level in &levels {
        if level.blob_offset + level.blob_length > from_offset {
            return Err(Error::CorruptionError(format!(
                "Live marf_squash_levels row (level_id={}, blob_offset={}, blob_length={}) \
                 overlaps truncation zone starting at {from_offset}",
                level.level_id, level.blob_offset, level.blob_length
            )));
        }
    }

    Ok(())
}

/// Prune external blob references for non-canonical `marf_data` rows whose blob data falls within
/// the reclaim truncation zone.
///
/// After blob export, committed fork blocks have `external_offset/external_length` pointing into
/// the `.blobs` file and `data = x''` (empty).  These rows are unreachable from the canonical chain
/// tip (`get_block_at_height` only walks the canonical ancestry), but `validate_truncation_zone`
/// correctly rejects them because they are not in the canonical `superseded_hashes` set.
///
/// This function zeroes their external refs so that reclaim truncation can proceed.  **This is an
/// intentional pruning of non-canonical fork state**: those trie blobs become permanently
/// unreadable after this call.
///
/// Returns the number of orphaned rows pruned.
///
/// **Cold-zone scoped.** Filters `storage_kind = 0` for the same reason as
/// [`validate_truncation_zone`]: hot rows live in a separate file namespace and must not be
/// coalesced with cold offsets by numeric overlap (Codex finding 2 from the v1.5 review). Hot-zone
/// orphan reclaim runs through the Phase C hot-file sweep, not through this helper.
pub fn prune_orphaned_external_refs<T: MarfTrieId>(
    conn: &Connection,
    from_offset: u64,
    canonical_hashes: &[T],
) -> Result<u64, Error> {
    // Same predicate as validate_truncation_zone: find rows in the zone.
    let mut stmt = conn.prepare(
        "SELECT block_hash, external_offset FROM marf_data \
         WHERE storage_kind = 0 \
         AND (external_offset + external_length) > ?1 \
         AND external_length > 0",
    )?;
    let candidates: Vec<(String, u64)> = stmt
        .query_map(params![from_offset as i64], |row| {
            Ok((
                row.get::<_, String>("block_hash")?,
                row.get::<_, i64>("external_offset")? as u64,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let canonical_strs: std::collections::HashSet<String> =
        canonical_hashes.iter().map(|h| format!("{}", h)).collect();

    let mut count = 0u64;
    for (block_hash, offset) in &candidates {
        if !canonical_strs.contains(block_hash) {
            warn!(
                "Pruning non-canonical external trie ref: block {block_hash} \
                 at offset {offset} (truncation boundary {from_offset})"
            );
            conn.execute(
                "UPDATE marf_data SET external_offset = 0, external_length = 0 \
                 WHERE block_hash = ?1",
                params![block_hash],
            )?;
            count += 1;
        }
    }
    Ok(count)
}

// ============================================================================
// `marf_state` singleton helpers (Schema 5+; see `.docs/squashing-v1.5.md` §4.2)
// ============================================================================

/// Snapshot of the MARF-wide state singleton.
///
/// Phase A populates `active_hot_seq` and `horizon_burn_blocks`. The `promotion_*` fields are part
/// of Phase B's single-flight promotion lock; in Phase A they are always `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarfState {
    /// Currently-active hot-file sequence number. Block appends go to `<db>.hot.{active_hot_seq}`.
    /// Bumped by the hot-file rotation path (Phase A) when the active file crosses its size
    /// threshold.
    pub active_hot_seq: u32,
    /// Burnchain reorg horizon used by horizon-gated squash (Phase B). The schema default is 6;
    /// v1.5 carries the value durably so an operator can adjust it for a deployment without
    /// recompiling.
    pub horizon_burn_blocks: u32,
    /// Phase B: `level_id` of an in-flight background promotion, or `None` when idle. Phase A
    /// always reads `None`.
    pub promotion_in_progress: Option<u32>,
    /// Phase B: cold-blob extent reserved by an in-flight promotion. Phase A always reads `None`.
    pub promotion_reserved_offset: Option<u64>,
    /// Phase B: cold-blob extent length reserved by an in-flight promotion. Phase A always reads
    /// `None`.
    pub promotion_reserved_length: Option<u64>,
    /// One-shot gate for the post-epoch-3.4 history-blob auto-trim per
    /// `.docs/full-history-history-blob-design.md` §10.3. `false` (the
    /// default) when the boundary hasn't been crossed yet; `true` after
    /// the chains-coordinator's auto-trim batch has completed (step 5 of
    /// the §10.3 batch flow — committed LAST so a mid-batch crash leaves
    /// `false` and the next boot resumes).
    pub auto_trim_done: bool,
}

/// Read the MARF state singleton.
///
/// Returns `Ok(state)` for v5+ chainstates (the `INSERT OR IGNORE` in the schema migration
/// guarantees a row exists). For v4 and earlier, the `marf_state` table doesn't exist; callers
/// shouldn't reach this helper on pre-v5 schemas, but we return a clear error rather than panicking
/// so the caller's diagnostic surfaces the real cause.
pub fn read_marf_state(conn: &Connection) -> Result<MarfState, Error> {
    let row = conn
        .query_row(
            "SELECT active_hot_seq, horizon_burn_blocks, \
                    promotion_in_progress, \
                    promotion_reserved_offset, promotion_reserved_length, \
                    COALESCE(auto_trim_done, 0) AS auto_trim_done \
             FROM marf_state WHERE id = 1",
            NO_PARAMS,
            |row| {
                Ok(MarfState {
                    active_hot_seq: row.get::<_, i64>("active_hot_seq")? as u32,
                    horizon_burn_blocks: row.get::<_, i64>("horizon_burn_blocks")? as u32,
                    promotion_in_progress: row
                        .get::<_, Option<i64>>("promotion_in_progress")?
                        .map(|v| v as u32),
                    promotion_reserved_offset: row
                        .get::<_, Option<i64>>("promotion_reserved_offset")?
                        .map(|v| v as u64),
                    promotion_reserved_length: row
                        .get::<_, Option<i64>>("promotion_reserved_length")?
                        .map(|v| v as u64),
                    auto_trim_done: row.get::<_, i64>("auto_trim_done")? != 0,
                })
            },
        )
        .optional()?;
    row.ok_or_else(|| {
        Error::CorruptionError(
            "marf_state singleton row missing — chainstate may be on a pre-v5 schema".into(),
        )
    })
}

/// Set `marf_state.auto_trim_done` to the given value. Used by the
/// chains-coordinator's epoch-3.4 auto-trim hook (§10.3 of the design
/// doc) to commit the one-shot gate AFTER the trim batch completes —
/// step 5 of the §10.3 batch flow. Committing this last is load-bearing
/// for crash-safety: a mid-batch crash leaves `false`, the next boot's
/// trigger check re-evaluates conditions and resumes the trim against
/// any remaining `'present'` levels.
pub fn set_auto_trim_done(conn: &Connection, done: bool) -> Result<(), Error> {
    conn.execute(
        "UPDATE marf_state SET auto_trim_done = ?1 WHERE id = 1",
        params![done as i64],
    )?;
    Ok(())
}

/// Set the active hot-file sequence number. Used by the hot-file rotation path when the active file
/// crosses its rotation threshold; Phase A is the only writer.
pub fn set_active_hot_seq(conn: &Connection, new_seq: u32) -> Result<(), Error> {
    conn.execute(
        "UPDATE marf_state SET active_hot_seq = ?1 WHERE id = 1",
        params![new_seq as i64],
    )?;
    Ok(())
}

/// Clear the in-flight promotion state on the `marf_state` singleton: `promotion_in_progress`,
/// `promotion_reserved_offset`, `promotion_reserved_length` all back to NULL.
///
/// Used by:
/// - The swap phase's SQL transaction once the level row is committed (clears the lock as part of
///   the same transaction so the lock release is atomic with publication).
/// - Recovery, when an abandoned plan leaves stale state behind. Without this clear, the MARF would
///   stay permanently single-flight-locked because every cadence tick sees `promotion_in_progress`
///   set with no plan file backing it.
///
/// See `.docs/squashing-v1.5-phase-b.md` §7.1 step 2a (abandon path) and §6.3.2 step 5 (commit
/// path).
pub fn clear_promotion_state(conn: &Connection) -> Result<(), Error> {
    conn.execute(
        "UPDATE marf_state SET \
         promotion_in_progress = NULL, \
         promotion_reserved_offset = NULL, \
         promotion_reserved_length = NULL \
         WHERE id = 1",
        [],
    )?;
    Ok(())
}
