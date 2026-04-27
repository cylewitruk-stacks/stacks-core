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
    -- live in [orphan_split_offset ..). Recorded by PR1; routed by PR2 for
    -- orphan-sidecar reads. 0 means no split (legacy / no orphans).
    orphan_split_offset INTEGER NOT NULL DEFAULT 0
);

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
                debug!("Migrate MARF data from schema 2 to schema 3");

                // add marf_squash_levels table
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

/// Write the offset/length of a trie blob that was stored to an external file.
/// Do this only once the trie is actually stored, since only the presence of this information is
/// what guarantees that the blob is persisted.
/// If block_id is Some(..), then an existing block ID's metadata will be updated.  Otherwise, a
/// new row will be created.
fn inner_write_external_trie_blob<T: MarfTrieId>(
    conn: &Connection,
    block_hash: &T,
    offset: u64,
    length: u64,
    block_id: Option<u32>,
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
            block_id,
        ];
        let mut s =
            conn.prepare("UPDATE marf_data SET block_hash = ?1, data = ?2, unconfirmed = ?3, external_offset = ?4, external_length = ?5 WHERE block_id = ?6")?;
        s.execute(args)?;

        debug!(
            "Replaced block trie {} at rowid {} offset {}",
            block_hash, block_id, offset
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
        ];
        let mut s =
            conn.prepare("INSERT INTO marf_data (block_hash, data, unconfirmed, external_offset, external_length) VALUES (?, ?, ?, ?, ?)")?;
        let block_id = s
            .insert(args)?
            .try_into()
            .expect("EXHAUSTION: MARF cannot track more than 2**31 - 1 blocks");

        debug!(
            "Wrote block trie {} to rowid {} offset {}",
            block_hash, block_id, offset
        );
        block_id
    };

    Ok(block_id)
}

/// Update the row for an external trie blob -- i.e. we're migrating blobs from sqlite storage to
/// file storage.
pub fn update_external_trie_blob<T: MarfTrieId>(
    conn: &Connection,
    block_hash: &T,
    offset: u64,
    length: u64,
    block_id: u32,
) -> Result<u32, Error> {
    inner_write_external_trie_blob(conn, block_hash, offset, length, Some(block_id))
}

/// Add a new row for an external trie blob -- i.e. we're creating a new trie whose blob will be
/// stored in an external file, but its metadata will be in the DB.
/// Returns the new row ID
pub fn write_external_trie_blob<T: MarfTrieId>(
    conn: &Connection,
    block_hash: &T,
    offset: u64,
    length: u64,
) -> Result<u32, Error> {
    inner_write_external_trie_blob(conn, block_hash, offset, length, None)
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

/// Determine the offset in the blobs file at which the last trie ends.  This is also the offset at
/// which the next trie will be appended.
///
/// Uses two index-friendly `ORDER BY … DESC LIMIT 1` queries instead of a
/// `UNION ALL` + `MAX()` which would force full table scans on every append.
pub fn get_external_blobs_length(conn: &Connection) -> Result<u64, Error> {
    let marf_end: u64 = db::query_row(
        conn,
        "SELECT (external_offset + external_length) AS end_offset \
         FROM marf_data ORDER BY external_offset DESC LIMIT 1",
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

/// Do we have a partially-migrated database?
/// Either all tries have offset and length 0, or they all don't.  If we have a mixture, then we're
/// corrupted.
pub fn detect_partial_migration(conn: &Connection) -> Result<bool, Error> {
    let migrated_version = get_migrated_version(conn);
    let schema_version = get_schema_version(conn);
    if migrated_version == schema_version {
        return Ok(false);
    }

    let num_migrated = db::query_count(
        conn,
        "SELECT COUNT(*) FROM marf_data WHERE external_offset = 0 AND external_length = 0 AND unconfirmed = 0",
        NO_PARAMS,
    )?;
    let num_not_migrated = db::query_count(
        conn,
        "SELECT COUNT(*) FROM marf_data WHERE external_offset != 0 AND external_length != 0 AND unconfirmed = 0",
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

use crate::chainstate::stacks::index::squash::SquashLevelRow;

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
    orphan_split_offset INTEGER NOT NULL DEFAULT 0
);
";

pub fn create_squash_levels_table(conn: &Connection) -> Result<(), Error> {
    conn.execute_batch(SQL_SQUASH_LEVELS_TABLE)?;
    // Best-effort, idempotent column-add for existing schemas.
    // `ALTER TABLE ... ADD COLUMN` errors if the column already exists; we
    // ignore that error and propagate any other.
    let _ = conn.execute_batch(
        "ALTER TABLE marf_squash_levels \
         ADD COLUMN root_sidecar_present INTEGER NOT NULL DEFAULT 0",
    );
    let _ = conn.execute_batch(
        "ALTER TABLE marf_squash_levels \
         ADD COLUMN root_sidecar_trimmed INTEGER NOT NULL DEFAULT 0",
    );
    let _ = conn.execute_batch(
        "ALTER TABLE marf_squash_levels \
         ADD COLUMN orphan_split_offset INTEGER NOT NULL DEFAULT 0",
    );
    Ok(())
}

pub fn write_squash_level(conn: &Connection, row: &SquashLevelRow) -> Result<(), Error> {
    conn.execute(
        "INSERT OR REPLACE INTO marf_squash_levels \
         (level_id, min_height, max_height, blob_offset, blob_length, \
          reads_redirected, root_sidecar_present, root_sidecar_trimmed, \
          orphan_split_offset) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
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
        ],
    )?;
    Ok(())
}

/// Mark `root_sidecar_present` for a level. Used at squash publish time
/// once the sidecar file has been atomically renamed into place. Idempotent.
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
/// This is intentionally called at trim time **before** the sidecar
/// file is `unlink`-ed: the SQL flag is the load-bearing source of
/// truth for the read path's `Error::SnapshotTrimmed` policy, and
/// flipping it first (followed by a `SquashMeta` republish) ensures
/// that no live handle ever observes the (file-missing, trimmed=false)
/// corruption window. The subsequent `unlink` is best-effort disk
/// hygiene; if it fails, the file is reaped by
/// [`crate::chainstate::stacks::index::sidecar::reconcile_squash_sidecars`]
/// on the next startup. See `trim_aged_root_sidecars` in `squash.rs`
/// for the full ordering rationale.
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

/// Update an existing `marf_data` row by block hash to point to a new external
/// blob location. Used by the incremental squash pipeline to redirect per-block
/// blob entries to the squash blob. The inline `data` column is cleared.
pub fn update_external_trie_blob_by_hash<T: MarfTrieId>(
    conn: &Connection,
    block_hash: &T,
    offset: u64,
    length: u64,
) -> Result<(), Error> {
    let empty_blob: &[u8] = &[];
    conn.execute(
        "UPDATE marf_data SET external_offset = ?1, external_length = ?2, data = ?3 \
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
         COALESCE(orphan_split_offset, 0) AS orphan_split_offset \
         FROM marf_squash_levels ORDER BY min_height ASC",
    )?;
    let rows = stmt
        .query_map(NO_PARAMS, |row| {
            Ok(SquashLevelRow {
                level_id: row.get::<_, u32>("level_id")?,
                min_height: row.get::<_, u32>("min_height")?,
                max_height: row.get::<_, u32>("max_height")?,
                blob_offset: row.get::<_, i64>("blob_offset")? as u64,
                blob_length: row.get::<_, i64>("blob_length")? as u64,
                reads_redirected: row.get::<_, i64>("reads_redirected")? != 0,
                root_sidecar_present: row.get::<_, i64>("root_sidecar_present")? != 0,
                root_sidecar_trimmed: row.get::<_, i64>("root_sidecar_trimmed")? != 0,
                orphan_split_offset: row.get::<_, i64>("orphan_split_offset")? as u32,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Validate that no live references point into the byte range `[from_offset, +∞)` in the
/// blob file, except for blocks whose `block_hash` is in `superseded_hashes`.
///
/// Returns `Ok(())` if the truncation zone is safe to overwrite/truncate.
/// Returns `Err(CorruptionError)` if any live reference would be destroyed.
///
/// Checks both `marf_data` and `marf_squash_levels`.
pub fn validate_truncation_zone<T: MarfTrieId>(
    conn: &Connection,
    from_offset: u64,
    superseded_hashes: &[T],
) -> Result<(), Error> {
    // Check each marf_data row that overlaps the truncation zone.
    // A blob overlaps if its extent (offset + length) exceeds from_offset.
    let mut stmt = conn.prepare(
        "SELECT block_hash, external_offset, external_length FROM marf_data \
         WHERE (external_offset + external_length) > ?1 AND external_length > 0",
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

    // Check marf_squash_levels: any level whose blob extent overlaps the
    // truncation zone? A level overlaps if blob_offset + blob_length > from_offset.
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

/// Prune external blob references for non-canonical `marf_data` rows whose blob
/// data falls within the reclaim truncation zone.
///
/// After blob export, committed fork blocks have `external_offset/external_length`
/// pointing into the `.blobs` file and `data = x''` (empty).  These rows are
/// unreachable from the canonical chain tip (`get_block_at_height` only walks
/// the canonical ancestry), but `validate_truncation_zone` correctly rejects
/// them because they are not in the canonical `superseded_hashes` set.
///
/// This function zeroes their external refs so that reclaim truncation can
/// proceed.  **This is an intentional pruning of non-canonical fork state**:
/// those trie blobs become permanently unreadable after this call.
///
/// Returns the number of orphaned rows pruned.
pub fn prune_orphaned_external_refs<T: MarfTrieId>(
    conn: &Connection,
    from_offset: u64,
    canonical_hashes: &[T],
) -> Result<u64, Error> {
    // Same predicate as validate_truncation_zone: find rows in the zone.
    let mut stmt = conn.prepare(
        "SELECT block_hash, external_offset FROM marf_data \
         WHERE (external_offset + external_length) > ?1 AND external_length > 0",
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
