// Copyright (C) 2025 Stacks Open Internet Foundation
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

use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use stacks::config::Config;
use stacks::types::chainstate::StacksPublicKey;
use stacks::util_lib::db::{sqlite_open, tx_begin_immediate, u64_to_sql, Error as DBError};
use stacks_network_types::ContentId;

/// Structure for storing **non-confidential** miner information
///  which can be reused between restarts
pub struct MinerDB {
    db: Connection,
}

static CREATE_STACKERDB_TRACKING: &str = "
CREATE TABLE stackerdb_tracking(
   public_key TEXT NOT NULL,
   slot_id INTEGER NOT NULL,
   slot_version INTEGER NOT NULL,
   PRIMARY KEY (public_key, slot_id)
) STRICT;
";

static CREATE_DB_CONFIG: &str = "
CREATE TABLE db_config(
   version INTEGER NOT NULL
) STRICT;
";

static SCHEMA_0: &[&str] = &[
    CREATE_STACKERDB_TRACKING,
    CREATE_DB_CONFIG,
    "INSERT INTO db_config VALUES (0);",
];

static CREATE_NATIVE_SIGNER_SEQUENCES: &str = "
CREATE TABLE native_signer_sequences(
   author_public_key BLOB NOT NULL,
   reward_cycle INTEGER NOT NULL,
   lane INTEGER NOT NULL,
   next_sequence INTEGER NOT NULL,
   previous_envelope_id BLOB,
   PRIMARY KEY (author_public_key, reward_cycle, lane)
) STRICT;
";

static SCHEMA_1: &[&str] = &[
    CREATE_NATIVE_SIGNER_SEQUENCES,
    "DELETE FROM db_config; INSERT INTO db_config VALUES (1);",
];

static MIGRATE_LEGACY_SIGNER_ADAPTER_VERSIONS: &str = "
CREATE TABLE legacy_signer_adapter_versions(
   public_key TEXT NOT NULL,
   slot_id INTEGER NOT NULL,
   slot_version INTEGER NOT NULL,
   PRIMARY KEY (public_key, slot_id)
) STRICT;
INSERT INTO legacy_signer_adapter_versions(public_key, slot_id, slot_version)
SELECT public_key, slot_id, slot_version FROM stackerdb_tracking;
DROP TABLE stackerdb_tracking;
";

static SCHEMA_2: &[&str] = &[
    MIGRATE_LEGACY_SIGNER_ADAPTER_VERSIONS,
    "DELETE FROM db_config; INSERT INTO db_config VALUES (2);",
];

pub static CURRENT_SCHEMA: u32 = 2;
pub static MINER_DB_NAME: &str = "miner.sqlite";

impl MinerDB {
    fn get_schema_version(conn: &Connection) -> Result<Option<u32>, DBError> {
        let qry_db_exists =
            "SELECT name FROM sqlite_master WHERE type='table' AND name='db_config'";
        let db_exists = conn
            .query_row(qry_db_exists, [], |_| Ok(true))
            .optional()?
            .is_some();
        if !db_exists {
            return Ok(None);
        }
        let version = conn.query_row("SELECT MAX(version) FROM db_config", [], |row| row.get(0))?;
        Ok(Some(version))
    }

    fn apply_schema_changes(conn: &Connection, changes: &[&str]) -> Result<(), DBError> {
        for query in changes.iter() {
            conn.execute_batch(query)?
        }
        Ok(())
    }

    fn apply_schema(db: &mut Connection) -> Result<(), DBError> {
        let tx = tx_begin_immediate(db)?;

        loop {
            match Self::get_schema_version(&tx)? {
                None => Self::apply_schema_changes(&tx, SCHEMA_0)?,
                Some(0) => Self::apply_schema_changes(&tx, SCHEMA_1)?,
                Some(1) => Self::apply_schema_changes(&tx, SCHEMA_2)?,
                Some(v) if v == CURRENT_SCHEMA => break,
                Some(v) => {
                    error!(
                        "Unexpected DB schema for minerdb: {v}. Latest supported schema is {CURRENT_SCHEMA}"
                    );
                    return Err(DBError::Corruption);
                }
            }
        }

        tx.commit()?;

        Ok(())
    }

    pub fn miner_db_path(config: &Config) -> PathBuf {
        let mut path = config.get_chainstate_path();
        path.set_file_name(MINER_DB_NAME);
        path
    }

    pub fn open<P: AsRef<Path>>(db_path: P) -> Result<Self, DBError> {
        let open_flags = OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_READ_WRITE;
        let mut db = sqlite_open(db_path, open_flags, false)?;
        Self::apply_schema(&mut db)?;
        Ok(Self { db })
    }

    pub fn open_with_config(config: &Config) -> Result<Self, DBError> {
        let db_path = Self::miner_db_path(config);
        Self::open(db_path)
    }

    /// Get the latest known version from the db for the given slot_id/pk pair
    pub fn get_legacy_adapter_version(
        &self,
        pk: &StacksPublicKey,
        slot_id: u32,
    ) -> Result<Option<u32>, DBError> {
        self.db
            .query_row(
                "SELECT slot_version FROM legacy_signer_adapter_versions WHERE public_key = ? AND slot_id = ?",
                params![pk.to_hex(), slot_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(DBError::from)
    }

    /// Set the latest known version for the given slot_id/pk pair
    pub fn set_legacy_adapter_version(
        &self,
        pk: &StacksPublicKey,
        slot_id: u32,
        slot_version: u32,
    ) -> Result<(), DBError> {
        self.db.execute(
            "INSERT OR REPLACE INTO legacy_signer_adapter_versions (public_key, slot_id, slot_version) VALUES (?, ?, ?)",
            params![pk.to_hex(), slot_id, slot_version],
        )?;
        Ok(())
    }

    /// Load the next restart-safe native signer sequence and predecessor.
    pub fn get_native_signer_sequence(
        &self,
        author_public_key: &[u8],
        reward_cycle: u64,
        lane: i32,
    ) -> Result<(u64, Option<ContentId>), DBError> {
        let row: Option<(u64, Option<Vec<u8>>)> = self
            .db
            .query_row(
                "SELECT next_sequence, previous_envelope_id
                 FROM native_signer_sequences
                 WHERE author_public_key = ?1 AND reward_cycle = ?2 AND lane = ?3",
                params![author_public_key, u64_to_sql(reward_cycle)?, lane],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((next_sequence, previous)) = row else {
            return Ok((0, None));
        };
        let previous = previous
            .map(|bytes| {
                let bytes: [u8; 32] = bytes.try_into().map_err(|_| DBError::Corruption)?;
                Ok::<ContentId, DBError>(ContentId::from_bytes(bytes))
            })
            .transpose()?;
        Ok((next_sequence, previous))
    }

    /// Durably advance a locally-authored lane before enqueueing its envelope.
    /// The monotonic guard makes stale retries harmless after coordinator churn.
    pub fn advance_native_signer_sequence(
        &self,
        author_public_key: &[u8],
        reward_cycle: u64,
        lane: i32,
        next_sequence: u64,
        previous_envelope_id: &ContentId,
    ) -> Result<(), DBError> {
        self.db.execute(
            "INSERT INTO native_signer_sequences
             (author_public_key, reward_cycle, lane, next_sequence, previous_envelope_id)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(author_public_key, reward_cycle, lane) DO UPDATE SET
                 next_sequence = excluded.next_sequence,
                 previous_envelope_id = excluded.previous_envelope_id
             WHERE excluded.next_sequence > native_signer_sequences.next_sequence",
            params![
                author_public_key,
                u64_to_sql(reward_cycle)?,
                lane,
                u64_to_sql(next_sequence)?,
                previous_envelope_id.as_bytes().as_slice(),
            ],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::{Connection, OpenFlags};
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn native_signer_sequence_is_restart_safe_and_monotonic() {
        let tempdir = TempDir::new().unwrap();
        let path = tempdir.path().join(MINER_DB_NAME);
        let author = [0x02; 33];
        let cycle = 42;
        let lane = 3;
        let first = ContentId::from_bytes([0x11; 32]);
        let stale = ContentId::from_bytes([0x22; 32]);
        let second = ContentId::from_bytes([0x33; 32]);

        {
            let db = MinerDB::open(&path).unwrap();
            assert_eq!(
                db.get_native_signer_sequence(&author, cycle, lane).unwrap(),
                (0, None)
            );

            db.advance_native_signer_sequence(&author, cycle, lane, 1, &first)
                .unwrap();
            assert_eq!(
                db.get_native_signer_sequence(&author, cycle, lane).unwrap(),
                (1, Some(first))
            );

            // Coordinator retries at the same cursor must not rewrite the
            // predecessor, or the next envelope would fork after a restart.
            db.advance_native_signer_sequence(&author, cycle, lane, 1, &stale)
                .unwrap();
            assert_eq!(
                db.get_native_signer_sequence(&author, cycle, lane).unwrap(),
                (1, Some(first))
            );

            db.advance_native_signer_sequence(&author, cycle, lane, 2, &second)
                .unwrap();
        }

        let reopened = MinerDB::open(&path).unwrap();
        assert_eq!(
            reopened
                .get_native_signer_sequence(&author, cycle, lane)
                .unwrap(),
            (2, Some(second))
        );
        assert_eq!(MinerDB::get_schema_version(&reopened.db).unwrap(), Some(2));
    }

    #[test]
    fn migrates_schema_zero_into_quarantined_legacy_adapter_tracking() {
        let tempdir = TempDir::new().unwrap();
        let path = tempdir.path().join(MINER_DB_NAME);
        let public_key = StacksPublicKey::from_hex(
            "020202020202020202020202020202020202020202020202020202020202020202",
        )
        .unwrap();

        {
            let conn = Connection::open_with_flags(
                &path,
                OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_READ_WRITE,
            )
            .unwrap();
            MinerDB::apply_schema_changes(&conn, SCHEMA_0).unwrap();
            conn.execute(
                "INSERT INTO stackerdb_tracking (public_key, slot_id, slot_version)
                 VALUES (?1, ?2, ?3)",
                params![public_key.to_hex(), 7, 9],
            )
            .unwrap();
            assert_eq!(MinerDB::get_schema_version(&conn).unwrap(), Some(0));
        }

        let migrated = MinerDB::open(&path).unwrap();
        assert_eq!(MinerDB::get_schema_version(&migrated.db).unwrap(), Some(2));
        assert_eq!(
            migrated.get_legacy_adapter_version(&public_key, 7).unwrap(),
            Some(9)
        );
        assert!(migrated
            .db
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='stackerdb_tracking'",
                [],
                |_| Ok(()),
            )
            .optional()
            .unwrap()
            .is_none());
        assert_eq!(
            migrated
                .get_native_signer_sequence(&[0x03; 33], 11, 1)
                .unwrap(),
            (0, None)
        );
    }
}
