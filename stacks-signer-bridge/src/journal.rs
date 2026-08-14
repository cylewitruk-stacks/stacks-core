use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use stacks_network_types::ContentId;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS bridge_versions(
  contract TEXT NOT NULL,
  slot_id INTEGER NOT NULL,
  next_version INTEGER NOT NULL,
  PRIMARY KEY(contract, slot_id)
) STRICT;
CREATE TABLE IF NOT EXISTS bridge_correlations(
  semantic_id BLOB NOT NULL,
  native_envelope_id BLOB,
  chunk_id BLOB NOT NULL UNIQUE,
  reward_cycle INTEGER NOT NULL,
  contract TEXT NOT NULL,
  slot_id INTEGER NOT NULL,
  slot_version INTEGER NOT NULL,
  chunk BLOB NOT NULL,
  state INTEGER NOT NULL,
  observed_at INTEGER NOT NULL,
  PRIMARY KEY(contract, slot_id, slot_version)
) STRICT;
CREATE INDEX IF NOT EXISTS bridge_correlations_cycle
  ON bridge_correlations(reward_cycle, observed_at);
";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorrelationRecord {
    pub semantic_id: ContentId,
    pub native_envelope_id: Option<ContentId>,
    pub chunk_id: ContentId,
    pub reward_cycle: u64,
    pub contract: String,
    pub slot_id: u32,
    pub slot_version: u32,
    pub chunk: Vec<u8>,
    pub state: i32,
    pub observed_at: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum BridgeJournalError {
    #[error(transparent)]
    Sql(#[from] rusqlite::Error),
    #[error("bridge journal contains invalid integer or content ID data")]
    Corruption,
    #[error("legacy slot version exhausted")]
    VersionExhausted,
    #[error("failed to construct reserved legacy chunk: {0}")]
    Build(String),
}

pub struct BridgeJournal {
    connection: Connection,
}

impl BridgeJournal {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, BridgeJournalError> {
        let connection = Connection::open(path)?;
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")?;
        connection.execute_batch(SCHEMA)?;
        Ok(Self { connection })
    }

    /// Atomically reserve a never-reused legacy version and persist the exact
    /// signed chunk before it can enter an asynchronous writer queue.
    pub fn reserve_and_record_with(
        &mut self,
        contract: &str,
        slot_id: u32,
        build: impl FnOnce(u32) -> Result<CorrelationRecord, BridgeJournalError>,
    ) -> Result<CorrelationRecord, BridgeJournalError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let next: Option<u32> = tx
            .query_row(
                "SELECT next_version FROM bridge_versions WHERE contract=?1 AND slot_id=?2",
                params![contract, slot_id],
                |row| row.get(0),
            )
            .optional()?;
        let version = next.unwrap_or(0);
        let following = version
            .checked_add(1)
            .ok_or(BridgeJournalError::VersionExhausted)?;
        let record = build(version)?;
        if record.contract != contract
            || record.slot_id != slot_id
            || record.slot_version != version
        {
            return Err(BridgeJournalError::Corruption);
        }
        tx.execute(
            "INSERT INTO bridge_versions(contract,slot_id,next_version) VALUES(?1,?2,?3)
             ON CONFLICT(contract,slot_id) DO UPDATE SET next_version=excluded.next_version
             WHERE excluded.next_version > bridge_versions.next_version",
            params![contract, slot_id, following],
        )?;
        tx.execute(
            "INSERT INTO bridge_correlations
             (semantic_id,native_envelope_id,chunk_id,reward_cycle,contract,slot_id,
              slot_version,chunk,state,observed_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                record.semantic_id.as_bytes().as_slice(),
                record.native_envelope_id.map(|id| id.as_bytes().to_vec()),
                record.chunk_id.as_bytes().as_slice(),
                to_sql_u64(record.reward_cycle)?,
                record.contract,
                record.slot_id,
                version,
                record.chunk,
                record.state,
                to_sql_u64(record.observed_at)?,
            ],
        )?;
        tx.commit()?;
        Ok(record)
    }

    pub fn is_local_echo(&self, chunk_id: ContentId) -> Result<bool, BridgeJournalError> {
        Ok(self
            .connection
            .query_row(
                "SELECT 1 FROM bridge_correlations WHERE chunk_id=?1",
                [chunk_id.as_bytes().as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Raise (never lower) the next version after a legacy node reports a
    /// pre-existing slot version during compatibility upgrade.
    pub fn advance_version_floor(
        &self,
        contract: &str,
        slot_id: u32,
        next_version: u32,
    ) -> Result<(), BridgeJournalError> {
        self.connection.execute(
            "INSERT INTO bridge_versions(contract,slot_id,next_version) VALUES(?1,?2,?3)
             ON CONFLICT(contract,slot_id) DO UPDATE SET next_version=excluded.next_version
             WHERE excluded.next_version > bridge_versions.next_version",
            params![contract, slot_id, next_version],
        )?;
        Ok(())
    }

    pub fn mark_state(&self, chunk_id: ContentId, state: i32) -> Result<(), BridgeJournalError> {
        self.connection.execute(
            "UPDATE bridge_correlations SET state=?2 WHERE chunk_id=?1",
            params![chunk_id.as_bytes().as_slice(), state],
        )?;
        Ok(())
    }

    pub fn prune_cycles(&self, current: u64, next: Option<u64>) -> Result<(), BridgeJournalError> {
        match next {
            Some(next) => self.connection.execute(
                "DELETE FROM bridge_correlations WHERE reward_cycle != ?1 AND reward_cycle != ?2",
                params![to_sql_u64(current)?, to_sql_u64(next)?],
            )?,
            None => self.connection.execute(
                "DELETE FROM bridge_correlations WHERE reward_cycle != ?1",
                [to_sql_u64(current)?],
            )?,
        };
        Ok(())
    }
}

fn to_sql_u64(value: u64) -> Result<i64, BridgeJournalError> {
    i64::try_from(value).map_err(|_| BridgeJournalError::Corruption)
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn record(version: u32) -> CorrelationRecord {
        CorrelationRecord {
            semantic_id: ContentId::from_domain_bytes(b"semantic", &[version as u8]),
            native_envelope_id: None,
            chunk_id: ContentId::from_domain_bytes(b"chunk", &[version as u8]),
            reward_cycle: 7,
            contract: "ST000000000000000000002AMW42H.signers-1-1".to_owned(),
            slot_id: 3,
            slot_version: version,
            chunk: vec![version as u8],
            state: 0,
            observed_at: 1,
        }
    }

    #[test]
    fn observed_legacy_version_only_advances_the_durable_floor() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("bridge.sqlite");
        let mut journal = BridgeJournal::open(&path).unwrap();
        let contract = "ST000000000000000000002AMW42H.signers-1-1";

        journal.advance_version_floor(contract, 3, 8).unwrap();
        let first = journal
            .reserve_and_record_with(contract, 3, |version| Ok(record(version)))
            .unwrap();
        assert_eq!(first.slot_version, 8);

        journal.advance_version_floor(contract, 3, 2).unwrap();
        let second = journal
            .reserve_and_record_with(contract, 3, |version| Ok(record(version)))
            .unwrap();
        assert_eq!(second.slot_version, 9);

        drop(journal);
        let mut reopened = BridgeJournal::open(path).unwrap();
        let third = reopened
            .reserve_and_record_with(contract, 3, |version| Ok(record(version)))
            .unwrap();
        assert_eq!(third.slot_version, 10);
    }
}
