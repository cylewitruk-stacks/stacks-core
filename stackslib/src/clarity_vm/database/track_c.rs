// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Production-shaped SQLite storage for canonical Track C Clarity values.

use std::str;

use clarity::vm::database::{TypedValueData, TypedValueResult};
use clarity::vm::errors::{VmExecutionError, VmInternalError};
use clarity::vm::types::storage::{
    decode_canonical_packed, encode_canonical_packed_value_with_consensus_len, StructuralValidation,
};
use clarity::vm::types::{PrincipalData, TypeSignature, Value};
use rusqlite::{params, Connection, OptionalExtension};
use stacks_common::types::StacksEpochId;
use stacks_common::util::hash::{hex_bytes, to_hex};

use crate::chainstate::stacks::index::MARFValue;

const FORMAT_VERSION: i64 = 2;
const FORMAT_TABLE: &str = "clarity_value_storage_format";

const CREATE_FORMAT_TABLE_SQL: &str = "CREATE TABLE clarity_value_storage_format (
    version INTEGER PRIMARY KEY NOT NULL,
    write_policy INTEGER NOT NULL CHECK(write_policy IN (1, 2))
)";
const CREATE_DATA_TABLE_SQL: &str = "CREATE TABLE data_table (
    value_hash BLOB NOT NULL
        CHECK(typeof(value_hash) = 'blob' AND length(value_hash) = 40),
    record BLOB NOT NULL
        CHECK(typeof(record) = 'blob' AND length(record) >= 1
              AND hex(substr(record, 1, 1)) IN ('00', '01', '02'))
)";
const CREATE_DATA_INDEX_SQL: &str =
    "CREATE UNIQUE INDEX data_table_value_hash ON data_table(value_hash)";
const INSERT_SQL: &str = "INSERT OR IGNORE INTO data_table (value_hash, record) VALUES (?1, ?2)";
const GET_SQL: &str = "SELECT record FROM data_table WHERE value_hash = ?1";

/// Exact canonical UTF-8, used for arbitrary generic storage values.
pub const KIND_CANONICAL_UTF8: i64 = 0;
/// Exact lowercase hexadecimal canonical text represented as decoded bytes.
pub const KIND_CANONICAL_HEX_BYTES: i64 = 1;
/// Canonical Track C packed Clarity value bytes.
pub const KIND_CANONICAL_PACKED: i64 = 2;

/// Typed-value write policy bound to a replacement `data_table` artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplacementWritePolicy {
    /// Store typed values as raw consensus bytes (Track A).
    ConsensusBytes,
    /// Store typed values as canonical packed bytes (Track C).
    CanonicalPacked,
}

impl ReplacementWritePolicy {
    fn code(self) -> i64 {
        match self {
            Self::ConsensusBytes => 1,
            Self::CanonicalPacked => 2,
        }
    }
}

/// Initialize an empty database for Track C, or verify an existing Track C schema.
pub fn initialize(
    conn: &Connection,
    policy: ReplacementWritePolicy,
) -> Result<(), VmExecutionError> {
    if let Some((version, stored_policy)) = format_state(conn)? {
        if version != FORMAT_VERSION || stored_policy != policy.code() {
            return Err(storage_error(format!(
                "replacement data_table format/policy mismatch: version={version}, policy={stored_policy}"
            )));
        }
        verify_schema(conn, policy)?;
        return Ok(());
    }

    let row_count: u64 = conn
        .query_row("SELECT COUNT(*) FROM data_table", [], |row| row.get(0))
        .map_err(sql_error)?;
    if row_count != 0 {
        return Err(storage_error(
            "Track C requires a migrated data_table; refusing to replace a populated legacy table",
        ));
    }

    conn.execute("DROP TABLE data_table", [])
        .map_err(sql_error)?;
    conn.execute(CREATE_DATA_TABLE_SQL, []).map_err(sql_error)?;
    conn.execute(CREATE_DATA_INDEX_SQL, []).map_err(sql_error)?;
    conn.execute(CREATE_FORMAT_TABLE_SQL, [])
        .map_err(sql_error)?;
    conn.execute(
        "INSERT INTO clarity_value_storage_format(version, write_policy) VALUES (?1, ?2)",
        params![FORMAT_VERSION, policy.code()],
    )
    .map_err(sql_error)?;
    verify_schema(conn, policy)
}

/// Reject a Track C database when another physical storage mode is selected.
pub fn reject_if_present(conn: &Connection) -> Result<(), VmExecutionError> {
    if let Some((version, policy)) = format_state(conn)? {
        return Err(storage_error(format!(
            "replacement data_table format {version}, policy {policy} opened in legacy mode"
        )));
    }
    Ok(())
}

/// Retain the copied legacy table while preparing a bulk migration destination.
pub fn initialize_bulk_migration_destination(
    conn: &Connection,
    policy: ReplacementWritePolicy,
) -> Result<(), VmExecutionError> {
    if format_state(conn)?.is_some() {
        return Err(storage_error(
            "migration destination is already marked as Track C",
        ));
    }
    conn.execute("ALTER TABLE data_table RENAME TO legacy_data_table", [])
        .map_err(sql_error)?;
    conn.execute(CREATE_DATA_TABLE_SQL, []).map_err(sql_error)?;
    conn.execute(CREATE_FORMAT_TABLE_SQL, [])
        .map_err(sql_error)?;
    conn.execute(
        "INSERT INTO clarity_value_storage_format(version, write_policy) VALUES (?1, ?2)",
        params![FORMAT_VERSION, policy.code()],
    )
    .map_err(sql_error)?;
    Ok(())
}

/// Build the deferred unique lookup index after bulk migration.
pub fn finalize_bulk_migration_destination(
    conn: &Connection,
    policy: ReplacementWritePolicy,
) -> Result<(), VmExecutionError> {
    conn.execute(CREATE_DATA_INDEX_SQL, []).map_err(sql_error)?;
    verify_schema(conn, policy)
}

/// Verify that `conn` exposes the supported Track C schema marker and columns.
pub fn verify(conn: &Connection, policy: ReplacementWritePolicy) -> Result<(), VmExecutionError> {
    match format_state(conn)? {
        Some((FORMAT_VERSION, stored_policy)) if stored_policy == policy.code() => {
            verify_schema(conn, policy)
        }
        Some((version, stored_policy)) => Err(storage_error(format!(
            "replacement data_table format/policy mismatch: version={version}, policy={stored_policy}"
        ))),
        None => Err(storage_error(
            "missing replacement data_table format marker",
        )),
    }
}

/// Store one typed Clarity value as canonical Track C bytes.
pub fn put_typed(
    conn: &Connection,
    value_hash: &MARFValue,
    canonical: &str,
    typed: TypedValueData,
) -> Result<(), VmExecutionError> {
    let consensus_byte_len = validate_typed_canonical(&typed, canonical)?;
    let packed = encode_canonical_packed_value_with_consensus_len(
        &typed.value,
        &typed.expected,
        &typed.epoch,
        consensus_byte_len,
        StructuralValidation::Disabled,
    )
    .map_err(codec_error)?
    .into_bytes();
    insert_or_reconcile(
        conn,
        value_hash,
        KIND_CANONICAL_PACKED,
        &packed,
        Some(canonical),
    )
}

/// Store one typed Clarity value as raw consensus bytes in the replacement table.
pub fn put_typed_consensus(
    conn: &Connection,
    value_hash: &MARFValue,
    canonical: &str,
    typed: TypedValueData,
) -> Result<(), VmExecutionError> {
    validate_typed_canonical(&typed, canonical)?;
    insert_or_reconcile(
        conn,
        value_hash,
        KIND_CANONICAL_HEX_BYTES,
        &typed.consensus,
        Some(canonical),
    )
}

/// Store one generic canonical value in an exactly reversible representation.
pub fn put_generic(
    conn: &Connection,
    value_hash: &MARFValue,
    canonical: &str,
) -> Result<(), VmExecutionError> {
    let (kind, payload) = match exact_lower_hex(canonical) {
        Some(bytes) => (KIND_CANONICAL_HEX_BYTES, bytes),
        None => (KIND_CANONICAL_UTF8, canonical.as_bytes().to_vec()),
    };
    insert_or_reconcile(conn, value_hash, kind, &payload, Some(canonical))
}

/// Fetch and decode one typed Track C row.
pub fn get_typed(
    conn: &Connection,
    value_hash: &MARFValue,
    expected: &TypeSignature,
    epoch: &StacksEpochId,
) -> Result<Option<TypedValueResult>, VmExecutionError> {
    let mut statement = conn.prepare_cached(GET_SQL).map_err(sql_error)?;
    let mut rows = statement
        .query(params![value_hash.as_bytes()])
        .map_err(sql_error)?;
    let Some(row) = rows.next().map_err(sql_error)? else {
        return Ok(None);
    };
    let stored = row
        .get_ref(0)
        .map_err(sql_error)?
        .as_blob()
        .map_err(codec_error)?;
    let (&kind, payload) = stored
        .split_first()
        .ok_or_else(|| storage_error("empty Track C record"))?;
    let (value, serialized_byte_len) = match kind {
        kind if i64::from(kind) == KIND_CANONICAL_UTF8 => {
            let canonical = str::from_utf8(payload).map_err(codec_error)?;
            let value = Value::try_deserialize_hex_at_epoch(canonical, expected, epoch)
                .map_err(codec_error)?;
            let len = canonical
                .len()
                .checked_div(2)
                .ok_or_else(|| storage_error("invalid canonical hexadecimal length"))?;
            (value, len as u64)
        }
        kind if i64::from(kind) == KIND_CANONICAL_HEX_BYTES => (
            decode_consensus_payload(payload, expected, epoch)?,
            payload.len() as u64,
        ),
        kind if i64::from(kind) == KIND_CANONICAL_PACKED => {
            let decoded = decode_canonical_packed(payload, expected, epoch).map_err(codec_error)?;
            (decoded.value, u64::from(decoded.consensus_byte_len))
        }
        _ => {
            return Err(storage_error(format!(
                "unknown Track C payload kind {kind}"
            )));
        }
    };
    Ok(Some(TypedValueResult {
        value,
        serialized_byte_len,
    }))
}

/// Fetch one generic Track C row and reconstruct its exact canonical text.
pub fn get_generic(
    conn: &Connection,
    value_hash: &MARFValue,
) -> Result<Option<String>, VmExecutionError> {
    let mut statement = conn.prepare_cached(GET_SQL).map_err(sql_error)?;
    let mut rows = statement
        .query(params![value_hash.as_bytes()])
        .map_err(sql_error)?;
    let Some(row) = rows.next().map_err(sql_error)? else {
        return Ok(None);
    };
    let stored = row
        .get_ref(0)
        .map_err(sql_error)?
        .as_blob()
        .map_err(codec_error)?;
    let (&kind, payload) = stored
        .split_first()
        .ok_or_else(|| storage_error("empty Track C record"))?;
    match kind {
        kind if i64::from(kind) == KIND_CANONICAL_UTF8 => str::from_utf8(payload)
            .map(str::to_owned)
            .map(Some)
            .map_err(codec_error),
        kind if i64::from(kind) == KIND_CANONICAL_HEX_BYTES => Ok(Some(to_hex(payload))),
        kind if i64::from(kind) == KIND_CANONICAL_PACKED => Err(storage_error(format!(
            "generic read addressed packed-only Track C row {}",
            value_hash.to_hex()
        ))),
        _ => Err(storage_error(format!(
            "unknown Track C payload kind {kind}"
        ))),
    }
}

fn insert_or_reconcile(
    conn: &Connection,
    value_hash: &MARFValue,
    kind: i64,
    payload: &[u8],
    canonical: Option<&str>,
) -> Result<(), VmExecutionError> {
    let expected_record = record(kind, payload)?;
    let inserted = conn
        .prepare_cached(INSERT_SQL)
        .and_then(|mut statement| {
            statement.execute(params![value_hash.as_bytes(), expected_record])
        })
        .map_err(sql_error)?;
    if inserted == 1 {
        return Ok(());
    }

    let (existing_kind, existing_payload) = load(conn, value_hash)?
        .ok_or_else(|| storage_error("Track C row disappeared during insert reconciliation"))?;
    if existing_kind == kind && existing_payload == payload {
        return Ok(());
    }

    if kind == KIND_CANONICAL_PACKED {
        let existing = canonical_from_payload(existing_kind, &existing_payload)?;
        if canonical == Some(existing.as_str()) {
            return Ok(());
        }
        return Err(storage_error(
            "typed write conflicts with an existing Track C content hash",
        ));
    }

    let canonical = canonical.ok_or_else(|| storage_error("missing canonical reconciliation"))?;
    if existing_kind == KIND_CANONICAL_PACKED {
        let replacement = record(kind, payload)?;
        let existing_record = record(existing_kind, &existing_payload)?;
        let updated = conn
            .prepare_cached(
                "UPDATE data_table SET record = ?2
                 WHERE value_hash = ?1 AND record = ?3",
            )
            .and_then(|mut statement| {
                statement.execute(params![value_hash.as_bytes(), replacement, existing_record,])
            })
            .map_err(sql_error)?;
        if updated == 1 {
            return Ok(());
        }
    } else if canonical_from_payload(existing_kind, &existing_payload)? == canonical {
        return Ok(());
    }

    let (final_kind, final_payload) = load(conn, value_hash)?
        .ok_or_else(|| storage_error("Track C row disappeared during reconciliation"))?;
    if final_kind != KIND_CANONICAL_PACKED
        && canonical_from_payload(final_kind, &final_payload)? == canonical
    {
        Ok(())
    } else {
        Err(storage_error(
            "generic write conflicts with an existing Track C content hash",
        ))
    }
}

fn load(
    conn: &Connection,
    value_hash: &MARFValue,
) -> Result<Option<(i64, Vec<u8>)>, VmExecutionError> {
    let stored: Option<Vec<u8>> = conn
        .prepare_cached(GET_SQL)
        .and_then(|mut statement| {
            statement
                .query_row(params![value_hash.as_bytes()], |row| row.get(0))
                .optional()
        })
        .map_err(sql_error)?;
    stored
        .map(|stored| {
            let (&kind, payload) = stored
                .split_first()
                .ok_or_else(|| storage_error("empty Track C record"))?;
            Ok((i64::from(kind), payload.to_vec()))
        })
        .transpose()
}

fn record(kind: i64, payload: &[u8]) -> Result<Vec<u8>, VmExecutionError> {
    let kind = u8::try_from(kind).map_err(|_| storage_error("invalid Track C payload kind"))?;
    if !matches!(
        i64::from(kind),
        KIND_CANONICAL_UTF8 | KIND_CANONICAL_HEX_BYTES | KIND_CANONICAL_PACKED
    ) {
        return Err(storage_error("invalid Track C payload kind"));
    }
    let mut record = Vec::with_capacity(payload.len() + 1);
    record.push(kind);
    record.extend_from_slice(payload);
    Ok(record)
}

fn canonical_from_payload(kind: i64, payload: &[u8]) -> Result<String, VmExecutionError> {
    match kind {
        KIND_CANONICAL_UTF8 => str::from_utf8(payload)
            .map(str::to_owned)
            .map_err(codec_error),
        KIND_CANONICAL_HEX_BYTES => Ok(to_hex(payload)),
        KIND_CANONICAL_PACKED => Err(storage_error(
            "packed Track C payload has no schema-free canonical text",
        )),
        _ => Err(storage_error(format!(
            "unknown Track C payload kind {kind}"
        ))),
    }
}

fn exact_lower_hex(canonical: &str) -> Option<Vec<u8>> {
    if !canonical.len().is_multiple_of(2)
        || !canonical
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    hex_bytes(canonical).ok()
}

fn consensus_matches_canonical(consensus: &[u8], canonical: &str) -> bool {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    canonical.len() == consensus.len().saturating_mul(2)
        && canonical
            .as_bytes()
            .chunks_exact(2)
            .zip(consensus)
            .all(|(encoded, byte)| {
                encoded.first() == HEX.get(usize::from(byte >> 4))
                    && encoded.get(1) == HEX.get(usize::from(byte & 0x0f))
            })
}

fn validate_typed_canonical(
    typed: &TypedValueData,
    canonical: &str,
) -> Result<u32, VmExecutionError> {
    if !consensus_matches_canonical(&typed.consensus, canonical) {
        return Err(storage_error(
            "typed value does not reproduce its canonical MARF payload",
        ));
    }
    u32::try_from(typed.consensus.len())
        .map_err(|_| storage_error("Clarity value exceeds the Track C length field"))
}

fn format_state(conn: &Connection) -> Result<Option<(i64, i64)>, VmExecutionError> {
    let exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
            [FORMAT_TABLE],
            |row| row.get(0),
        )
        .map_err(sql_error)?;
    if !exists {
        return Ok(None);
    }
    conn.query_row(
        "SELECT version, write_policy FROM clarity_value_storage_format",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()
    .map_err(sql_error)
}

fn verify_schema(
    conn: &Connection,
    policy: ReplacementWritePolicy,
) -> Result<(), VmExecutionError> {
    let state = format_state(conn)?;
    if state != Some((FORMAT_VERSION, policy.code())) {
        return Err(storage_error(format!(
            "replacement data_table marker mismatch: {state:?}"
        )));
    }
    let columns: Vec<(String, String)> = {
        let mut statement = conn
            .prepare("PRAGMA table_info(data_table)")
            .map_err(sql_error)?;
        let columns = statement
            .query_map([], |row| Ok((row.get(1)?, row.get(2)?)))
            .map_err(sql_error)?
            .collect::<rusqlite::Result<_>>()
            .map_err(sql_error)?;
        columns
    };
    let expected = [
        ("value_hash".to_owned(), "BLOB".to_owned()),
        ("record".to_owned(), "BLOB".to_owned()),
    ];
    if columns != expected {
        return Err(storage_error(format!(
            "invalid Track C data_table columns: {columns:?}"
        )));
    }
    let index_unique: Option<i64> = conn
        .query_row(
            "SELECT \"unique\" FROM pragma_index_list('data_table')
             WHERE name = 'data_table_value_hash'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql_error)?;
    let indexed_columns: Vec<String> = conn
        .prepare("SELECT name FROM pragma_index_info('data_table_value_hash') ORDER BY seqno")
        .map_err(sql_error)?
        .query_map([], |row| row.get(0))
        .map_err(sql_error)?
        .collect::<rusqlite::Result<_>>()
        .map_err(sql_error)?;
    if index_unique != Some(1) || indexed_columns != ["value_hash"] {
        return Err(storage_error("invalid Track C value-hash index"));
    }
    Ok(())
}

fn decode_consensus_payload(
    payload: &[u8],
    expected: &TypeSignature,
    epoch: &StacksEpochId,
) -> Result<Value, VmExecutionError> {
    match Value::try_deserialize_slice_at_epoch(payload, expected, epoch) {
        Ok(value) => Ok(value),
        Err(error)
            if matches!(
                expected,
                TypeSignature::CallableType(_) | TypeSignature::TraitReferenceType(_)
            ) =>
        {
            let principal = Value::try_deserialize_slice_at_epoch(
                payload,
                &TypeSignature::PrincipalType,
                epoch,
            )
            .map_err(codec_error)?;
            let Value::Principal(PrincipalData::Contract(contract_identifier)) = principal else {
                return Err(codec_error(error));
            };
            let trait_identifier = match expected {
                TypeSignature::CallableType(
                    clarity::vm::types::signatures::CallableSubtype::Principal(expected_contract),
                ) => {
                    if contract_identifier != *expected_contract {
                        return Err(codec_error(error));
                    }
                    None
                }
                TypeSignature::CallableType(
                    clarity::vm::types::signatures::CallableSubtype::Trait(trait_identifier),
                )
                | TypeSignature::TraitReferenceType(trait_identifier) => {
                    Some(Box::new(trait_identifier.clone()))
                }
                _ => unreachable!("guard restricts callable schema variants"),
            };
            Ok(Value::CallableContract(clarity::vm::types::CallableData {
                contract_identifier,
                trait_identifier,
            }))
        }
        Err(error) => Err(codec_error(error)),
    }
}

fn codec_error(error: impl std::fmt::Display) -> VmExecutionError {
    storage_error(error.to_string())
}

fn sql_error(error: rusqlite::Error) -> VmExecutionError {
    storage_error(error.to_string())
}

fn storage_error(message: impl Into<String>) -> VmExecutionError {
    VmInternalError::DBError(message.into()).into()
}

#[cfg(test)]
mod tests {
    use clarity::vm::types::TypeSignature;
    use stacks_common::types::StacksEpochId;
    use stacks_common::util::hash::to_hex;

    use super::*;

    const EPOCH: StacksEpochId = StacksEpochId::Epoch40;
    const PACKED_POLICY: ReplacementWritePolicy = ReplacementWritePolicy::CanonicalPacked;

    fn typed(value: Value, expected: TypeSignature) -> (String, TypedValueData, MARFValue) {
        let consensus = value.serialize_to_vec().unwrap();
        let canonical = to_hex(&consensus);
        let hash = MARFValue::from_value(&canonical);
        (
            canonical,
            TypedValueData {
                value,
                expected,
                epoch: EPOCH,
                consensus,
            },
            hash,
        )
    }

    #[test]
    fn initializes_only_empty_legacy_tables() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute(
            "CREATE TABLE data_table (key TEXT PRIMARY KEY, value TEXT)",
            [],
        )
        .unwrap();
        initialize(&conn, PACKED_POLICY).unwrap();
        assert_eq!(
            format_state(&conn).unwrap(),
            Some((FORMAT_VERSION, PACKED_POLICY.code()))
        );
        verify_schema(&conn, PACKED_POLICY).unwrap();
        assert!(reject_if_present(&conn).is_err());
    }

    #[test]
    fn replacement_write_policies_are_mutually_exclusive() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute(
            "CREATE TABLE data_table (key TEXT PRIMARY KEY, value TEXT)",
            [],
        )
        .unwrap();
        initialize(&conn, PACKED_POLICY).unwrap();

        assert!(initialize(&conn, ReplacementWritePolicy::ConsensusBytes).is_err());
        assert!(verify(&conn, ReplacementWritePolicy::ConsensusBytes).is_err());
        verify(&conn, PACKED_POLICY).unwrap();
    }

    #[test]
    fn typed_and_generic_rows_round_trip_with_one_lookup_shape() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute(
            "CREATE TABLE data_table (key TEXT PRIMARY KEY, value TEXT)",
            [],
        )
        .unwrap();
        initialize(&conn, PACKED_POLICY).unwrap();

        let value = Value::UInt(42);
        let (canonical, data, hash) = typed(value.clone(), TypeSignature::UIntType);
        put_typed(&conn, &hash, &canonical, data).unwrap();
        assert_eq!(
            get_typed(&conn, &hash, &TypeSignature::UIntType, &EPOCH)
                .unwrap()
                .unwrap()
                .value,
            value
        );
        assert!(get_generic(&conn, &hash).is_err());

        let generic = "not hexadecimal";
        let generic_hash = MARFValue::from_value(generic);
        put_generic(&conn, &generic_hash, generic).unwrap();
        assert_eq!(
            get_generic(&conn, &generic_hash).unwrap().as_deref(),
            Some(generic)
        );

        let hex = "000102ff";
        let hex_hash = MARFValue::from_value(hex);
        put_generic(&conn, &hex_hash, hex).unwrap();
        assert_eq!(get_generic(&conn, &hex_hash).unwrap().as_deref(), Some(hex));
    }

    #[test]
    fn consensus_mode_serves_typed_and_generic_reads_from_one_record() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute(
            "CREATE TABLE data_table (key TEXT PRIMARY KEY, value TEXT)",
            [],
        )
        .unwrap();
        initialize(&conn, ReplacementWritePolicy::ConsensusBytes).unwrap();

        let value = Value::UInt(42);
        let (canonical, data, hash) = typed(value.clone(), TypeSignature::UIntType);
        let consensus = data.consensus.clone();
        put_typed_consensus(&conn, &hash, &canonical, data).unwrap();

        let record: Vec<u8> = conn
            .query_row(
                "SELECT record FROM data_table WHERE value_hash = ?1",
                [hash.as_bytes()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(record[0], KIND_CANONICAL_HEX_BYTES as u8);
        assert_eq!(&record[1..], consensus);
        assert_eq!(
            get_typed(&conn, &hash, &TypeSignature::UIntType, &EPOCH)
                .unwrap()
                .unwrap()
                .value,
            value
        );
        assert_eq!(
            get_generic(&conn, &hash).unwrap().as_deref(),
            Some(canonical.as_str())
        );
        put_generic(&conn, &hash, &canonical).unwrap();
    }

    #[test]
    fn typed_writes_require_exact_lowercase_consensus_text() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute(
            "CREATE TABLE data_table (key TEXT PRIMARY KEY, value TEXT)",
            [],
        )
        .unwrap();
        initialize(&conn, PACKED_POLICY).unwrap();
        let (canonical, data, hash) = typed(Value::UInt(0xab), TypeSignature::UIntType);
        assert!(put_typed(&conn, &hash, &canonical.to_uppercase(), data).is_err());
    }

    #[test]
    fn real_capability_collision_monotonically_preserves_generic_reads() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute(
            "CREATE TABLE data_table (key TEXT PRIMARY KEY, value TEXT)",
            [],
        )
        .unwrap();
        initialize(&conn, PACKED_POLICY).unwrap();
        let value = Value::Bool(true);
        let (canonical, data, hash) = typed(value.clone(), TypeSignature::BoolType);
        put_typed(&conn, &hash, &canonical, data).unwrap();
        put_generic(&conn, &hash, &canonical).unwrap();

        assert_eq!(
            get_generic(&conn, &hash).unwrap().as_deref(),
            Some(canonical.as_str())
        );
        assert_eq!(
            get_typed(&conn, &hash, &TypeSignature::BoolType, &EPOCH)
                .unwrap()
                .unwrap()
                .value,
            value
        );
        let kind: u8 = conn
            .query_row(
                "SELECT unicode(substr(record, 1, 1)) FROM data_table",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(i64::from(kind), KIND_CANONICAL_HEX_BYTES);
    }
}
