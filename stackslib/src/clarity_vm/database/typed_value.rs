// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Experimental typed Clarity value side storage used by whole-block comparisons.

use std::sync::atomic::{AtomicU64, Ordering};
use std::{env, mem};

use clarity::vm::database::{TypedValueData, TypedValueResult};
use clarity::vm::errors::{VmExecutionError, VmInternalError};
use clarity::vm::types::signatures::CallableSubtype;
use clarity::vm::types::storage::{
    decode_packed_value, encode_packed_value_with_consensus_len, StructuralValidation,
};
use clarity::vm::types::{CallableData, PrincipalData, TypeSignature, Value};
use rusqlite::{params, Connection};
use stacks_common::types::StacksEpochId;

use crate::chainstate::stacks::index::MARFValue;
use crate::clarity_vm::database::track_c;

const MODE_ENV: &str = "STACKS_CLARITY_VALUE_STORAGE";

const CREATE_TABLE_SQL: &str = "CREATE TABLE IF NOT EXISTS clarity_typed_data (
    value_hash BLOB PRIMARY KEY NOT NULL CHECK(typeof(value_hash) = 'blob' AND length(value_hash) = 40),
    storage_kind INTEGER NOT NULL,
    payload BLOB NOT NULL CHECK(typeof(payload) = 'blob'),
    consensus_byte_len INTEGER NOT NULL
)";
const INSERT_SQL: &str = "INSERT OR IGNORE INTO clarity_typed_data
    (value_hash, storage_kind, payload, consensus_byte_len)
    VALUES (?1, ?2, ?3, ?4)";
const EXISTING_SQL: &str = "SELECT storage_kind, payload, consensus_byte_len
    FROM clarity_typed_data WHERE value_hash = ?1";
const DOWNGRADE_TO_RAW_SQL: &str = "UPDATE clarity_typed_data
    SET storage_kind = ?2, payload = ?3, consensus_byte_len = ?4
    WHERE value_hash = ?1 AND storage_kind = ?5 AND payload = ?6 AND consensus_byte_len = ?7";
const GET_SQL: &str = "SELECT storage_kind, payload, consensus_byte_len
    FROM clarity_typed_data WHERE value_hash = ?1";

const KIND_HEX_UTF8: i64 = 0;
const KIND_CONSENSUS_BYTES: i64 = 1;
const KIND_PACKED_TYPED: i64 = 2;

static READ_HITS: AtomicU64 = AtomicU64::new(0);
static READ_FALLBACKS: AtomicU64 = AtomicU64::new(0);
static WRITES: AtomicU64 = AtomicU64::new(0);
static RAW_WRITES: AtomicU64 = AtomicU64::new(0);
static PACKED_WRITES: AtomicU64 = AtomicU64::new(0);
/// Physical value-storage arm selected for a process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TypedValueStorageMode {
    /// Exact production behavior; the experimental table is not opened or queried.
    Current,
    /// Shared typed-table plumbing with the current canonical hexadecimal payload.
    IntegratedHex,
    /// Raw consensus bytes.
    ConsensusBytes,
    /// The smaller of raw consensus bytes and packed typed bytes.
    PackedTyped,
    /// Raw consensus bytes in the production-shaped replacement `data_table`.
    CanonicalConsensus,
    /// Canonical Track C packed values in the production-shaped `data_table`.
    CanonicalPacked,
}

impl TypedValueStorageMode {
    /// Read the benchmark arm from `STACKS_CLARITY_VALUE_STORAGE`.
    pub fn from_environment() -> Result<Self, VmExecutionError> {
        match env::var(MODE_ENV).as_deref() {
            Ok("integrated-hex") => Ok(Self::IntegratedHex),
            Ok("track-a") => Ok(Self::ConsensusBytes),
            Ok("track-a-data-table") => Ok(Self::CanonicalConsensus),
            Ok("track-b") => Ok(Self::PackedTyped),
            Ok("track-c") => Ok(Self::CanonicalPacked),
            Ok("current") | Err(env::VarError::NotPresent) => Ok(Self::Current),
            Ok(value) => {
                Err(VmInternalError::Expect(format!("invalid {MODE_ENV} value '{value}'")).into())
            }
            Err(error) => {
                Err(VmInternalError::Expect(format!("failed to read {MODE_ENV}: {error}")).into())
            }
        }
    }

    /// Whether this arm uses the experimental typed table.
    pub fn is_integrated(self) -> bool {
        self != Self::Current
    }

    /// Whether this mode replaces the legacy text-keyed `data_table`.
    pub fn uses_canonical_data_table(self) -> bool {
        matches!(self, Self::CanonicalConsensus | Self::CanonicalPacked)
    }
}

/// Process-wide experimental counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TypedValueStorageCounters {
    /// Typed-table read hits.
    pub read_hits: u64,
    /// Legacy reads promoted to the typed table.
    pub read_fallbacks: u64,
    /// Typed values written.
    pub writes: u64,
    /// Typed writes stored as raw or hexadecimal payloads.
    pub raw_writes: u64,
    /// Typed writes stored packed.
    pub packed_writes: u64,
}

/// Return current process-wide counters.
pub fn counters() -> TypedValueStorageCounters {
    TypedValueStorageCounters {
        read_hits: READ_HITS.load(Ordering::Relaxed),
        read_fallbacks: READ_FALLBACKS.load(Ordering::Relaxed),
        writes: WRITES.load(Ordering::Relaxed),
        raw_writes: RAW_WRITES.load(Ordering::Relaxed),
        packed_writes: PACKED_WRITES.load(Ordering::Relaxed),
    }
}

/// Create the experimental table for an integrated arm.
pub fn initialize(conn: &Connection, mode: TypedValueStorageMode) -> Result<(), VmExecutionError> {
    match mode {
        TypedValueStorageMode::CanonicalConsensus => {
            return track_c::initialize(conn, track_c::ReplacementWritePolicy::ConsensusBytes);
        }
        TypedValueStorageMode::CanonicalPacked => {
            return track_c::initialize(conn, track_c::ReplacementWritePolicy::CanonicalPacked);
        }
        TypedValueStorageMode::Current
        | TypedValueStorageMode::IntegratedHex
        | TypedValueStorageMode::ConsensusBytes
        | TypedValueStorageMode::PackedTyped => track_c::reject_if_present(conn)?,
    }
    if mode.is_integrated() {
        conn.execute(CREATE_TABLE_SQL, []).map_err(sql_error)?;
    }
    Ok(())
}

/// Store one typed value under its unchanged logical MARF hash.
pub fn put(
    conn: &Connection,
    mode: TypedValueStorageMode,
    value_hash: &MARFValue,
    canonical: &str,
    mut typed: TypedValueData,
) -> Result<(), VmExecutionError> {
    debug_assert!(mode.is_integrated());
    if mode.uses_canonical_data_table() {
        let result = if mode == TypedValueStorageMode::CanonicalPacked {
            track_c::put_typed(conn, value_hash, canonical, typed)
        } else {
            track_c::put_typed_consensus(conn, value_hash, canonical, typed)
        };
        if result.is_ok() {
            WRITES.fetch_add(1, Ordering::Relaxed);
            if mode == TypedValueStorageMode::CanonicalPacked {
                PACKED_WRITES.fetch_add(1, Ordering::Relaxed);
            } else {
                RAW_WRITES.fetch_add(1, Ordering::Relaxed);
            }
        }
        return result;
    }
    if !matches_canonical_hex(&typed.consensus, canonical) {
        return Err(VmInternalError::Expect(
            "typed value does not reproduce its canonical MARF payload".into(),
        )
        .into());
    }
    let consensus_byte_len = typed
        .consensus
        .len()
        .try_into()
        .map_err(|_| VmInternalError::Expect("Clarity value too large".into()))?;
    let encoded = encode_payload(mode, &mut typed, canonical)?;
    let canonical_consensus = if encoded.kind == KIND_CONSENSUS_BYTES {
        encoded.bytes.as_slice()
    } else {
        typed.consensus.as_slice()
    };
    let inserted = conn
        .prepare_cached(INSERT_SQL)
        .and_then(|mut statement| {
            statement.execute(params![
                value_hash.as_bytes(),
                encoded.kind,
                encoded.bytes,
                i64::from(consensus_byte_len),
            ])
        })
        .map_err(sql_error)?;
    if inserted == 0 {
        reconcile_existing_row(
            conn,
            mode,
            value_hash,
            &encoded,
            &typed.expected,
            &typed.epoch,
            canonical_consensus,
            consensus_byte_len,
        )?;
    }
    WRITES.fetch_add(1, Ordering::Relaxed);
    if encoded.kind == KIND_PACKED_TYPED {
        PACKED_WRITES.fetch_add(1, Ordering::Relaxed);
    } else {
        RAW_WRITES.fetch_add(1, Ordering::Relaxed);
    }
    Ok(())
}

fn reconcile_existing_row(
    conn: &Connection,
    mode: TypedValueStorageMode,
    value_hash: &MARFValue,
    expected: &EncodedPayload,
    schema: &TypeSignature,
    epoch: &StacksEpochId,
    canonical_consensus: &[u8],
    expected_consensus_len: u32,
) -> Result<(), VmExecutionError> {
    let (existing_kind, existing_payload, existing_consensus_len) =
        load_existing_row(conn, value_hash)?;
    if existing_kind == expected.kind
        && existing_payload == expected.bytes
        && existing_consensus_len == expected_consensus_len
    {
        return Ok(());
    }

    if mode != TypedValueStorageMode::PackedTyped {
        return Err(conflicting_payload_error());
    }

    if existing_kind == KIND_CONSENSUS_BYTES
        && existing_payload == canonical_consensus
        && existing_consensus_len == expected_consensus_len
    {
        return Ok(());
    }

    if existing_kind != KIND_PACKED_TYPED {
        return Err(conflicting_payload_error());
    }

    if let Ok(decoded) = decode_packed_value(&existing_payload, schema, epoch) {
        if decoded.consensus_byte_len == expected_consensus_len
            && decoded.value.serialize_to_vec().map_err(codec_error)? == canonical_consensus
        {
            return Ok(());
        }
    }

    let updated = conn
        .prepare_cached(DOWNGRADE_TO_RAW_SQL)
        .and_then(|mut statement| {
            statement.execute(params![
                value_hash.as_bytes(),
                KIND_CONSENSUS_BYTES,
                canonical_consensus,
                i64::from(expected_consensus_len),
                existing_kind,
                existing_payload,
                i64::from(existing_consensus_len),
            ])
        })
        .map_err(sql_error)?;
    if updated == 1 {
        Ok(())
    } else {
        // Another writer may have performed the same monotonic downgrade.
        let row = load_existing_row(conn, value_hash)?;
        if row.0 == KIND_CONSENSUS_BYTES
            && row.1 == canonical_consensus
            && row.2 == expected_consensus_len
        {
            Ok(())
        } else {
            Err(conflicting_payload_error())
        }
    }
}

fn load_existing_row(
    conn: &Connection,
    value_hash: &MARFValue,
) -> Result<(i64, Vec<u8>, u32), VmExecutionError> {
    conn.prepare_cached(EXISTING_SQL)
        .and_then(|mut statement| {
            statement.query_row(params![value_hash.as_bytes()], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
        })
        .map_err(sql_error)
}

fn conflicting_payload_error() -> VmExecutionError {
    VmInternalError::DBError("conflicting typed payload for an existing value hash".into()).into()
}

/// Fetch and decode one typed value.
pub fn get(
    conn: &Connection,
    mode: TypedValueStorageMode,
    value_hash: &MARFValue,
    expected: &TypeSignature,
    epoch: &StacksEpochId,
) -> Result<Option<TypedValueResult>, VmExecutionError> {
    debug_assert!(mode.is_integrated());
    if mode.uses_canonical_data_table() {
        let result = track_c::get_typed(conn, value_hash, expected, epoch)?;
        if result.is_some() {
            READ_HITS.fetch_add(1, Ordering::Relaxed);
        }
        return Ok(result);
    }
    let mut statement = conn.prepare_cached(GET_SQL).map_err(sql_error)?;
    let mut rows = statement
        .query(params![value_hash.as_bytes()])
        .map_err(sql_error)?;
    let Some(row) = rows.next().map_err(sql_error)? else {
        return Ok(None);
    };
    let kind = row.get::<_, i64>(0).map_err(sql_error)?;
    let payload = row
        .get_ref(1)
        .map_err(sql_error)?
        .as_blob()
        .map_err(codec_error)?;
    let consensus_byte_len = row.get::<_, u32>(2).map_err(sql_error)?;
    let value = decode_payload(kind, payload, consensus_byte_len, expected, epoch)?;
    READ_HITS.fetch_add(1, Ordering::Relaxed);
    Ok(Some(TypedValueResult {
        value,
        serialized_byte_len: u64::from(consensus_byte_len),
    }))
}

/// Record a legacy fallback that can be distinguished from typed-table hits.
pub fn record_fallback() {
    READ_FALLBACKS.fetch_add(1, Ordering::Relaxed);
}

struct EncodedPayload {
    kind: i64,
    bytes: Vec<u8>,
}

fn encode_payload(
    mode: TypedValueStorageMode,
    typed: &mut TypedValueData,
    canonical: &str,
) -> Result<EncodedPayload, VmExecutionError> {
    match mode {
        TypedValueStorageMode::Current => unreachable!("current mode has no typed table"),
        TypedValueStorageMode::IntegratedHex => Ok(EncodedPayload {
            kind: KIND_HEX_UTF8,
            bytes: canonical.as_bytes().to_vec(),
        }),
        TypedValueStorageMode::ConsensusBytes => Ok(EncodedPayload {
            kind: KIND_CONSENSUS_BYTES,
            bytes: mem::take(&mut typed.consensus),
        }),
        TypedValueStorageMode::PackedTyped => {
            let consensus_byte_len = typed
                .consensus
                .len()
                .try_into()
                .map_err(|_| VmInternalError::Expect("Clarity value too large".into()))?;
            let packed = encode_packed_value_with_consensus_len(
                &typed.value,
                &typed.expected,
                &typed.epoch,
                consensus_byte_len,
                StructuralValidation::Disabled,
            )
            .map_err(codec_error)?
            .into_bytes();
            if packed.len() < typed.consensus.len() {
                Ok(EncodedPayload {
                    kind: KIND_PACKED_TYPED,
                    bytes: packed,
                })
            } else {
                Ok(EncodedPayload {
                    kind: KIND_CONSENSUS_BYTES,
                    bytes: mem::take(&mut typed.consensus),
                })
            }
        }
        TypedValueStorageMode::CanonicalConsensus => {
            unreachable!("replacement Track A encoding is handled by track_c::put_typed_consensus")
        }
        TypedValueStorageMode::CanonicalPacked => {
            unreachable!("Track C encoding is handled by track_c::put_typed")
        }
    }
}

fn matches_canonical_hex(bytes: &[u8], canonical: &str) -> bool {
    let canonical = canonical.as_bytes();
    if canonical.len() != bytes.len().saturating_mul(2) {
        return false;
    }
    canonical
        .chunks_exact(2)
        .zip(bytes)
        .all(|(digits, byte)| digits == [hex_digit(byte >> 4), hex_digit(byte & 0x0f)])
}

fn hex_digit(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        10..=15 => b'a' + nibble - 10,
        _ => unreachable!("a nibble always fits in four bits"),
    }
}

fn decode_payload(
    kind: i64,
    payload: &[u8],
    consensus_byte_len: u32,
    expected: &TypeSignature,
    epoch: &StacksEpochId,
) -> Result<Value, VmExecutionError> {
    match kind {
        KIND_HEX_UTF8 => {
            let canonical = std::str::from_utf8(payload).map_err(codec_error)?;
            if canonical.len() / 2 != consensus_byte_len as usize {
                return Err(VmInternalError::DBError(
                    "typed hexadecimal payload length mismatch".into(),
                )
                .into());
            }
            Value::try_deserialize_hex_at_epoch(canonical, expected, epoch).map_err(codec_error)
        }
        KIND_CONSENSUS_BYTES => {
            if payload.len() != consensus_byte_len as usize {
                return Err(VmInternalError::DBError(
                    "typed consensus payload length mismatch".into(),
                )
                .into());
            }
            decode_consensus_payload(payload, expected, epoch)
        }
        KIND_PACKED_TYPED => {
            let decoded = decode_packed_value(payload, expected, epoch).map_err(codec_error)?;
            if decoded.consensus_byte_len != consensus_byte_len {
                return Err(VmInternalError::DBError(
                    "typed packed payload length mismatch".into(),
                )
                .into());
            }
            Ok(decoded.value)
        }
        _ => {
            Err(VmInternalError::DBError(format!("unknown typed value storage kind {kind}")).into())
        }
    }
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
                TypeSignature::CallableType(CallableSubtype::Principal(expected_contract)) => {
                    if contract_identifier != *expected_contract {
                        return Err(codec_error(error));
                    }
                    None
                }
                TypeSignature::CallableType(CallableSubtype::Trait(trait_identifier))
                | TypeSignature::TraitReferenceType(trait_identifier) => {
                    Some(Box::new(trait_identifier.clone()))
                }
                _ => unreachable!("guard restricts callable schema variants"),
            };
            Ok(Value::CallableContract(CallableData {
                contract_identifier,
                trait_identifier,
            }))
        }
        Err(error) => Err(codec_error(error)),
    }
}

fn codec_error(error: impl std::fmt::Display) -> VmExecutionError {
    VmInternalError::DBError(error.to_string()).into()
}

fn sql_error(error: rusqlite::Error) -> VmExecutionError {
    VmInternalError::DBError(error.to_string()).into()
}

#[cfg(test)]
mod tests {
    use clarity::vm::types::signatures::CallableSubtype;
    use clarity::vm::types::{
        CallableData, ListTypeData, PrincipalData, QualifiedContractIdentifier, SequenceSubtype,
    };
    use stacks_common::util::hash::to_hex;

    use super::*;

    const EPOCH: StacksEpochId = StacksEpochId::Epoch40;

    fn bool_list() -> (Value, TypeSignature) {
        let list_type = ListTypeData::new_list(TypeSignature::BoolType, 128).unwrap();
        let values = (0..128).map(|index| Value::Bool(index % 3 == 0)).collect();
        let value = Value::list_with_type(&EPOCH, values, list_type.clone()).unwrap();
        (
            value,
            TypeSignature::SequenceType(SequenceSubtype::ListType(list_type)),
        )
    }

    fn typed_data(value: Value, expected: TypeSignature) -> (String, TypedValueData) {
        let consensus = value.serialize_to_vec().unwrap();
        (
            to_hex(&consensus),
            TypedValueData {
                value,
                expected,
                epoch: EPOCH,
                consensus,
            },
        )
    }

    #[test]
    fn all_integrated_arms_round_trip_through_the_same_schema() {
        for (mode, expected_kind) in [
            (TypedValueStorageMode::IntegratedHex, KIND_HEX_UTF8),
            (TypedValueStorageMode::ConsensusBytes, KIND_CONSENSUS_BYTES),
            (TypedValueStorageMode::PackedTyped, KIND_PACKED_TYPED),
        ] {
            let conn = Connection::open_in_memory().unwrap();
            initialize(&conn, mode).unwrap();
            let (value, expected) = bool_list();
            let (canonical, typed) = typed_data(value.clone(), expected.clone());
            let value_hash = MARFValue::from_value(&canonical);

            put(&conn, mode, &value_hash, &canonical, typed).unwrap();
            let result = get(&conn, mode, &value_hash, &expected, &EPOCH)
                .unwrap()
                .unwrap();
            assert_eq!(result.value, value);
            assert_eq!(result.serialized_byte_len, canonical.len() as u64 / 2);

            let (kind, hash_type, hash_len): (i64, String, i64) = conn
                .query_row(
                    "SELECT storage_kind, typeof(value_hash), length(value_hash)
                     FROM clarity_typed_data",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            assert_eq!(kind, expected_kind);
            assert_eq!(hash_type, "blob");
            assert_eq!(hash_len, 40);
        }
    }

    #[test]
    fn repeated_rows_must_be_physically_identical() {
        let conn = Connection::open_in_memory().unwrap();
        initialize(&conn, TypedValueStorageMode::IntegratedHex).unwrap();
        let (value, expected) = bool_list();
        let (canonical, typed) = typed_data(value, expected);
        let value_hash = MARFValue::from_value(&canonical);

        put(
            &conn,
            TypedValueStorageMode::IntegratedHex,
            &value_hash,
            &canonical,
            typed.clone(),
        )
        .unwrap();
        put(
            &conn,
            TypedValueStorageMode::IntegratedHex,
            &value_hash,
            &canonical,
            typed.clone(),
        )
        .unwrap();
        assert!(put(
            &conn,
            TypedValueStorageMode::ConsensusBytes,
            &value_hash,
            &canonical,
            typed,
        )
        .is_err());
    }

    #[test]
    fn repeated_packed_rows_with_compatible_declared_bounds_share_one_row() {
        let conn = Connection::open_in_memory().unwrap();
        initialize(&conn, TypedValueStorageMode::PackedTyped).unwrap();
        let list_type = ListTypeData::new_list(TypeSignature::BoolType, 128).unwrap();
        let (value, _) = bool_list();
        let (canonical, first) = typed_data(
            value.clone(),
            TypeSignature::SequenceType(SequenceSubtype::ListType(list_type)),
        );
        let wider_type = ListTypeData::new_list(TypeSignature::BoolType, 256).unwrap();
        let (_, second) = typed_data(
            value,
            TypeSignature::SequenceType(SequenceSubtype::ListType(wider_type)),
        );
        let value_hash = MARFValue::from_value(&canonical);

        put(
            &conn,
            TypedValueStorageMode::PackedTyped,
            &value_hash,
            &canonical,
            first,
        )
        .unwrap();
        put(
            &conn,
            TypedValueStorageMode::PackedTyped,
            &value_hash,
            &canonical,
            second,
        )
        .unwrap();

        let (rows, kind): (u32, i64) = conn
            .query_row(
                "SELECT count(*), storage_kind FROM clarity_typed_data",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(rows, 1);
        assert_eq!(kind, KIND_PACKED_TYPED);
    }

    #[test]
    fn incompatible_schemas_monotonically_downgrade_one_hash_to_raw() {
        let conn = Connection::open_in_memory().unwrap();
        initialize(&conn, TypedValueStorageMode::PackedTyped).unwrap();
        let contract = QualifiedContractIdentifier::transient();
        let callable = Value::CallableContract(CallableData {
            contract_identifier: contract.clone(),
            trait_identifier: None,
        });
        let principal = Value::Principal(PrincipalData::Contract(contract.clone()));
        assert_eq!(
            callable.serialize_to_vec().unwrap(),
            principal.serialize_to_vec().unwrap()
        );
        let callable_type = TypeSignature::CallableType(CallableSubtype::Principal(contract));
        let (canonical, callable_data) = typed_data(callable, callable_type.clone());
        let (principal_canonical, principal_data) =
            typed_data(principal.clone(), TypeSignature::PrincipalType);
        assert_eq!(canonical, principal_canonical);
        let value_hash = MARFValue::from_value(&canonical);

        put(
            &conn,
            TypedValueStorageMode::PackedTyped,
            &value_hash,
            &canonical,
            callable_data,
        )
        .unwrap();
        put(
            &conn,
            TypedValueStorageMode::PackedTyped,
            &value_hash,
            &canonical,
            principal_data,
        )
        .unwrap();

        let (rows, kind): (u32, i64) = conn
            .query_row(
                "SELECT count(*), storage_kind FROM clarity_typed_data",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(rows, 1);
        assert_eq!(kind, KIND_CONSENSUS_BYTES);
        assert_eq!(
            get(
                &conn,
                TypedValueStorageMode::PackedTyped,
                &value_hash,
                &TypeSignature::PrincipalType,
                &EPOCH,
            )
            .unwrap()
            .unwrap()
            .value,
            principal
        );
        assert!(get(
            &conn,
            TypedValueStorageMode::PackedTyped,
            &value_hash,
            &callable_type,
            &EPOCH,
        )
        .is_ok());
    }
}
