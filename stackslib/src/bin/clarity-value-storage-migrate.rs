// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Build and verify production-shaped Clarity value-storage comparison databases.

use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use std::{env, fs};

use blockstack_lib::clarity_vm::database::track_c::{
    self, KIND_CANONICAL_HEX_BYTES, KIND_CANONICAL_PACKED, KIND_CANONICAL_UTF8,
};
use clarity::vm::types::storage::transcode_consensus_to_canonical_packed;
use rusqlite::functions::FunctionFlags;
use rusqlite::{Connection, OpenFlags};
use stacks_common::util::hash::hex_bytes;

const PROGRESS_ROWS: u64 = 1_000_000;
const SOURCE_SAMPLE_ROWS: usize = 10_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MigrationPolicy {
    Current,
    TrackA,
    TrackC,
}

impl MigrationPolicy {
    fn replacement_write_policy(self) -> Result<track_c::ReplacementWritePolicy, &'static str> {
        match self {
            Self::TrackA => Ok(track_c::ReplacementWritePolicy::ConsensusBytes),
            Self::TrackC => Ok(track_c::ReplacementWritePolicy::CanonicalPacked),
            Self::Current => Err("current policy has no replacement-table write policy"),
        }
    }
}

#[derive(Debug)]
struct Config {
    source: PathBuf,
    destination: PathBuf,
    policy: MigrationPolicy,
    vacuum: bool,
    full_integrity: bool,
    resume_expected_rows: Option<u64>,
}

#[derive(Default)]
struct MigrationStats {
    rows: AtomicU64,
    source_utf8_bytes: AtomicU64,
    payload_bytes: AtomicU64,
    canonical_utf8_rows: AtomicU64,
    canonical_hex_rows: AtomicU64,
    packed_rows: AtomicU64,
    packed_consensus_bytes: AtomicU64,
    packed_payload_bytes: AtomicU64,
    transcode_rejections: AtomicU64,
}

#[derive(Debug)]
struct MigrationStatsSnapshot {
    rows: u64,
    source_utf8_bytes: u64,
    payload_bytes: u64,
    canonical_utf8_rows: u64,
    canonical_hex_rows: u64,
    packed_rows: u64,
    packed_consensus_bytes: u64,
    packed_payload_bytes: u64,
    transcode_rejections: u64,
}

fn main() -> Result<(), Box<dyn Error>> {
    let config = parse_config()?;
    preflight(&config)?;

    println!("source={}", config.source.display());
    println!("destination={}", config.destination.display());
    println!("policy={:?}", config.policy);

    if let Some(expected_rows) = config.resume_expected_rows {
        return resume_finalization(&config, expected_rows);
    }

    let copy_started = Instant::now();
    let copied = fs::copy(&config.source, &config.destination)?;
    println!(
        "copied_bytes={copied} copy_seconds={:.3}",
        copy_started.elapsed().as_secs_f64()
    );

    let source = immutable_connection(&config.source)?;
    let destination = Connection::open(&config.destination)?;
    destination.busy_timeout(std::time::Duration::from_secs(300))?;
    destination.execute_batch(
        "PRAGMA journal_mode = DELETE;
         PRAGMA synchronous = NORMAL;
         PRAGMA secure_delete = OFF;
         PRAGMA temp_store = FILE;",
    )?;

    if config.policy == MigrationPolicy::Current {
        return finalize_current_destination(&config, source, destination);
    }

    let source_metadata_schema = metadata_schema(&source)?;
    let write_policy = config.policy.replacement_write_policy()?;
    track_c::initialize_bulk_migration_destination(&destination, write_policy)?;
    validate_source_samples(&destination)?;

    println!("phase=migrate_data_table");
    let migrate_started = Instant::now();
    let stats = migrate_rows(&destination, config.policy)?;
    println!(
        "migration_seconds={:.3} rows_per_second={:.1}",
        migrate_started.elapsed().as_secs_f64(),
        stats.rows as f64 / migrate_started.elapsed().as_secs_f64()
    );
    print_stats(&stats);

    println!("phase=build_value_hash_index");
    track_c::finalize_bulk_migration_destination(&destination, write_policy)?;
    finalize_destination(
        &config,
        destination,
        stats.rows,
        &source_metadata_schema,
        false,
    )
}

fn finalize_current_destination(
    config: &Config,
    source: Connection,
    destination: Connection,
) -> Result<(), Box<dyn Error>> {
    println!("phase=validate_current_copy");
    let expected_data_schema = data_schema(&source)?;
    let expected_metadata_schema = metadata_schema(&source)?;
    validate_current_destination(
        &destination,
        &expected_data_schema,
        &expected_metadata_schema,
    )?;
    drop(source);

    println!("phase=checkpoint");
    destination.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    if config.vacuum {
        println!("phase=vacuum");
        let started = Instant::now();
        destination.execute_batch("VACUUM;")?;
        println!("vacuum_seconds={:.3}", started.elapsed().as_secs_f64());
    }
    drop(destination);

    let reopened = Connection::open_with_flags(
        &config.destination,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    validate_current_destination(&reopened, &expected_data_schema, &expected_metadata_schema)?;
    validate_integrity(&reopened, config.full_integrity)?;
    println!(
        "complete destination_bytes={}",
        fs::metadata(&config.destination)?.len()
    );
    Ok(())
}

fn resume_finalization(config: &Config, expected_rows: u64) -> Result<(), Box<dyn Error>> {
    println!("phase=resume_finalization");
    let source = immutable_connection(&config.source)?;
    let destination = Connection::open(&config.destination)?;
    destination.busy_timeout(std::time::Duration::from_secs(300))?;
    destination.execute_batch(
        "PRAGMA journal_mode = DELETE;
         PRAGMA synchronous = NORMAL;
         PRAGMA secure_delete = OFF;
         PRAGMA temp_store = FILE;",
    )?;
    track_c::verify(&destination, config.policy.replacement_write_policy()?)?;
    finalize_destination(
        config,
        destination,
        expected_rows,
        &metadata_schema(&source)?,
        true,
    )
}

fn finalize_destination(
    config: &Config,
    destination: Connection,
    expected_rows: u64,
    source_metadata_schema: &[(String, String, String, Option<String>)],
    prevalidated: bool,
) -> Result<(), Box<dyn Error>> {
    let write_policy = config.policy.replacement_write_policy()?;
    if !prevalidated {
        validate_destination_structure(
            &destination,
            write_policy,
            expected_rows,
            source_metadata_schema,
        )?;
    }
    println!("phase=drop_legacy_data_table");
    let started = Instant::now();
    destination.execute("DROP TABLE legacy_data_table", [])?;
    println!("drop_seconds={:.3}", started.elapsed().as_secs_f64());
    println!("phase=analyze");
    destination.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); ANALYZE;")?;
    if config.vacuum {
        println!("phase=vacuum");
        let started = Instant::now();
        destination.execute_batch("VACUUM;")?;
        println!("vacuum_seconds={:.3}", started.elapsed().as_secs_f64());
    }
    destination.execute_batch("PRAGMA optimize;")?;
    drop(destination);

    let reopened = Connection::open_with_flags(
        &config.destination,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    track_c::verify(&reopened, write_policy)?;
    validate_destination_structure(
        &reopened,
        write_policy,
        expected_rows,
        source_metadata_schema,
    )?;
    validate_integrity(&reopened, config.full_integrity)?;
    println!(
        "complete destination_bytes={}",
        fs::metadata(&config.destination)?.len()
    );
    Ok(())
}

fn parse_config() -> Result<Config, Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let mut source = None;
    let mut destination = None;
    let mut policy = MigrationPolicy::TrackC;
    let mut vacuum = true;
    let mut full_integrity = false;
    let mut resume_expected_rows = None;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--source" => source = args.next().map(PathBuf::from),
            "--destination" => destination = args.next().map(PathBuf::from),
            "--policy" => {
                policy = match args.next().as_deref() {
                    Some("current") => MigrationPolicy::Current,
                    Some("track-a") | Some("canonical") => MigrationPolicy::TrackA,
                    Some("track-c") | Some("optimistic") => MigrationPolicy::TrackC,
                    Some(value) => return Err(format!("invalid migration policy '{value}'").into()),
                    None => return Err("--policy requires current, track-a, or track-c".into()),
                };
            }
            "--no-vacuum" => vacuum = false,
            "--full-integrity" => full_integrity = true,
            "--resume-finalization" => {
                resume_expected_rows = Some(
                    args.next()
                        .ok_or("--resume-finalization requires an expected row count")?
                        .parse()?,
                );
            }
            "--help" | "-h" => {
                println!(
                    "usage: clarity-value-storage-migrate --source PATH --destination PATH \
                     [--policy current|track-a|track-c] [--no-vacuum] [--full-integrity] \
                     [--resume-finalization EXPECTED_ROWS]"
                );
                std::process::exit(0);
            }
            value => return Err(format!("unknown argument '{value}'").into()),
        }
    }
    Ok(Config {
        source: source.ok_or("--source is required")?,
        destination: destination.ok_or("--destination is required")?,
        policy,
        vacuum,
        full_integrity,
        resume_expected_rows,
    })
}

fn preflight(config: &Config) -> Result<(), Box<dyn Error>> {
    if !config.source.is_file() {
        return Err(format!("source does not exist: {}", config.source.display()).into());
    }
    if config.resume_expected_rows.is_some() && !config.destination.is_file() {
        return Err(format!(
            "resume destination does not exist: {}",
            config.destination.display()
        )
        .into());
    }
    if config.resume_expected_rows.is_none() && config.destination.exists() {
        return Err(format!(
            "destination already exists; refusing to overwrite: {}",
            config.destination.display()
        )
        .into());
    }
    if config.source == config.destination {
        return Err("source and destination must differ".into());
    }
    if config.policy == MigrationPolicy::Current && config.resume_expected_rows.is_some() {
        return Err("current policy does not support --resume-finalization".into());
    }
    let wal_path = PathBuf::from(format!("{}-wal", config.source.display()));
    if wal_path.exists() && fs::metadata(&wal_path)?.len() != 0 {
        return Err(format!(
            "source WAL is non-empty ({}); checkpoint or stop the writer before migration",
            wal_path.display()
        )
        .into());
    }
    Ok(())
}

fn validate_current_destination(
    destination: &Connection,
    expected_data_schema: &[(String, String, String, Option<String>)],
    expected_metadata_schema: &[(String, String, String, Option<String>)],
) -> Result<(), Box<dyn Error>> {
    track_c::reject_if_present(destination)?;
    if data_schema(destination)? != expected_data_schema {
        return Err("current-control data_table schema or indexes changed".into());
    }
    if metadata_schema(destination)? != expected_metadata_schema {
        return Err("current-control metadata_table schema or indexes changed".into());
    }
    Ok(())
}

fn immutable_connection(path: &Path) -> Result<Connection, rusqlite::Error> {
    let uri = format!("file:{}?mode=ro&immutable=1", path.display());
    Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
}

fn migrate_rows(
    destination: &Connection,
    policy: MigrationPolicy,
) -> Result<MigrationStatsSnapshot, Box<dyn Error>> {
    let unhex_probe: Vec<u8> =
        destination.query_row("SELECT unhex('00ff')", [], |row| row.get(0))?;
    if unhex_probe != [0, 255] {
        return Err("SQLite unhex() failed its startup check".into());
    }

    let stats = Arc::new(MigrationStats::default());
    let function_stats = Arc::clone(&stats);
    destination.create_scalar_function(
        "track_c_record",
        1,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        move |context| {
            let value = context
                .get_raw(0)
                .as_str()
                .map_err(|error| rusqlite::Error::UserFunctionError(Box::new(error)))?;
            classify_record(value, policy, &function_stats)
                .map_err(rusqlite::Error::UserFunctionError)
        },
    )?;

    let inserted = destination.execute(
        "INSERT INTO data_table(value_hash, record)
         SELECT unhex(key), track_c_record(value)
         FROM legacy_data_table",
        [],
    )?;
    let snapshot = stats.snapshot();
    if inserted as u64 != snapshot.rows {
        return Err(format!(
            "bulk migration row mismatch: classified={}, inserted={inserted}",
            snapshot.rows
        )
        .into());
    }
    destination.remove_function("track_c_record", 1)?;
    Ok(snapshot)
}

fn classify_record(
    value: &str,
    policy: MigrationPolicy,
    stats: &MigrationStats,
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let row = stats.rows.fetch_add(1, Ordering::Relaxed) + 1;
    if row % PROGRESS_ROWS == 0 {
        println!("migrated_rows={row}");
    }
    stats
        .source_utf8_bytes
        .fetch_add(value.len() as u64, Ordering::Relaxed);
    let consensus = exact_lower_hex(value);
    let (payload_kind, payload) = match (policy, consensus) {
        (MigrationPolicy::TrackC, Some(consensus)) => {
            match transcode_consensus_to_canonical_packed(&consensus) {
                Ok(packed) => {
                    let payload = packed.into_bytes();
                    let stored_len = u32::from_le_bytes(
                        payload
                            .get(..4)
                            .ok_or("packed migration row lacks header")?
                            .try_into()?,
                    );
                    if stored_len as usize != consensus.len() {
                        return Err("packed migration row logical length mismatch".into());
                    }
                    stats.packed_rows.fetch_add(1, Ordering::Relaxed);
                    stats
                        .packed_consensus_bytes
                        .fetch_add(consensus.len() as u64, Ordering::Relaxed);
                    stats
                        .packed_payload_bytes
                        .fetch_add(payload.len() as u64, Ordering::Relaxed);
                    (KIND_CANONICAL_PACKED, payload)
                }
                Err(_) => {
                    stats.transcode_rejections.fetch_add(1, Ordering::Relaxed);
                    stats.canonical_hex_rows.fetch_add(1, Ordering::Relaxed);
                    (KIND_CANONICAL_HEX_BYTES, consensus)
                }
            }
        }
        (MigrationPolicy::TrackA, Some(consensus)) => {
            stats.canonical_hex_rows.fetch_add(1, Ordering::Relaxed);
            (KIND_CANONICAL_HEX_BYTES, consensus)
        }
        (MigrationPolicy::TrackA | MigrationPolicy::TrackC, None) => {
            stats.canonical_utf8_rows.fetch_add(1, Ordering::Relaxed);
            (KIND_CANONICAL_UTF8, value.as_bytes().to_vec())
        }
        (MigrationPolicy::Current, _) => {
            return Err("current policy does not transform data_table rows".into());
        }
    };
    stats
        .payload_bytes
        .fetch_add(payload.len() as u64, Ordering::Relaxed);
    let mut record = Vec::with_capacity(payload.len() + 1);
    record.push(u8::try_from(payload_kind)?);
    record.extend_from_slice(&payload);
    Ok(record)
}

fn validate_destination_structure(
    destination: &Connection,
    write_policy: track_c::ReplacementWritePolicy,
    source_rows: u64,
    source_metadata_schema: &[(String, String, String, Option<String>)],
) -> Result<(), Box<dyn Error>> {
    track_c::verify(destination, write_policy)?;
    let destination_rows: u64 =
        destination.query_row("SELECT COUNT(*) FROM data_table", [], |row| row.get(0))?;
    if source_rows != destination_rows {
        return Err(format!(
            "row count mismatch: source={source_rows}, destination={destination_rows}"
        )
        .into());
    }
    let malformed_rows: u64 = destination.query_row(
        "SELECT COUNT(*) FROM data_table
         WHERE typeof(value_hash) != 'blob' OR length(value_hash) != 40
            OR typeof(record) != 'blob' OR length(record) < 1
            OR hex(substr(record, 1, 1)) NOT IN ('00', '01', '02')",
        [],
        |row| row.get(0),
    )?;
    if malformed_rows != 0 {
        return Err(format!("destination has {malformed_rows} malformed rows").into());
    }
    if source_metadata_schema != metadata_schema(destination)? {
        return Err("metadata_table schema or indexes changed during migration".into());
    }
    Ok(())
}

fn validate_integrity(destination: &Connection, full: bool) -> Result<(), Box<dyn Error>> {
    let pragma = if full {
        "PRAGMA integrity_check"
    } else {
        "PRAGMA quick_check"
    };
    println!(
        "phase={}",
        if full {
            "integrity_check"
        } else {
            "quick_check"
        }
    );
    let integrity: String = destination.query_row(pragma, [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(format!("SQLite {pragma} failed: {integrity}").into());
    }
    Ok(())
}

fn validate_source_samples(connection: &Connection) -> Result<(), Box<dyn Error>> {
    for ordering in ["ASC", "DESC"] {
        let sql = format!(
            "SELECT key, value FROM legacy_data_table ORDER BY rowid {ordering} LIMIT {SOURCE_SAMPLE_ROWS}"
        );
        let mut statement = connection.prepare(&sql)?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let key: &str = row.get_ref(0)?.as_str()?;
            let value: &str = row.get_ref(1)?.as_str()?;
            let decoded = exact_lower_hex(key).ok_or("legacy key is not lowercase hexadecimal")?;
            if decoded.len() != 40
                || blockstack_lib::chainstate::stacks::index::MARFValue::from_value(value)
                    .as_bytes()
                    != decoded.as_slice()
            {
                return Err("sampled legacy key does not hash its canonical value".into());
            }
        }
    }
    Ok(())
}

fn metadata_schema(
    connection: &Connection,
) -> Result<Vec<(String, String, String, Option<String>)>, rusqlite::Error> {
    let mut statement = connection.prepare(
        "SELECT type, name, tbl_name, sql FROM sqlite_master
         WHERE tbl_name = 'metadata_table' OR name = 'md_blockhashes'
         ORDER BY type, name",
    )?;
    let schema: Vec<(String, String, String, Option<String>)> = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(schema)
}

fn data_schema(
    connection: &Connection,
) -> Result<Vec<(String, String, String, Option<String>)>, rusqlite::Error> {
    let mut statement = connection.prepare(
        "SELECT type, name, tbl_name, sql FROM sqlite_master
         WHERE tbl_name = 'data_table'
         ORDER BY type, name",
    )?;
    let schema: Vec<(String, String, String, Option<String>)> = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(schema)
}

fn exact_lower_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    hex_bytes(value).ok()
}

fn print_stats(stats: &MigrationStatsSnapshot) {
    let payload_ratio = stats.payload_bytes as f64 / stats.source_utf8_bytes as f64;
    let packed_ratio = stats.packed_payload_bytes as f64 / stats.packed_consensus_bytes as f64;
    println!("rows={}", stats.rows);
    println!("canonical_utf8_rows={}", stats.canonical_utf8_rows);
    println!("canonical_hex_rows={}", stats.canonical_hex_rows);
    println!("packed_rows={}", stats.packed_rows);
    println!("transcode_rejections={}", stats.transcode_rejections);
    println!("source_key_bytes={}", stats.rows * 80);
    println!("source_value_bytes={}", stats.source_utf8_bytes);
    println!("destination_payload_bytes={}", stats.payload_bytes);
    println!("packed_consensus_bytes={}", stats.packed_consensus_bytes);
    println!("packed_payload_bytes={}", stats.packed_payload_bytes);
    println!("payload/source_value_ratio={payload_ratio:.6}");
    if stats.packed_consensus_bytes != 0 {
        println!("packed/consensus_ratio={packed_ratio:.6}");
    }
}

impl MigrationStats {
    fn snapshot(&self) -> MigrationStatsSnapshot {
        MigrationStatsSnapshot {
            rows: self.rows.load(Ordering::Relaxed),
            source_utf8_bytes: self.source_utf8_bytes.load(Ordering::Relaxed),
            payload_bytes: self.payload_bytes.load(Ordering::Relaxed),
            canonical_utf8_rows: self.canonical_utf8_rows.load(Ordering::Relaxed),
            canonical_hex_rows: self.canonical_hex_rows.load(Ordering::Relaxed),
            packed_rows: self.packed_rows.load(Ordering::Relaxed),
            packed_consensus_bytes: self.packed_consensus_bytes.load(Ordering::Relaxed),
            packed_payload_bytes: self.packed_payload_bytes.load(Ordering::Relaxed),
            transcode_rejections: self.transcode_rejections.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use clarity::vm::types::Value;
    use stacks_common::util::hash::to_hex;
    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn track_c_policy_packs_exact_values_and_preserves_generic_rows() {
        let value = Value::UInt(42);
        let canonical = to_hex(&value.serialize_to_vec().unwrap());
        let stats = MigrationStats::default();
        let migrated = classify_record(&canonical, MigrationPolicy::TrackC, &stats).unwrap();
        assert_eq!(i64::from(migrated[0]), KIND_CANONICAL_PACKED);
        assert_eq!(stats.packed_rows.load(Ordering::Relaxed), 1);

        let generic = "a generic string";
        let migrated = classify_record(generic, MigrationPolicy::TrackC, &stats).unwrap();
        assert_eq!(i64::from(migrated[0]), KIND_CANONICAL_UTF8);
        assert_eq!(&migrated[1..], generic.as_bytes());
    }

    #[test]
    fn track_a_policy_never_creates_packed_rows() {
        let value = Value::Bool(true);
        let canonical = to_hex(&value.serialize_to_vec().unwrap());
        let stats = MigrationStats::default();
        let migrated = classify_record(&canonical, MigrationPolicy::TrackA, &stats).unwrap();
        assert_eq!(i64::from(migrated[0]), KIND_CANONICAL_HEX_BYTES);
        assert_eq!(&migrated[1..], value.serialize_to_vec().unwrap());
    }

    #[test]
    fn bulk_pipeline_replaces_the_legacy_table() {
        let file = NamedTempFile::new().unwrap();
        let connection = Connection::open(file.path()).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE data_table (key TEXT PRIMARY KEY, value TEXT);
                 CREATE TABLE metadata_table (key TEXT, blockhash TEXT, value TEXT);
                 CREATE INDEX md_blockhashes ON metadata_table(blockhash);",
            )
            .unwrap();
        for value in [
            to_hex(&Value::UInt(42).serialize_to_vec().unwrap()),
            "plain canonical text".to_owned(),
        ] {
            let hash = blockstack_lib::chainstate::stacks::index::MARFValue::from_value(&value);
            connection
                .execute(
                    "INSERT INTO data_table(key, value) VALUES (?1, ?2)",
                    rusqlite::params![hash.to_hex(), value],
                )
                .unwrap();
        }

        let write_policy = track_c::ReplacementWritePolicy::CanonicalPacked;
        track_c::initialize_bulk_migration_destination(&connection, write_policy).unwrap();
        validate_source_samples(&connection).unwrap();
        let stats = migrate_rows(&connection, MigrationPolicy::TrackC).unwrap();
        assert_eq!(stats.rows, 2);
        assert_eq!(stats.packed_rows, 1);
        track_c::finalize_bulk_migration_destination(&connection, write_policy).unwrap();
        validate_destination_structure(
            &connection,
            write_policy,
            2,
            &metadata_schema(&connection).unwrap(),
        )
        .unwrap();
        validate_integrity(&connection, true).unwrap();
        connection
            .execute("DROP TABLE legacy_data_table", [])
            .unwrap();
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM data_table", [], |row| row
                    .get::<_, u64>(0))
                .unwrap(),
            2
        );
    }

    #[test]
    fn current_policy_vacuums_without_changing_the_legacy_schema() {
        let directory = tempfile::tempdir().unwrap();
        let source_path = directory.path().join("source.sqlite");
        let destination_path = directory.path().join("current.sqlite");
        let source = Connection::open(&source_path).unwrap();
        source
            .execute_batch(
                "CREATE TABLE data_table (key TEXT PRIMARY KEY, value TEXT);
                 CREATE TABLE metadata_table (key TEXT, blockhash TEXT, value TEXT);
                 CREATE INDEX md_blockhashes ON metadata_table(blockhash);
                 INSERT INTO data_table VALUES ('key', 'value');
                 INSERT INTO metadata_table VALUES ('key', 'block', 'value');",
            )
            .unwrap();
        drop(source);
        fs::copy(&source_path, &destination_path).unwrap();

        let config = Config {
            source: source_path.clone(),
            destination: destination_path.clone(),
            policy: MigrationPolicy::Current,
            vacuum: true,
            full_integrity: false,
            resume_expected_rows: None,
        };
        finalize_current_destination(
            &config,
            immutable_connection(&source_path).unwrap(),
            Connection::open(&destination_path).unwrap(),
        )
        .unwrap();

        let reopened = Connection::open(&destination_path).unwrap();
        assert_eq!(
            data_schema(&reopened).unwrap(),
            data_schema(&immutable_connection(&source_path).unwrap()).unwrap()
        );
        assert_eq!(
            reopened
                .query_row(
                    "SELECT value FROM data_table WHERE key = 'key'",
                    [],
                    |row| { row.get::<_, String>(0) }
                )
                .unwrap(),
            "value"
        );
    }
}
