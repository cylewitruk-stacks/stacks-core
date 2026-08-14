// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Bounded, restart-safe libp2p dial hints.
//!
//! This is deliberately not an authentication cache. An address is promoted
//! only after that exact outbound endpoint completes Noise and the
//! challenge-bound Stacks Hello. On restore it is merely a dial hint: every
//! connection must perform fresh Noise and Hello authentication, and role
//! authorization is always reconstructed from chainstate.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use stacks_network_types::limits::{
    HARD_MAX_PEER_STORE_STARTUP_DIALS, HARD_MAX_PEER_STORE_WRITE_QUEUE,
    HARD_MAX_PERSISTED_ADDRESSES_PER_PEER, HARD_MAX_PERSISTED_PEERS,
};
use stacks_network_types::NetworkScope;

const SCHEMA_VERSION: u32 = 1;
const MAX_PEER_ID_BYTES: usize = 64;
const MAX_MULTIADDR_BYTES: usize = 256;
const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS peer_store_meta(
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  schema_version INTEGER NOT NULL,
  chain_id INTEGER NOT NULL,
  network_id INTEGER NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS peers(
  peer_id BLOB PRIMARY KEY CHECK(length(peer_id) BETWEEN 1 AND 64),
  capabilities BLOB NOT NULL CHECK(length(capabilities) = 8),
  last_authenticated INTEGER NOT NULL CHECK(last_authenticated >= 0),
  successful_handshakes INTEGER NOT NULL CHECK(successful_handshakes >= 0),
  consecutive_failures INTEGER NOT NULL CHECK(consecutive_failures >= 0),
  last_failure INTEGER CHECK(last_failure IS NULL OR last_failure >= 0)
) STRICT;
CREATE TABLE IF NOT EXISTS peer_addresses(
  peer_id BLOB NOT NULL REFERENCES peers(peer_id) ON DELETE CASCADE,
  address BLOB NOT NULL CHECK(length(address) BETWEEN 1 AND 256),
  last_success INTEGER NOT NULL CHECK(last_success >= 0),
  successful_handshakes INTEGER NOT NULL CHECK(successful_handshakes >= 0),
  consecutive_failures INTEGER NOT NULL CHECK(consecutive_failures >= 0),
  last_failure INTEGER CHECK(last_failure IS NULL OR last_failure >= 0),
  PRIMARY KEY(peer_id, address)
) STRICT;
CREATE INDEX IF NOT EXISTS peer_addresses_restart_rank
  ON peer_addresses(consecutive_failures, last_success DESC);
"#;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerStorePolicy {
    pub max_peers: usize,
    pub max_addresses_per_peer: usize,
    pub entry_ttl_secs: u64,
    pub startup_dial_count: usize,
    pub write_queue_capacity: usize,
}

impl Default for PeerStorePolicy {
    fn default() -> Self {
        Self {
            max_peers: 2_048,
            max_addresses_per_peer: 4,
            entry_ttl_secs: 30 * 24 * 60 * 60,
            startup_dial_count: 16,
            write_queue_capacity: 256,
        }
    }
}

impl PeerStorePolicy {
    pub fn validate(&self) -> Result<(), PeerStoreError> {
        if self.max_peers == 0 || self.max_peers > HARD_MAX_PERSISTED_PEERS as usize {
            return Err(PeerStoreError::InvalidPolicy(format!(
                "max_peers must be within 1..={HARD_MAX_PERSISTED_PEERS}"
            )));
        }
        if self.max_addresses_per_peer == 0
            || self.max_addresses_per_peer > HARD_MAX_PERSISTED_ADDRESSES_PER_PEER as usize
        {
            return Err(PeerStoreError::InvalidPolicy(format!(
                "max_addresses_per_peer must be within 1..={HARD_MAX_PERSISTED_ADDRESSES_PER_PEER}"
            )));
        }
        if self.entry_ttl_secs == 0 {
            return Err(PeerStoreError::InvalidPolicy(
                "entry_ttl_secs must be nonzero".to_owned(),
            ));
        }
        if self.startup_dial_count > self.max_peers
            || self.startup_dial_count > HARD_MAX_PEER_STORE_STARTUP_DIALS as usize
        {
            return Err(PeerStoreError::InvalidPolicy(format!(
                "startup_dial_count must not exceed max_peers or {HARD_MAX_PEER_STORE_STARTUP_DIALS}"
            )));
        }
        if self.write_queue_capacity == 0
            || self.write_queue_capacity > HARD_MAX_PEER_STORE_WRITE_QUEUE as usize
        {
            return Err(PeerStoreError::InvalidPolicy(format!(
                "write_queue_capacity must be within 1..={HARD_MAX_PEER_STORE_WRITE_QUEUE}"
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct PeerStoreConfig {
    pub path: PathBuf,
    pub chain_id: u32,
    pub network_id: u32,
    pub local_peer_id: PeerId,
    pub policy: PeerStorePolicy,
}

impl PeerStoreConfig {
    pub const fn scope(&self) -> NetworkScope {
        NetworkScope::new(self.chain_id, self.network_id)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerStoreCandidate {
    pub peer_id: PeerId,
    /// Normalized transport address without a trailing `/p2p` component.
    pub address: Multiaddr,
    /// Historical capability bits are selection hints only. They are not
    /// installed into the application gate.
    pub historical_capabilities: u64,
    pub last_authenticated: u64,
    pub consecutive_failures: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PeerStoreRuntimeSnapshot {
    pub peers: u64,
    pub addresses: u64,
    pub restored: u64,
    pub writes: u64,
    pub write_failures: u64,
    pub queue_drops: u64,
    pub corruptions_recovered: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum PeerStoreError {
    #[error(transparent)]
    Sql(#[from] rusqlite::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("invalid peer-store policy: {0}")]
    InvalidPolicy(String),
    #[error("peer store belongs to chain/network {found_chain:#x}/{found_network:#x}, expected {expected_chain:#x}/{expected_network:#x}")]
    WrongNetwork {
        found_chain: u32,
        found_network: u32,
        expected_chain: u32,
        expected_network: u32,
    },
    #[error("unsupported peer-store schema {found}; this binary supports {supported}")]
    UnsupportedSchema { found: u32, supported: u32 },
    #[error("peer store contains invalid or out-of-range data")]
    Corruption,
    #[error("peer-store worker stopped during startup")]
    WorkerStopped,
}

/// Storage port used by the worker and directly by deterministic tests.
pub trait PeerStore {
    fn record_authenticated(
        &mut self,
        peer: PeerId,
        address: Multiaddr,
        capabilities: u64,
        observed_at: u64,
    ) -> Result<(), PeerStoreError>;

    fn record_failure(
        &mut self,
        peer: PeerId,
        address: Multiaddr,
        observed_at: u64,
    ) -> Result<(), PeerStoreError>;

    fn load_candidates(
        &mut self,
        now: u64,
        limit: usize,
    ) -> Result<Vec<PeerStoreCandidate>, PeerStoreError>;

    fn counts(&self) -> Result<(u64, u64), PeerStoreError>;
}

pub struct SqlitePeerStore {
    connection: Connection,
    local_peer_id: PeerId,
    policy: PeerStorePolicy,
}

impl SqlitePeerStore {
    pub fn open(config: &PeerStoreConfig) -> Result<Self, PeerStoreError> {
        config.policy.validate()?;
        if let Some(parent) = config.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let connection = Connection::open(&config.path)?;
        connection.busy_timeout(std::time::Duration::from_secs(2))?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;",
        )?;
        let integrity: String =
            connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
        if integrity != "ok" {
            return Err(PeerStoreError::Corruption);
        }
        connection.execute_batch(SCHEMA)?;
        Self::initialize_scope(&connection, config.chain_id, config.network_id)?;
        Ok(Self {
            connection,
            local_peer_id: config.local_peer_id,
            policy: config.policy.clone(),
        })
    }

    fn initialize_scope(
        connection: &Connection,
        chain_id: u32,
        network_id: u32,
    ) -> Result<(), PeerStoreError> {
        let existing = connection
            .query_row(
                "SELECT schema_version, chain_id, network_id FROM peer_store_meta WHERE singleton=1",
                [],
                |row| Ok((row.get::<_, u32>(0)?, row.get::<_, u32>(1)?, row.get::<_, u32>(2)?)),
            )
            .optional()?;
        match existing {
            Some((version, _, _)) if version != SCHEMA_VERSION => {
                Err(PeerStoreError::UnsupportedSchema {
                    found: version,
                    supported: SCHEMA_VERSION,
                })
            }
            Some((_, found_chain, found_network))
                if found_chain != chain_id || found_network != network_id =>
            {
                Err(PeerStoreError::WrongNetwork {
                    found_chain,
                    found_network,
                    expected_chain: chain_id,
                    expected_network: network_id,
                })
            }
            Some(_) => Ok(()),
            None => {
                connection.execute(
                    "INSERT INTO peer_store_meta(singleton,schema_version,chain_id,network_id) VALUES(1,?1,?2,?3)",
                    params![SCHEMA_VERSION, chain_id, network_id],
                )?;
                Ok(())
            }
        }
    }

    /// Open a disposable cache defensively. SQLite corruption is preserved
    /// under a `.corrupt-*` name and replaced; policy, schema, permission, and
    /// network-scope errors remain explicit and are never papered over.
    pub fn open_or_recover(
        config: &PeerStoreConfig,
    ) -> Result<(Self, Option<PathBuf>), PeerStoreError> {
        match Self::open(config) {
            Ok(store) => Ok((store, None)),
            Err(error) if is_recoverable_corruption(&error) && config.path.exists() => {
                let recovered = rotate_corrupt_database(&config.path)?;
                let store = Self::open(config)?;
                Ok((store, Some(recovered)))
            }
            Err(error) => Err(error),
        }
    }

    fn prune_and_bound(&mut self, now: u64) -> Result<(), PeerStoreError> {
        let cutoff = now.saturating_sub(self.policy.entry_ttl_secs);
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM peers WHERE last_authenticated < ?1",
            [to_sql_u64(cutoff)?],
        )?;
        enforce_peer_bound(&tx, self.policy.max_peers)?;
        tx.commit()?;
        Ok(())
    }
}

impl PeerStore for SqlitePeerStore {
    fn record_authenticated(
        &mut self,
        peer: PeerId,
        address: Multiaddr,
        capabilities: u64,
        observed_at: u64,
    ) -> Result<(), PeerStoreError> {
        if peer == self.local_peer_id {
            return Ok(());
        }
        let address = normalize_dial_address(peer, address)?;
        let peer_bytes = peer.to_bytes();
        if peer_bytes.len() > MAX_PEER_ID_BYTES {
            return Err(PeerStoreError::Corruption);
        }
        let address_bytes = address.to_vec();
        let observed_at_secs = observed_at;
        let observed_at = to_sql_u64(observed_at_secs)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO peers(peer_id,capabilities,last_authenticated,successful_handshakes,consecutive_failures,last_failure)
             VALUES(?1,?2,?3,1,0,NULL)
             ON CONFLICT(peer_id) DO UPDATE SET
               capabilities=excluded.capabilities,
               last_authenticated=MAX(peers.last_authenticated,excluded.last_authenticated),
               successful_handshakes=CASE
                 WHEN peers.successful_handshakes < 9223372036854775807
                 THEN peers.successful_handshakes + 1
                 ELSE peers.successful_handshakes END,
               consecutive_failures=0",
            params![peer_bytes, capabilities.to_be_bytes().as_slice(), observed_at],
        )?;
        tx.execute(
            "INSERT INTO peer_addresses(peer_id,address,last_success,successful_handshakes,consecutive_failures,last_failure)
             VALUES(?1,?2,?3,1,0,NULL)
             ON CONFLICT(peer_id,address) DO UPDATE SET
               last_success=MAX(peer_addresses.last_success,excluded.last_success),
               successful_handshakes=CASE
                 WHEN peer_addresses.successful_handshakes < 9223372036854775807
                 THEN peer_addresses.successful_handshakes + 1
                 ELSE peer_addresses.successful_handshakes END,
               consecutive_failures=0",
            params![peer.to_bytes(), address_bytes, observed_at],
        )?;
        enforce_address_bound(&tx, &peer, self.policy.max_addresses_per_peer)?;
        let cutoff = observed_at_secs.saturating_sub(self.policy.entry_ttl_secs);
        tx.execute(
            "DELETE FROM peers WHERE last_authenticated < ?1",
            [to_sql_u64(cutoff)?],
        )?;
        enforce_peer_bound(&tx, self.policy.max_peers)?;
        tx.commit()?;
        Ok(())
    }

    fn record_failure(
        &mut self,
        peer: PeerId,
        address: Multiaddr,
        observed_at: u64,
    ) -> Result<(), PeerStoreError> {
        let address = normalize_dial_address(peer, address)?;
        let observed_at = to_sql_u64(observed_at)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE peer_addresses SET
               consecutive_failures=MIN(consecutive_failures + 1,2147483647),
               last_failure=?3
             WHERE peer_id=?1 AND address=?2",
            params![peer.to_bytes(), address.to_vec(), observed_at],
        )?;
        if changed > 0 {
            tx.execute(
                "UPDATE peers SET
                   consecutive_failures=MIN(consecutive_failures + 1,2147483647),
                   last_failure=?2
                 WHERE peer_id=?1",
                params![peer.to_bytes(), observed_at],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    fn load_candidates(
        &mut self,
        now: u64,
        limit: usize,
    ) -> Result<Vec<PeerStoreCandidate>, PeerStoreError> {
        self.prune_and_bound(now)?;
        let limit = limit.min(self.policy.max_peers);
        if limit == 0 {
            return Ok(Vec::new());
        }
        let cutoff = now.saturating_sub(self.policy.entry_ttl_secs);
        let mut statement = self.connection.prepare(
            "WITH ranked_addresses AS (
               SELECT p.peer_id,a.address,p.capabilities,p.last_authenticated,
                      a.consecutive_failures,a.last_success,a.successful_handshakes,
                      ROW_NUMBER() OVER (
                        PARTITION BY p.peer_id
                        ORDER BY a.consecutive_failures ASC,a.last_success DESC,
                                 a.successful_handshakes DESC,a.address ASC
                      ) AS address_rank
               FROM peers p JOIN peer_addresses a ON a.peer_id=p.peer_id
               WHERE p.last_authenticated >= ?1
             )
             SELECT peer_id,address,capabilities,last_authenticated,consecutive_failures
             FROM ranked_addresses WHERE address_rank=1
             ORDER BY consecutive_failures ASC,last_success DESC,
                      successful_handshakes DESC,peer_id ASC,address ASC",
        )?;
        let mut rows = statement.query([to_sql_u64(cutoff)?])?;
        let mut ranked = Vec::with_capacity(limit);
        let mut selected = HashSet::with_capacity(limit);
        while let Some(row) = rows.next()? {
            let peer_bytes: Vec<u8> = row.get(0)?;
            let address_bytes: Vec<u8> = row.get(1)?;
            let capabilities: Vec<u8> = row.get(2)?;
            let last_authenticated: i64 = row.get(3)?;
            let consecutive_failures: i64 = row.get(4)?;
            let Ok(peer_id) = PeerId::from_bytes(&peer_bytes) else {
                continue;
            };
            if peer_id == self.local_peer_id || selected.contains(&peer_id) {
                continue;
            }
            let Ok(address) = Multiaddr::try_from(address_bytes) else {
                continue;
            };
            let Ok(address) = normalize_dial_address(peer_id, address) else {
                continue;
            };
            let Ok(capabilities) = <[u8; 8]>::try_from(capabilities.as_slice()) else {
                continue;
            };
            let Ok(last_authenticated) = u64::try_from(last_authenticated) else {
                continue;
            };
            let Ok(consecutive_failures) = u32::try_from(consecutive_failures) else {
                continue;
            };
            selected.insert(peer_id);
            ranked.push(PeerStoreCandidate {
                peer_id,
                address,
                historical_capabilities: u64::from_be_bytes(capabilities),
                last_authenticated,
                consecutive_failures,
            });
            if ranked.len() == self.policy.max_peers {
                break;
            }
        }
        let mut candidates = Vec::with_capacity(limit);
        let mut deferred = Vec::new();
        let mut failure_domains = HashSet::new();
        for candidate in ranked {
            if let Some(domain) = address_failure_domain(&candidate.address) {
                if !failure_domains.insert(domain) {
                    deferred.push(candidate);
                    continue;
                }
            }
            candidates.push(candidate);
            if candidates.len() == limit {
                return Ok(candidates);
            }
        }
        for candidate in deferred {
            candidates.push(candidate);
            if candidates.len() == limit {
                break;
            }
        }
        Ok(candidates)
    }

    fn counts(&self) -> Result<(u64, u64), PeerStoreError> {
        let peers = self
            .connection
            .query_row("SELECT COUNT(*) FROM peers", [], |row| row.get::<_, u64>(0))?;
        let addresses =
            self.connection
                .query_row("SELECT COUNT(*) FROM peer_addresses", [], |row| {
                    row.get::<_, u64>(0)
                })?;
        Ok((peers, addresses))
    }
}

fn enforce_address_bound(
    tx: &Transaction<'_>,
    peer: &PeerId,
    limit: usize,
) -> Result<(), PeerStoreError> {
    let count: u64 = tx.query_row(
        "SELECT COUNT(*) FROM peer_addresses WHERE peer_id=?1",
        [peer.to_bytes()],
        |row| row.get(0),
    )?;
    let excess = count.saturating_sub(limit as u64);
    if excess > 0 {
        tx.execute(
            "DELETE FROM peer_addresses WHERE rowid IN (
               SELECT rowid FROM peer_addresses WHERE peer_id=?1
               ORDER BY consecutive_failures DESC,last_success ASC,successful_handshakes ASC,address DESC
               LIMIT ?2
             )",
            params![peer.to_bytes(), to_sql_u64(excess)?],
        )?;
    }
    Ok(())
}

fn enforce_peer_bound(tx: &Transaction<'_>, limit: usize) -> Result<(), PeerStoreError> {
    let count: u64 = tx.query_row("SELECT COUNT(*) FROM peers", [], |row| row.get(0))?;
    let excess = count.saturating_sub(limit as u64);
    if excess > 0 {
        tx.execute(
            "DELETE FROM peers WHERE peer_id IN (
               SELECT peer_id FROM peers
               ORDER BY last_authenticated ASC,consecutive_failures DESC,successful_handshakes ASC,peer_id DESC
               LIMIT ?1
             )",
            [to_sql_u64(excess)?],
        )?;
    }
    Ok(())
}

pub(super) fn normalize_dial_address(
    expected_peer: PeerId,
    mut address: Multiaddr,
) -> Result<Multiaddr, PeerStoreError> {
    if address.to_vec().len() > MAX_MULTIADDR_BYTES {
        return Err(PeerStoreError::Corruption);
    }
    if let Some(Protocol::P2p(peer)) = address.iter().last() {
        if peer != expected_peer {
            return Err(PeerStoreError::Corruption);
        }
        address.pop();
    }
    if address.is_empty()
        || (!address.iter().any(|part| matches!(part, Protocol::Tcp(_)))
            && !address
                .iter()
                .any(|part| matches!(part, Protocol::Memory(_))))
        || address.iter().any(|part| matches!(part, Protocol::P2p(_)))
    {
        return Err(PeerStoreError::Corruption);
    }
    Ok(address)
}

/// Prefer one startup dial per directly observable failure domain before
/// filling remaining slots. This is deliberately a local approximation
/// (/24, /48, or exact DNS name), not a claim of ASN-level independence.
fn address_failure_domain(address: &Multiaddr) -> Option<Vec<u8>> {
    address.iter().find_map(|protocol| match protocol {
        Protocol::Ip4(ip) => {
            let octets = ip.octets();
            Some(vec![4, octets[0], octets[1], octets[2]])
        }
        Protocol::Ip6(ip) => {
            let octets = ip.octets();
            let mut domain = vec![6];
            domain.extend_from_slice(&octets[..6]);
            Some(domain)
        }
        Protocol::Dns(name)
        | Protocol::Dns4(name)
        | Protocol::Dns6(name)
        | Protocol::Dnsaddr(name) => {
            let mut domain = vec![0];
            domain.extend_from_slice(name.to_ascii_lowercase().as_bytes());
            Some(domain)
        }
        _ => None,
    })
}

fn to_sql_u64(value: u64) -> Result<i64, PeerStoreError> {
    i64::try_from(value).map_err(|_| PeerStoreError::Corruption)
}

fn is_recoverable_corruption(error: &PeerStoreError) -> bool {
    match error {
        PeerStoreError::Corruption => true,
        PeerStoreError::Sql(rusqlite::Error::SqliteFailure(code, _)) => matches!(
            code.code,
            rusqlite::ffi::ErrorCode::DatabaseCorrupt | rusqlite::ffi::ErrorCode::NotADatabase
        ),
        _ => false,
    }
}

fn rotate_corrupt_database(path: &Path) -> Result<PathBuf, std::io::Error> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("libp2p-peers.sqlite");
    let mut suffix = 0_u32;
    let recovered = loop {
        let suffix_text = if suffix == 0 {
            String::new()
        } else {
            format!("-{suffix}")
        };
        let candidate =
            path.with_file_name(format!("{file_name}.corrupt-{timestamp}{suffix_text}"));
        if !candidate.exists() {
            break candidate;
        }
        suffix = suffix.saturating_add(1);
    };
    fs::rename(path, &recovered)?;
    for sidecar_suffix in ["-wal", "-shm"] {
        let sidecar = PathBuf::from(format!("{}{sidecar_suffix}", path.display()));
        if sidecar.exists() {
            let recovered_sidecar =
                PathBuf::from(format!("{}{sidecar_suffix}", recovered.display()));
            let _ = fs::rename(sidecar, recovered_sidecar);
        }
    }
    Ok(recovered)
}

enum PeerStoreCommand {
    Authenticated {
        peer: PeerId,
        address: Multiaddr,
        capabilities: u64,
        observed_at: u64,
    },
    Failure {
        peer: PeerId,
        address: Multiaddr,
        observed_at: u64,
    },
}

#[derive(Default)]
struct PeerStoreRuntimeMetrics {
    peers: AtomicU64,
    addresses: AtomicU64,
    restored: AtomicU64,
    writes: AtomicU64,
    write_failures: AtomicU64,
    queue_drops: AtomicU64,
    corruptions_recovered: AtomicU64,
}

impl PeerStoreRuntimeMetrics {
    fn snapshot(&self) -> PeerStoreRuntimeSnapshot {
        PeerStoreRuntimeSnapshot {
            peers: self.peers.load(Ordering::Relaxed),
            addresses: self.addresses.load(Ordering::Relaxed),
            restored: self.restored.load(Ordering::Relaxed),
            writes: self.writes.load(Ordering::Relaxed),
            write_failures: self.write_failures.load(Ordering::Relaxed),
            queue_drops: self.queue_drops.load(Ordering::Relaxed),
            corruptions_recovered: self.corruptions_recovered.load(Ordering::Relaxed),
        }
    }
}

pub struct PeerStoreStartup {
    pub runtime: PeerStoreRuntime,
    pub candidates: Vec<PeerStoreCandidate>,
    pub recovered_corruption: Option<PathBuf>,
}

/// Nonblocking handle backed by one SQLite-owning worker thread. The swarm
/// never performs filesystem I/O and drops observations rather than blocking
/// when its bounded queue is saturated.
pub struct PeerStoreRuntime {
    sender: Option<mpsc::SyncSender<PeerStoreCommand>>,
    metrics: Arc<PeerStoreRuntimeMetrics>,
    worker: Option<JoinHandle<()>>,
}

impl PeerStoreRuntime {
    pub fn start(config: PeerStoreConfig, now: u64) -> Result<PeerStoreStartup, PeerStoreError> {
        config.policy.validate()?;
        let (sender, receiver) = mpsc::sync_channel(config.policy.write_queue_capacity);
        let (startup_sender, startup_receiver) = mpsc::sync_channel(1);
        let metrics = Arc::new(PeerStoreRuntimeMetrics::default());
        let worker_metrics = Arc::clone(&metrics);
        // Only materialize the bounded set that startup will actually dial.
        // Durable entries remain in SQLite for later restarts; they are not
        // injected into Kademlia or held in memory before fresh authentication.
        let candidate_limit = config.policy.startup_dial_count;
        let worker = thread::Builder::new()
            .name("libp2p-peer-store".to_owned())
            .spawn(move || {
                let (mut store, recovered) = match SqlitePeerStore::open_or_recover(&config) {
                    Ok(opened) => opened,
                    Err(error) => {
                        let _ = startup_sender.send(Err(error));
                        return;
                    }
                };
                let candidates = match store.load_candidates(now, candidate_limit) {
                    Ok(candidates) => candidates,
                    Err(error) => {
                        let _ = startup_sender.send(Err(error));
                        return;
                    }
                };
                if recovered.is_some() {
                    worker_metrics
                        .corruptions_recovered
                        .fetch_add(1, Ordering::Relaxed);
                }
                update_runtime_counts(&store, &worker_metrics);
                worker_metrics
                    .restored
                    .store(candidates.len() as u64, Ordering::Relaxed);
                if startup_sender.send(Ok((candidates, recovered))).is_err() {
                    return;
                }
                while let Ok(command) = receiver.recv() {
                    let result = match command {
                        PeerStoreCommand::Authenticated {
                            peer,
                            address,
                            capabilities,
                            observed_at,
                        } => store.record_authenticated(
                            peer,
                            address,
                            capabilities,
                            observed_at,
                        ),
                        PeerStoreCommand::Failure {
                            peer,
                            address,
                            observed_at,
                        } => store.record_failure(peer, address, observed_at),
                    };
                    match result {
                        Ok(()) => {
                            worker_metrics.writes.fetch_add(1, Ordering::Relaxed);
                            update_runtime_counts(&store, &worker_metrics);
                        }
                        Err(error) => {
                            worker_metrics
                                .write_failures
                                .fetch_add(1, Ordering::Relaxed);
                            tracing::warn!(target: "stacks_network", %error, "libp2p peer-store write failed");
                        }
                    }
                }
            })?;
        let (candidates, recovered_corruption) = startup_receiver
            .recv()
            .map_err(|_| PeerStoreError::WorkerStopped)??;
        Ok(PeerStoreStartup {
            runtime: PeerStoreRuntime {
                sender: Some(sender),
                metrics,
                worker: Some(worker),
            },
            candidates,
            recovered_corruption,
        })
    }

    pub fn record_authenticated(
        &self,
        peer: PeerId,
        address: Multiaddr,
        capabilities: u64,
        observed_at: u64,
    ) {
        self.try_send(PeerStoreCommand::Authenticated {
            peer,
            address,
            capabilities,
            observed_at,
        });
    }

    pub fn record_failure(&self, peer: PeerId, address: Multiaddr, observed_at: u64) {
        self.try_send(PeerStoreCommand::Failure {
            peer,
            address,
            observed_at,
        });
    }

    pub fn snapshot(&self) -> PeerStoreRuntimeSnapshot {
        self.metrics.snapshot()
    }

    fn try_send(&self, command: PeerStoreCommand) {
        let Some(sender) = self.sender.as_ref() else {
            return;
        };
        match sender.try_send(command) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => {
                self.metrics.queue_drops.fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                self.metrics.write_failures.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl Drop for PeerStoreRuntime {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn update_runtime_counts(store: &SqlitePeerStore, metrics: &PeerStoreRuntimeMetrics) {
    match store.counts() {
        Ok((peers, addresses)) => {
            metrics.peers.store(peers, Ordering::Relaxed);
            metrics.addresses.store(addresses, Ordering::Relaxed);
        }
        Err(error) => {
            metrics.write_failures.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(target: "stacks_network", %error, "libp2p peer-store count failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::TempDir;

    use super::*;

    fn config(temp: &TempDir, local_peer_id: PeerId, policy: PeerStorePolicy) -> PeerStoreConfig {
        PeerStoreConfig {
            path: temp.path().join("libp2p-peers.sqlite"),
            chain_id: 0x8000_0000,
            network_id: 0x8000_0000,
            local_peer_id,
            policy,
        }
    }

    fn address(port: u16) -> Multiaddr {
        format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap()
    }

    fn ip_address(ip: &str, port: u16) -> Multiaddr {
        format!("/ip4/{ip}/tcp/{port}").parse().unwrap()
    }

    #[test]
    fn restart_restores_only_exact_authenticated_endpoints() {
        let temp = TempDir::new().unwrap();
        let local = PeerId::random();
        let remote = PeerId::random();
        let config = config(&temp, local, PeerStorePolicy::default());
        {
            let mut store = SqlitePeerStore::open(&config).unwrap();
            store
                .record_authenticated(remote, address(20445), 0x55, 1_000)
                .unwrap();
            assert_eq!(store.counts().unwrap(), (1, 1));
        }
        let mut restarted = SqlitePeerStore::open(&config).unwrap();
        assert_eq!(
            restarted.load_candidates(1_001, 10).unwrap(),
            vec![PeerStoreCandidate {
                peer_id: remote,
                address: address(20445),
                historical_capabilities: 0x55,
                last_authenticated: 1_000,
                consecutive_failures: 0,
            }]
        );
    }

    #[test]
    fn runtime_materializes_only_the_bounded_startup_dial_set() {
        let temp = TempDir::new().unwrap();
        let local = PeerId::random();
        let policy = PeerStorePolicy {
            max_peers: 8,
            max_addresses_per_peer: 2,
            entry_ttl_secs: 600,
            startup_dial_count: 1,
            write_queue_capacity: 4,
        };
        let config = config(&temp, local, policy);
        {
            let mut store = SqlitePeerStore::open(&config).unwrap();
            for (offset, peer) in (0_u16..3).zip(std::iter::repeat_with(PeerId::random)) {
                store
                    .record_authenticated(
                        peer,
                        address(20_445 + offset),
                        0,
                        1_000 + u64::from(offset),
                    )
                    .unwrap();
            }
            assert_eq!(store.counts().unwrap(), (3, 3));
        }

        let startup = PeerStoreRuntime::start(config.clone(), 1_010).unwrap();
        assert_eq!(startup.candidates.len(), 1);
        assert_eq!(startup.runtime.snapshot().restored, 1);
        drop(startup.runtime);

        let store = SqlitePeerStore::open(&config).unwrap();
        assert_eq!(store.counts().unwrap(), (3, 3));
    }

    #[test]
    fn peer_address_and_ttl_bounds_are_enforced_deterministically() {
        let temp = TempDir::new().unwrap();
        let local = PeerId::random();
        let policy = PeerStorePolicy {
            max_peers: 2,
            max_addresses_per_peer: 2,
            entry_ttl_secs: 100,
            startup_dial_count: 2,
            write_queue_capacity: 4,
        };
        let config = config(&temp, local, policy);
        let peers = [PeerId::random(), PeerId::random(), PeerId::random()];
        let mut store = SqlitePeerStore::open(&config).unwrap();
        store
            .record_authenticated(peers[0], address(1), 1, 1_000)
            .unwrap();
        store
            .record_authenticated(peers[0], address(2), 1, 1_001)
            .unwrap();
        store
            .record_authenticated(peers[0], address(3), 1, 1_002)
            .unwrap();
        assert_eq!(store.counts().unwrap(), (1, 2));
        store
            .record_authenticated(peers[1], address(4), 1, 1_003)
            .unwrap();
        store
            .record_authenticated(peers[2], address(5), 1, 1_004)
            .unwrap();
        assert_eq!(store.counts().unwrap(), (2, 2));
        let candidates = store.load_candidates(1_004, 10).unwrap();
        assert_eq!(candidates.len(), 2);
        assert!(!candidates
            .iter()
            .any(|candidate| candidate.peer_id == peers[0]));
        assert!(store.load_candidates(1_200, 10).unwrap().is_empty());
        assert_eq!(store.counts().unwrap(), (0, 0));
    }

    #[test]
    fn failures_affect_restart_order_but_never_create_unverified_rows() {
        let temp = TempDir::new().unwrap();
        let local = PeerId::random();
        let first = PeerId::random();
        let second = PeerId::random();
        let config = config(&temp, local, PeerStorePolicy::default());
        let mut store = SqlitePeerStore::open(&config).unwrap();
        store.record_failure(first, address(10), 900).unwrap();
        assert_eq!(store.counts().unwrap(), (0, 0));
        store
            .record_authenticated(first, address(10), 1, 1_000)
            .unwrap();
        store
            .record_authenticated(second, address(11), 1, 999)
            .unwrap();
        store.record_failure(first, address(10), 1_001).unwrap();
        let candidates = store.load_candidates(1_002, 10).unwrap();
        assert_eq!(candidates[0].peer_id, second);
        assert_eq!(candidates[1].peer_id, first);
        assert_eq!(candidates[1].consecutive_failures, 1);
    }

    #[test]
    fn startup_selection_prefers_distinct_routable_prefixes() {
        let temp = TempDir::new().unwrap();
        let local = PeerId::random();
        let same_new = PeerId::random();
        let same_old = PeerId::random();
        let diverse = PeerId::random();
        let config = config(&temp, local, PeerStorePolicy::default());
        let mut store = SqlitePeerStore::open(&config).unwrap();
        store
            .record_authenticated(same_new, ip_address("10.1.2.1", 1), 1, 1_002)
            .unwrap();
        store
            .record_authenticated(same_old, ip_address("10.1.2.2", 2), 1, 1_001)
            .unwrap();
        store
            .record_authenticated(diverse, ip_address("11.1.2.1", 3), 1, 1_000)
            .unwrap();
        let selected = store.load_candidates(1_003, 2).unwrap();
        assert_eq!(selected[0].peer_id, same_new);
        assert_eq!(selected[1].peer_id, diverse);
    }

    #[test]
    fn wrong_network_and_unsupported_schema_fail_closed() {
        let temp = TempDir::new().unwrap();
        let local = PeerId::random();
        let config = config(&temp, local, PeerStorePolicy::default());
        drop(SqlitePeerStore::open(&config).unwrap());
        let mut wrong_network = config.clone();
        wrong_network.network_id = 1;
        assert!(matches!(
            SqlitePeerStore::open(&wrong_network),
            Err(PeerStoreError::WrongNetwork { .. })
        ));
        let connection = Connection::open(&config.path).unwrap();
        connection
            .execute("UPDATE peer_store_meta SET schema_version=99", [])
            .unwrap();
        drop(connection);
        assert!(matches!(
            SqlitePeerStore::open(&config),
            Err(PeerStoreError::UnsupportedSchema { found: 99, .. })
        ));
    }

    #[test]
    fn corrupt_cache_is_preserved_and_recreated() {
        let temp = TempDir::new().unwrap();
        let local = PeerId::random();
        let config = config(&temp, local, PeerStorePolicy::default());
        let mut file = fs::File::create(&config.path).unwrap();
        file.write_all(b"not sqlite").unwrap();
        drop(file);
        let (store, recovered) = SqlitePeerStore::open_or_recover(&config).unwrap();
        assert_eq!(store.counts().unwrap(), (0, 0));
        let recovered = recovered.expect("corrupt cache is preserved");
        assert_eq!(fs::read(recovered).unwrap(), b"not sqlite");
    }

    #[test]
    fn local_identity_and_mismatched_peer_suffix_are_rejected() {
        let temp = TempDir::new().unwrap();
        let local = PeerId::random();
        let remote = PeerId::random();
        let config = config(&temp, local, PeerStorePolicy::default());
        let mut store = SqlitePeerStore::open(&config).unwrap();
        store
            .record_authenticated(local, address(1), 1, 1_000)
            .unwrap();
        assert_eq!(store.counts().unwrap(), (0, 0));
        let wrong = address(2).with(Protocol::P2p(PeerId::random()));
        assert!(store.record_authenticated(remote, wrong, 1, 1_000).is_err());
        assert_eq!(store.counts().unwrap(), (0, 0));
    }
}
