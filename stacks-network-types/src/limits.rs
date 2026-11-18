//! Shared, validated resource limits for node and signer swarms.

use serde::Deserialize;

pub const HARD_MAX_PERSISTED_PEERS: u32 = 100_000;
pub const HARD_MAX_PERSISTED_ADDRESSES_PER_PEER: u32 = 16;
pub const HARD_MAX_PEER_STORE_STARTUP_DIALS: u32 = 256;
pub const HARD_MAX_PEER_STORE_WRITE_QUEUE: u32 = 4_096;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Libp2pLimits {
    pub max_pending_incoming: u32,
    pub max_pending_outgoing: u32,
    pub max_established_incoming: u32,
    pub max_established_outgoing: u32,
    pub max_established_total: u32,
    pub max_connections_per_peer: u32,
    pub max_connections_per_ip: u32,
    /// Maximum simultaneous connections from one IPv4 /24 or IPv6 /48.
    /// This bounds cheap address fan-out attacks without requiring an ASN DB.
    pub max_connections_per_prefix: u32,
    pub max_inflight_requests_per_peer: u32,
    pub max_inflight_block_pushes: u32,
    pub max_concurrent_streams: u32,
    pub max_process_memory_bytes: u64,
    pub object_cache_bytes: u64,
    pub inbound_bytes_per_second: u64,
    pub inbound_byte_burst: u64,
    pub validation_units_per_second: u64,
    pub validation_unit_burst: u64,
    pub small_transaction_bytes: u64,
    pub request_timeout_secs: u64,
    /// Maximum authenticated libp2p peers retained as restart dial hints.
    pub max_persisted_peers: u32,
    /// Maximum successfully dialed endpoints retained for one PeerId.
    pub max_persisted_addresses_per_peer: u32,
    /// Expire restart hints this many seconds after their last successful
    /// Noise + Stacks Hello handshake.
    pub peer_store_ttl_secs: u64,
    /// Maximum restored peers proactively dialed at startup. Restored
    /// addresses are untrusted dial hints and do not enter Kademlia until the
    /// peer freshly authenticates and advertises a tracked, revocable address
    /// in this process lifetime.
    pub peer_store_startup_dials: u32,
    /// Bounded nonblocking swarm-to-SQLite observation queue.
    pub peer_store_write_queue: u32,
}

impl Default for Libp2pLimits {
    fn default() -> Self {
        Self {
            max_pending_incoming: 64,
            max_pending_outgoing: 32,
            max_established_incoming: 256,
            max_established_outgoing: 44,
            max_established_total: 300,
            // Yamux needs only one steady-state connection, but admitting two
            // lets simultaneous inbound/outbound dials converge instead of
            // both peers rejecting the other's connection. Application state
            // remains keyed by PeerId rather than connection ID.
            max_connections_per_peer: 2,
            max_connections_per_ip: 8,
            max_connections_per_prefix: 32,
            max_inflight_requests_per_peer: 8,
            max_inflight_block_pushes: 12,
            max_concurrent_streams: 100,
            max_process_memory_bytes: 1024 * 1024 * 1024,
            object_cache_bytes: 64 * 1024 * 1024,
            inbound_bytes_per_second: 4 * 1024 * 1024,
            // One incumbent-maximum authenticated signer payload plus
            // framing, while the sustained rate remains much lower.
            inbound_byte_burst: 20 * 1024 * 1024,
            validation_units_per_second: 100,
            validation_unit_burst: 400,
            small_transaction_bytes: 64 * 1024,
            request_timeout_secs: 10,
            max_persisted_peers: 2_048,
            max_persisted_addresses_per_peer: 4,
            peer_store_ttl_secs: 30 * 24 * 60 * 60,
            peer_store_startup_dials: 16,
            peer_store_write_queue: 256,
        }
    }
}

impl Libp2pLimits {
    pub fn validate(&self) -> Result<(), Libp2pLimitsError> {
        let nonzero = [
            ("max_pending_incoming", u64::from(self.max_pending_incoming)),
            ("max_pending_outgoing", u64::from(self.max_pending_outgoing)),
            (
                "max_established_incoming",
                u64::from(self.max_established_incoming),
            ),
            (
                "max_established_outgoing",
                u64::from(self.max_established_outgoing),
            ),
            (
                "max_established_total",
                u64::from(self.max_established_total),
            ),
            (
                "max_connections_per_peer",
                u64::from(self.max_connections_per_peer),
            ),
            (
                "max_connections_per_ip",
                u64::from(self.max_connections_per_ip),
            ),
            (
                "max_connections_per_prefix",
                u64::from(self.max_connections_per_prefix),
            ),
            (
                "max_inflight_requests_per_peer",
                u64::from(self.max_inflight_requests_per_peer),
            ),
            (
                "max_inflight_block_pushes",
                u64::from(self.max_inflight_block_pushes),
            ),
            (
                "max_concurrent_streams",
                u64::from(self.max_concurrent_streams),
            ),
            ("max_process_memory_bytes", self.max_process_memory_bytes),
            ("object_cache_bytes", self.object_cache_bytes),
            ("inbound_bytes_per_second", self.inbound_bytes_per_second),
            ("inbound_byte_burst", self.inbound_byte_burst),
            (
                "validation_units_per_second",
                self.validation_units_per_second,
            ),
            ("validation_unit_burst", self.validation_unit_burst),
            ("small_transaction_bytes", self.small_transaction_bytes),
            ("request_timeout_secs", self.request_timeout_secs),
            ("max_persisted_peers", u64::from(self.max_persisted_peers)),
            (
                "max_persisted_addresses_per_peer",
                u64::from(self.max_persisted_addresses_per_peer),
            ),
            ("peer_store_ttl_secs", self.peer_store_ttl_secs),
            (
                "peer_store_write_queue",
                u64::from(self.peer_store_write_queue),
            ),
        ];
        if let Some((field, _)) = nonzero.into_iter().find(|(_, value)| *value == 0) {
            return Err(Libp2pLimitsError::Zero(field));
        }
        if self.max_connections_per_peer > self.max_established_total {
            return Err(Libp2pLimitsError::Inconsistent(
                "max_connections_per_peer exceeds max_established_total",
            ));
        }
        if self.max_connections_per_ip > self.max_established_total {
            return Err(Libp2pLimitsError::Inconsistent(
                "max_connections_per_ip exceeds max_established_total",
            ));
        }
        if self.max_connections_per_prefix > self.max_established_total {
            return Err(Libp2pLimitsError::Inconsistent(
                "max_connections_per_prefix exceeds max_established_total",
            ));
        }
        if self.max_connections_per_prefix < self.max_connections_per_ip {
            return Err(Libp2pLimitsError::Inconsistent(
                "max_connections_per_prefix is smaller than max_connections_per_ip",
            ));
        }
        if self.object_cache_bytes > self.max_process_memory_bytes {
            return Err(Libp2pLimitsError::Inconsistent(
                "object_cache_bytes exceeds max_process_memory_bytes",
            ));
        }
        if self.inbound_byte_burst < self.inbound_bytes_per_second {
            return Err(Libp2pLimitsError::Inconsistent(
                "inbound_byte_burst is smaller than inbound_bytes_per_second",
            ));
        }
        if self.validation_unit_burst < self.validation_units_per_second {
            return Err(Libp2pLimitsError::Inconsistent(
                "validation_unit_burst is smaller than validation_units_per_second",
            ));
        }
        if self.max_persisted_peers > HARD_MAX_PERSISTED_PEERS {
            return Err(Libp2pLimitsError::Inconsistent(
                "max_persisted_peers exceeds its hard safety bound",
            ));
        }
        if self.max_persisted_addresses_per_peer > HARD_MAX_PERSISTED_ADDRESSES_PER_PEER {
            return Err(Libp2pLimitsError::Inconsistent(
                "max_persisted_addresses_per_peer exceeds its hard safety bound",
            ));
        }
        if self.peer_store_startup_dials > self.max_persisted_peers
            || self.peer_store_startup_dials > HARD_MAX_PEER_STORE_STARTUP_DIALS
        {
            return Err(Libp2pLimitsError::Inconsistent(
                "peer_store_startup_dials exceeds max_persisted_peers or its hard safety bound",
            ));
        }
        if self.peer_store_write_queue > HARD_MAX_PEER_STORE_WRITE_QUEUE {
            return Err(Libp2pLimitsError::Inconsistent(
                "peer_store_write_queue exceeds its hard safety bound",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum Libp2pLimitsError {
    #[error("libp2p limit {0} must be nonzero")]
    Zero(&'static str),
    #[error("inconsistent libp2p limits: {0}")]
    Inconsistent(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid_and_fail_closed() {
        Libp2pLimits::default().validate().unwrap();
        let invalid = Libp2pLimits {
            max_inflight_requests_per_peer: 0,
            ..Libp2pLimits::default()
        };
        assert_eq!(
            invalid.validate(),
            Err(Libp2pLimitsError::Zero("max_inflight_requests_per_peer"))
        );
        let defaults = Libp2pLimits::default();
        let invalid = Libp2pLimits {
            object_cache_bytes: defaults.max_process_memory_bytes + 1,
            ..defaults
        };
        assert!(matches!(
            invalid.validate(),
            Err(Libp2pLimitsError::Inconsistent(_))
        ));
        let invalid = Libp2pLimits {
            max_persisted_peers: HARD_MAX_PERSISTED_PEERS + 1,
            ..Libp2pLimits::default()
        };
        assert_eq!(
            invalid.validate(),
            Err(Libp2pLimitsError::Inconsistent(
                "max_persisted_peers exceeds its hard safety bound"
            ))
        );
        let invalid = Libp2pLimits {
            peer_store_startup_dials: Libp2pLimits::default().max_persisted_peers + 1,
            ..Libp2pLimits::default()
        };
        assert_eq!(
            invalid.validate(),
            Err(Libp2pLimitsError::Inconsistent(
                "peer_store_startup_dials exceeds max_persisted_peers or its hard safety bound"
            ))
        );
    }
}
