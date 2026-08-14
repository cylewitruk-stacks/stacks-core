// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Connection admission before application protocols are allowed to run.
//!
//! Cheap address/rate policy is applied from the pending-inbound hook, before
//! Noise and Yamux. Identity-aware policy is applied only after Noise has
//! authenticated the remote PeerId. All counters live here so a failed
//! handshake, a later-behaviour denial, an address change, and a normal close
//! share one cleanup path.

use std::collections::{HashMap, HashSet, VecDeque};
use std::convert::Infallible;
use std::net::IpAddr;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use libp2p::core::transport::PortUse;
use libp2p::core::{ConnectedPoint, Endpoint};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{
    dummy, CloseConnection, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, ToSwarm,
};
use libp2p::{Multiaddr, PeerId};

const RATE_WINDOW: Duration = Duration::from_secs(1);
const MAX_RATE_BUCKETS: usize = 4_096;

/// A deterministic routable-network bucket. ASN/provider diversity can be
/// added when a trustworthy mapping is available, while /24 and /48 limits
/// remain local and fail closed.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum NetworkPrefix {
    V4([u8; 3]),
    V6([u8; 6]),
}

impl NetworkPrefix {
    pub fn diversity_key(self) -> Vec<u8> {
        match self {
            Self::V4(bytes) => {
                let mut key = vec![4];
                key.extend_from_slice(&bytes);
                key
            }
            Self::V6(bytes) => {
                let mut key = vec![6];
                key.extend_from_slice(&bytes);
                key
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionPhase {
    PendingInbound,
    Established,
    AddressChange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AdmissionDenied {
    #[error("global inbound connection-attempt rate exceeded")]
    GlobalRate,
    #[error("inbound connection-attempt rate exceeded for remote IP")]
    IpRate,
    #[error("inbound connection-attempt rate exceeded for remote prefix")]
    PrefixRate,
    #[error("pending inbound connection limit exceeded for remote IP")]
    PendingIp,
    #[error("pending inbound connection limit exceeded for remote prefix")]
    PendingPrefix,
    #[error("established connection limit exceeded for remote IP")]
    EstablishedIp,
    #[error("established connection limit exceeded for remote prefix")]
    EstablishedPrefix,
    #[error("unreserved connection capacity is full")]
    ReservedCapacity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionEvent {
    pub peer: Option<PeerId>,
    pub connection_id: ConnectionId,
    pub phase: AdmissionPhase,
    pub reason: AdmissionDenied,
}

#[derive(Clone, Copy, Debug)]
struct AddressBucket {
    ip: IpAddr,
    prefix: NetworkPrefix,
}

#[derive(Clone, Copy, Debug)]
struct EstablishedConnection {
    peer: PeerId,
    bucket: AddressBucket,
}

#[derive(Clone, Debug)]
struct LiveConnection {
    peer: PeerId,
    outbound: bool,
    remote_addr: Multiaddr,
}

#[derive(Clone, Copy, Debug, Default)]
struct PeerConnectionCounts {
    total: usize,
    outbound: usize,
}

#[derive(Clone, Copy, Debug)]
struct FixedWindow {
    started: Instant,
    attempts: u32,
}

impl FixedWindow {
    fn admit(&mut self, now: Instant, limit: u32) -> bool {
        if now.saturating_duration_since(self.started) >= RATE_WINDOW {
            self.started = now;
            self.attempts = 0;
        }
        if self.attempts >= limit {
            return false;
        }
        self.attempts += 1;
        true
    }

    fn expired(self, now: Instant) -> bool {
        now.saturating_duration_since(self.started) >= RATE_WINDOW
    }
}

#[derive(Clone, Copy, Debug)]
pub struct AdmissionConfig {
    pub max_pending_per_ip: u32,
    pub max_pending_per_prefix: u32,
    pub max_established_per_ip: u32,
    pub max_established_per_prefix: u32,
    pub max_established_total: u32,
    pub max_connections_per_peer: u32,
    pub global_attempts_per_second: u32,
    pub attempts_per_ip_per_second: u32,
    pub attempts_per_prefix_per_second: u32,
}

impl AdmissionConfig {
    pub fn from_network(config: &crate::NetworkConfig) -> Self {
        Self {
            max_pending_per_ip: config.max_connections_per_ip,
            max_pending_per_prefix: config.max_connections_per_prefix,
            max_established_per_ip: config.max_connections_per_ip,
            max_established_per_prefix: config.max_connections_per_prefix,
            max_established_total: config.max_established_total,
            max_connections_per_peer: config.max_connections_per_peer,
            global_attempts_per_second: config.max_pending_incoming,
            attempts_per_ip_per_second: config.max_connections_per_ip,
            attempts_per_prefix_per_second: config.max_connections_per_prefix,
        }
    }
}

#[derive(Default)]
struct PendingAdmissions {
    by_connection: HashMap<ConnectionId, AddressBucket>,
    per_ip: HashMap<IpAddr, usize>,
    per_prefix: HashMap<NetworkPrefix, usize>,
}

#[derive(Default)]
struct EstablishedAdmissions {
    by_connection: HashMap<ConnectionId, EstablishedConnection>,
    per_ip: HashMap<IpAddr, usize>,
    per_prefix: HashMap<NetworkPrefix, usize>,
    peer_prefixes: HashMap<PeerId, HashMap<NetworkPrefix, usize>>,
    live: HashMap<ConnectionId, LiveConnection>,
    per_peer: HashMap<PeerId, PeerConnectionCounts>,
}

#[derive(Default)]
struct AdmissionRates {
    global: Option<FixedWindow>,
    per_ip: HashMap<IpAddr, FixedWindow>,
    per_prefix: HashMap<NetworkPrefix, FixedWindow>,
}

/// Stateful connection admission with a dummy protocol handler. Place this
/// immediately after libp2p's stock connection and memory limit behaviours.
pub struct ConnectionAdmissionBehaviour {
    config: AdmissionConfig,
    pending: PendingAdmissions,
    established: EstablishedAdmissions,
    rates: AdmissionRates,
    events: VecDeque<AdmissionEvent>,
    closes: VecDeque<(PeerId, ConnectionId)>,
    reserved_peers: HashSet<PeerId>,
    max_unreserved_connections: Option<usize>,
}

impl ConnectionAdmissionBehaviour {
    pub fn new(config: AdmissionConfig) -> Self {
        Self {
            config,
            pending: PendingAdmissions::default(),
            established: EstablishedAdmissions::default(),
            rates: AdmissionRates::default(),
            events: VecDeque::new(),
            closes: VecDeque::new(),
            reserved_peers: HashSet::new(),
            max_unreserved_connections: None,
        }
    }

    /// Reserve hard-limit headroom for statically authorized peers.
    ///
    /// The stock libp2p connection limiter remains the final total and
    /// per-PeerId safety boundary. This earlier identity-aware admission rule
    /// prevents ordinary restored, discovered, or inbound connections from
    /// consuming the slots that those authorized peers can use. Reserve the
    /// full per-peer allowance so simultaneous-dial overlap cannot starve a
    /// different reserved peer.
    pub fn reserve_capacity_for(
        &mut self,
        peers: impl IntoIterator<Item = PeerId>,
    ) -> Result<(), String> {
        if !self.established.live.is_empty() {
            return Err("reserved peer capacity must be configured before connections open".into());
        }
        let peers = peers.into_iter().collect::<HashSet<_>>();
        if peers.is_empty() {
            self.reserved_peers.clear();
            self.max_unreserved_connections = None;
            return Ok(());
        }
        let reserved_slots = peers
            .len()
            .checked_mul(self.config.max_connections_per_peer as usize)
            .ok_or_else(|| "reserved peer capacity overflowed usize".to_owned())?;
        let total = self.config.max_established_total as usize;
        let max_unreserved_connections = total.checked_sub(reserved_slots).ok_or_else(|| {
            "reserved peer capacity exceeds the total established connection limit".to_owned()
        })?;
        if max_unreserved_connections == 0 {
            return Err("reserved peer capacity leaves no ordinary connection slot".into());
        }
        self.reserved_peers = peers;
        self.max_unreserved_connections = Some(max_unreserved_connections);
        Ok(())
    }

    pub fn primary_prefix(&self, peer: &PeerId) -> Option<NetworkPrefix> {
        self.established
            .peer_prefixes
            .get(peer)
            .and_then(|prefixes| prefixes.keys().min().copied())
    }

    pub fn pending_len(&self) -> usize {
        self.pending.by_connection.len()
    }

    pub fn established_len(&self) -> usize {
        self.established.by_connection.len()
    }

    /// Peers with at least one live, post-Noise connection. Keeping this view
    /// beside admission's per-connection accounting prevents the service loop
    /// from growing a second connection registry.
    pub fn connected_peers(&self) -> impl Iterator<Item = PeerId> + '_ {
        self.established.per_peer.keys().copied()
    }

    pub fn connected_len(&self) -> usize {
        self.established.per_peer.len()
    }

    pub fn is_connected(&self, peer: &PeerId) -> bool {
        self.established.per_peer.contains_key(peer)
    }

    pub fn has_outbound_connection(&self, peer: &PeerId) -> bool {
        self.established
            .per_peer
            .get(peer)
            .is_some_and(|counts| counts.outbound > 0)
    }

    /// Return the exact endpoint used by an outbound post-Noise connection.
    /// Callers may persist it only after the same connection completes the
    /// application Hello; inbound source ports are intentionally excluded.
    pub fn authenticated_dial_address(
        &self,
        peer: &PeerId,
        connection_id: ConnectionId,
    ) -> Option<&Multiaddr> {
        self.established
            .live
            .get(&connection_id)
            .and_then(|live| (live.peer == *peer && live.outbound).then_some(&live.remote_addr))
    }

    fn admit_pending(
        &mut self,
        connection_id: ConnectionId,
        remote_addr: &Multiaddr,
        now: Instant,
    ) -> Result<(), AdmissionDenied> {
        let Some(bucket) = address_bucket(remote_addr) else {
            // DNS, onion, relay, and MemoryTransport addresses have no local
            // IP bucket. The adjacent stock global pending limiter still
            // applies; authenticated PeerId limits apply after Noise.
            return Ok(());
        };
        self.prune_rate_buckets(now);
        let global = self.rates.global.get_or_insert(FixedWindow {
            started: now,
            attempts: 0,
        });
        if !global.admit(now, self.config.global_attempts_per_second) {
            return Err(AdmissionDenied::GlobalRate);
        }
        if !admit_rate(
            &mut self.rates.per_ip,
            bucket.ip,
            now,
            self.config.attempts_per_ip_per_second,
        ) {
            return Err(AdmissionDenied::IpRate);
        }
        if !admit_rate(
            &mut self.rates.per_prefix,
            bucket.prefix,
            now,
            self.config.attempts_per_prefix_per_second,
        ) {
            return Err(AdmissionDenied::PrefixRate);
        }
        if self.pending.per_ip.get(&bucket.ip).copied().unwrap_or(0)
            >= self.config.max_pending_per_ip as usize
        {
            return Err(AdmissionDenied::PendingIp);
        }
        if self
            .pending
            .per_prefix
            .get(&bucket.prefix)
            .copied()
            .unwrap_or(0)
            >= self.config.max_pending_per_prefix as usize
        {
            return Err(AdmissionDenied::PendingPrefix);
        }
        if let Some(previous) = self.pending.by_connection.insert(connection_id, bucket) {
            self.decrement_pending(previous);
        }
        *self.pending.per_ip.entry(bucket.ip).or_default() += 1;
        *self.pending.per_prefix.entry(bucket.prefix).or_default() += 1;
        Ok(())
    }

    fn admit_established(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        remote_addr: &Multiaddr,
    ) -> Result<(), AdmissionDenied> {
        self.remove_pending(connection_id);
        if !self.reserved_peers.contains(&peer)
            && self.max_unreserved_connections.is_some_and(|limit| {
                self.established
                    .live
                    .values()
                    .filter(|connection| !self.reserved_peers.contains(&connection.peer))
                    .count()
                    >= limit
            })
        {
            return Err(AdmissionDenied::ReservedCapacity);
        }
        let Some(bucket) = address_bucket(remote_addr) else {
            return Ok(());
        };
        if self
            .established
            .per_ip
            .get(&bucket.ip)
            .copied()
            .unwrap_or(0)
            >= self.config.max_established_per_ip as usize
        {
            return Err(AdmissionDenied::EstablishedIp);
        }
        if self
            .established
            .per_prefix
            .get(&bucket.prefix)
            .copied()
            .unwrap_or(0)
            >= self.config.max_established_per_prefix as usize
        {
            return Err(AdmissionDenied::EstablishedPrefix);
        }
        self.insert_established(connection_id, peer, bucket);
        Ok(())
    }

    fn address_changed(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        remote_addr: &Multiaddr,
    ) {
        self.remove_established(connection_id);
        let Some(bucket) = address_bucket(remote_addr) else {
            return;
        };
        let reason = if self
            .established
            .per_ip
            .get(&bucket.ip)
            .copied()
            .unwrap_or(0)
            >= self.config.max_established_per_ip as usize
        {
            Some(AdmissionDenied::EstablishedIp)
        } else if self
            .established
            .per_prefix
            .get(&bucket.prefix)
            .copied()
            .unwrap_or(0)
            >= self.config.max_established_per_prefix as usize
        {
            Some(AdmissionDenied::EstablishedPrefix)
        } else {
            None
        };
        // Account the live connection at its actual address even while a
        // policy close is queued. ConnectionClosed then balances it exactly.
        self.insert_established(connection_id, peer, bucket);
        if let Some(reason) = reason {
            self.events.push_back(AdmissionEvent {
                peer: Some(peer),
                connection_id,
                phase: AdmissionPhase::AddressChange,
                reason,
            });
            self.closes.push_back((peer, connection_id));
        }
    }

    fn insert_established(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        bucket: AddressBucket,
    ) {
        if let Some(previous) = self
            .established
            .by_connection
            .insert(connection_id, EstablishedConnection { peer, bucket })
        {
            self.decrement_established(previous);
        }
        *self.established.per_ip.entry(bucket.ip).or_default() += 1;
        *self
            .established
            .per_prefix
            .entry(bucket.prefix)
            .or_default() += 1;
        *self
            .established
            .peer_prefixes
            .entry(peer)
            .or_default()
            .entry(bucket.prefix)
            .or_default() += 1;
    }

    fn remove_pending(&mut self, connection_id: ConnectionId) {
        if let Some(bucket) = self.pending.by_connection.remove(&connection_id) {
            self.decrement_pending(bucket);
        }
    }

    fn decrement_pending(&mut self, bucket: AddressBucket) {
        decrement(&mut self.pending.per_ip, bucket.ip);
        decrement(&mut self.pending.per_prefix, bucket.prefix);
    }

    fn remove_established(&mut self, connection_id: ConnectionId) {
        if let Some(connection) = self.established.by_connection.remove(&connection_id) {
            self.decrement_established(connection);
        }
    }

    fn decrement_established(&mut self, connection: EstablishedConnection) {
        decrement(&mut self.established.per_ip, connection.bucket.ip);
        decrement(&mut self.established.per_prefix, connection.bucket.prefix);
        if let Some(prefixes) = self.established.peer_prefixes.get_mut(&connection.peer) {
            decrement(prefixes, connection.bucket.prefix);
            if prefixes.is_empty() {
                self.established.peer_prefixes.remove(&connection.peer);
            }
        }
    }

    fn insert_live(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        outbound: bool,
        remote_addr: Multiaddr,
    ) {
        self.remove_live(connection_id);
        self.established.live.insert(
            connection_id,
            LiveConnection {
                peer,
                outbound,
                remote_addr,
            },
        );
        let counts = self.established.per_peer.entry(peer).or_default();
        counts.total = counts.total.saturating_add(1);
        counts.outbound = counts.outbound.saturating_add(usize::from(outbound));
    }

    fn remove_live(&mut self, connection_id: ConnectionId) {
        let Some(connection) = self.established.live.remove(&connection_id) else {
            return;
        };
        let mut remove_peer = false;
        if let Some(counts) = self.established.per_peer.get_mut(&connection.peer) {
            counts.total = counts.total.saturating_sub(1);
            counts.outbound = counts
                .outbound
                .saturating_sub(usize::from(connection.outbound));
            remove_peer = counts.total == 0;
        }
        if remove_peer {
            self.established.per_peer.remove(&connection.peer);
        }
    }

    fn prune_rate_buckets(&mut self, now: Instant) {
        self.rates.per_ip.retain(|_, window| !window.expired(now));
        self.rates
            .per_prefix
            .retain(|_, window| !window.expired(now));
        // Fail closed rather than permitting an attacker to bypass rate
        // limits by evicting a still-live address bucket.
        if self.rates.per_ip.len() > MAX_RATE_BUCKETS {
            self.rates.per_ip.retain(|_, _| false);
        }
        if self.rates.per_prefix.len() > MAX_RATE_BUCKETS {
            self.rates.per_prefix.retain(|_, _| false);
        }
    }
}

impl NetworkBehaviour for ConnectionAdmissionBehaviour {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = AdmissionEvent;

    fn handle_pending_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        _local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        self.admit_pending(connection_id, remote_addr, Instant::now())
            .map_err(|reason| {
                self.events.push_back(AdmissionEvent {
                    peer: None,
                    connection_id,
                    phase: AdmissionPhase::PendingInbound,
                    reason,
                });
                ConnectionDenied::new(reason)
            })
    }

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        _local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<Self::ConnectionHandler, ConnectionDenied> {
        self.admit_established(connection_id, peer, remote_addr)
            .map_err(|reason| {
                self.events.push_back(AdmissionEvent {
                    peer: Some(peer),
                    connection_id,
                    phase: AdmissionPhase::Established,
                    reason,
                });
                ConnectionDenied::new(reason)
            })?;
        self.insert_live(connection_id, peer, false, remote_addr.clone());
        Ok(dummy::ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        _role_override: Endpoint,
        _port_use: PortUse,
    ) -> Result<Self::ConnectionHandler, ConnectionDenied> {
        self.admit_established(connection_id, peer, addr)
            .map_err(|reason| {
                self.events.push_back(AdmissionEvent {
                    peer: Some(peer),
                    connection_id,
                    phase: AdmissionPhase::Established,
                    reason,
                });
                ConnectionDenied::new(reason)
            })?;
        self.insert_live(connection_id, peer, true, addr.clone());
        Ok(dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionClosed(event) => {
                self.remove_pending(event.connection_id);
                self.remove_established(event.connection_id);
                self.remove_live(event.connection_id);
            }
            FromSwarm::DialFailure(event) => {
                self.remove_pending(event.connection_id);
                self.remove_established(event.connection_id);
                self.remove_live(event.connection_id);
            }
            FromSwarm::ListenFailure(event) => {
                self.remove_pending(event.connection_id);
                self.remove_established(event.connection_id);
                self.remove_live(event.connection_id);
            }
            FromSwarm::AddressChange(event) => {
                self.address_changed(
                    event.connection_id,
                    event.peer_id,
                    remote_address(event.new),
                );
                if let Some(live) = self.established.live.get_mut(&event.connection_id) {
                    live.remote_addr = remote_address(event.new).clone();
                }
            }
            FromSwarm::ConnectionEstablished(event) => {
                self.remove_pending(event.connection_id);
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _peer_id: PeerId,
        _connection_id: ConnectionId,
        event: Infallible,
    ) {
        libp2p::core::util::unreachable(event)
    }

    fn poll(&mut self, _cx: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, Infallible>> {
        if let Some((peer_id, connection_id)) = self.closes.pop_front() {
            return Poll::Ready(ToSwarm::CloseConnection {
                peer_id,
                connection: CloseConnection::One(connection_id),
            });
        }
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(ToSwarm::GenerateEvent(event));
        }
        Poll::Pending
    }
}

pub fn multiaddr_ip(address: &Multiaddr) -> Option<IpAddr> {
    address.iter().find_map(|protocol| match protocol {
        Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
        Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
        _ => None,
    })
}

pub fn network_prefix(ip: IpAddr) -> NetworkPrefix {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            NetworkPrefix::V4([octets[0], octets[1], octets[2]])
        }
        IpAddr::V6(ip) => {
            let octets = ip.octets();
            NetworkPrefix::V6([
                octets[0], octets[1], octets[2], octets[3], octets[4], octets[5],
            ])
        }
    }
}

fn address_bucket(address: &Multiaddr) -> Option<AddressBucket> {
    multiaddr_ip(address).map(|ip| AddressBucket {
        ip,
        prefix: network_prefix(ip),
    })
}

fn remote_address(point: &ConnectedPoint) -> &Multiaddr {
    point.get_remote_address()
}

fn decrement<K: Eq + std::hash::Hash + Copy>(counts: &mut HashMap<K, usize>, key: K) {
    if let Some(count) = counts.get_mut(&key) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            counts.remove(&key);
        }
    }
}

fn admit_rate<K: Eq + std::hash::Hash + Copy>(
    rates: &mut HashMap<K, FixedWindow>,
    key: K,
    now: Instant,
    limit: u32,
) -> bool {
    if !rates.contains_key(&key) && rates.len() >= MAX_RATE_BUCKETS {
        return false;
    }
    rates
        .entry(key)
        .or_insert(FixedWindow {
            started: now,
            attempts: 0,
        })
        .admit(now, limit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::core::ConnectedPoint;
    use libp2p::swarm::behaviour::{ConnectionClosed, ListenFailure};
    use libp2p::swarm::ListenError;

    fn config() -> AdmissionConfig {
        AdmissionConfig {
            max_pending_per_ip: 1,
            max_pending_per_prefix: 2,
            max_established_per_ip: 1,
            max_established_per_prefix: 2,
            max_established_total: 8,
            max_connections_per_peer: 2,
            global_attempts_per_second: 8,
            attempts_per_ip_per_second: 2,
            attempts_per_prefix_per_second: 4,
        }
    }

    fn address(last: u8) -> Multiaddr {
        format!("/ip4/192.0.2.{last}/tcp/20445").parse().unwrap()
    }

    #[test]
    fn pending_policy_runs_before_identity_and_cleans_failure() {
        let now = Instant::now();
        let mut behaviour = ConnectionAdmissionBehaviour::new(config());
        let first = ConnectionId::new_unchecked(1);
        behaviour.admit_pending(first, &address(1), now).unwrap();
        assert_eq!(behaviour.pending_len(), 1);
        assert_eq!(
            behaviour.admit_pending(ConnectionId::new_unchecked(2), &address(1), now),
            Err(AdmissionDenied::PendingIp)
        );
        behaviour.remove_pending(first);
        assert_eq!(behaviour.pending_len(), 0);
        behaviour
            .admit_pending(
                ConnectionId::new_unchecked(3),
                &address(1),
                now + RATE_WINDOW,
            )
            .unwrap();
    }

    #[test]
    fn lifecycle_hooks_reject_before_peer_identity_and_balance_failure_and_close() {
        let mut behaviour = ConnectionAdmissionBehaviour::new(config());
        let local: Multiaddr = "/ip4/127.0.0.1/tcp/20445".parse().unwrap();
        let remote = address(1);
        let pending = ConnectionId::new_unchecked(11);

        // The pending hook has no PeerId argument: this policy runs before
        // Noise authenticates an identity.
        NetworkBehaviour::handle_pending_inbound_connection(
            &mut behaviour,
            pending,
            &local,
            &remote,
        )
        .unwrap();
        assert_eq!(behaviour.pending_len(), 1);
        let aborted = ListenError::Aborted;
        NetworkBehaviour::on_swarm_event(
            &mut behaviour,
            FromSwarm::ListenFailure(ListenFailure {
                local_addr: &local,
                send_back_addr: &remote,
                error: &aborted,
                connection_id: pending,
                peer_id: None,
            }),
        );
        assert_eq!(behaviour.pending_len(), 0);

        let established_id = ConnectionId::new_unchecked(12);
        let peer = PeerId::random();
        NetworkBehaviour::handle_pending_inbound_connection(
            &mut behaviour,
            established_id,
            &local,
            &remote,
        )
        .unwrap();
        NetworkBehaviour::handle_established_inbound_connection(
            &mut behaviour,
            established_id,
            peer,
            &local,
            &remote,
        )
        .unwrap();
        assert_eq!(behaviour.pending_len(), 0);
        assert_eq!(behaviour.established_len(), 1);
        assert!(behaviour.is_connected(&peer));
        assert_eq!(behaviour.connected_len(), 1);
        assert!(!behaviour.has_outbound_connection(&peer));
        let endpoint = ConnectedPoint::Listener {
            local_addr: local,
            send_back_addr: remote,
        };
        NetworkBehaviour::on_swarm_event(
            &mut behaviour,
            FromSwarm::ConnectionClosed(ConnectionClosed {
                peer_id: peer,
                connection_id: established_id,
                endpoint: &endpoint,
                cause: None,
                remaining_established: 0,
            }),
        );
        assert_eq!(behaviour.established_len(), 0);
        assert!(behaviour.primary_prefix(&peer).is_none());
        assert!(!behaviour.is_connected(&peer));
        assert_eq!(behaviour.connected_len(), 0);
    }

    #[test]
    fn peer_connection_view_tracks_each_connection_and_direction() {
        let mut behaviour = ConnectionAdmissionBehaviour::new(config());
        let peer = PeerId::random();
        let inbound = ConnectionId::new_unchecked(31);
        let outbound = ConnectionId::new_unchecked(32);

        behaviour.insert_live(inbound, peer, false, "/memory/1".parse().unwrap());
        behaviour.insert_live(outbound, peer, true, "/memory/2".parse().unwrap());
        assert_eq!(behaviour.connected_peers().collect::<Vec<_>>(), [peer]);
        assert!(behaviour.has_outbound_connection(&peer));

        behaviour.remove_live(outbound);
        assert!(behaviour.is_connected(&peer));
        assert!(!behaviour.has_outbound_connection(&peer));

        behaviour.remove_live(inbound);
        assert!(!behaviour.is_connected(&peer));
    }

    #[test]
    fn ordinary_connections_cannot_consume_reserved_peer_capacity() {
        let mut policy = config();
        policy.max_established_total = 6;
        policy.max_connections_per_peer = 2;
        policy.max_established_per_ip = 6;
        policy.max_established_per_prefix = 6;
        let mut behaviour = ConnectionAdmissionBehaviour::new(policy);
        let reserved_a = PeerId::random();
        let reserved_b = PeerId::random();
        behaviour
            .reserve_capacity_for([reserved_a, reserved_b])
            .unwrap();

        for id in 1..=2 {
            let peer = PeerId::random();
            behaviour
                .admit_established(ConnectionId::new_unchecked(id), peer, &address(id as u8))
                .unwrap();
            behaviour.insert_live(
                ConnectionId::new_unchecked(id),
                peer,
                true,
                address(id as u8),
            );
        }
        assert_eq!(
            behaviour.admit_established(
                ConnectionId::new_unchecked(3),
                PeerId::random(),
                &address(3),
            ),
            Err(AdmissionDenied::ReservedCapacity)
        );

        // Two connections for each reserved peer still fit the stock hard
        // total of six; ordinary traffic cannot have consumed their slots.
        for (offset, reserved) in [reserved_a, reserved_b].into_iter().enumerate() {
            for duplicate in 0..2 {
                let id = ConnectionId::new_unchecked(10 + offset * 2 + duplicate);
                behaviour
                    .admit_established(id, reserved, &address(10 + offset as u8))
                    .unwrap();
                behaviour.insert_live(id, reserved, true, address(10 + offset as u8));
            }
        }
        assert_eq!(behaviour.established.live.len(), 6);
    }

    #[test]
    fn reservation_fails_closed_when_no_ordinary_capacity_remains() {
        let mut policy = config();
        policy.max_established_total = 4;
        let mut behaviour = ConnectionAdmissionBehaviour::new(policy);
        let error = behaviour
            .reserve_capacity_for([PeerId::random(), PeerId::random()])
            .unwrap_err();
        assert_eq!(
            error,
            "reserved peer capacity leaves no ordinary connection slot"
        );
        assert!(behaviour.reserved_peers.is_empty());
        assert!(behaviour.max_unreserved_connections.is_none());
    }

    #[test]
    fn failed_denied_closed_and_address_changed_connections_balance_exactly() {
        let now = Instant::now();
        let mut behaviour = ConnectionAdmissionBehaviour::new(config());
        let alice = PeerId::random();
        let bob = PeerId::random();
        let first = ConnectionId::new_unchecked(1);
        behaviour.admit_pending(first, &address(1), now).unwrap();
        behaviour
            .admit_established(first, alice, &address(1))
            .unwrap();
        assert_eq!(behaviour.pending_len(), 0);
        assert_eq!(behaviour.established_len(), 1);
        assert_eq!(
            behaviour.admit_established(ConnectionId::new_unchecked(2), bob, &address(1)),
            Err(AdmissionDenied::EstablishedIp)
        );
        assert_eq!(behaviour.established_len(), 1);

        behaviour.address_changed(first, alice, &address(2));
        assert_eq!(behaviour.established_len(), 1);
        assert_eq!(
            behaviour.primary_prefix(&alice),
            Some(network_prefix("192.0.2.2".parse().unwrap()))
        );
        behaviour.remove_established(first);
        assert_eq!(behaviour.established_len(), 0);
        assert!(behaviour.primary_prefix(&alice).is_none());
    }

    #[test]
    fn attempt_limits_refill_without_sleeping() {
        let now = Instant::now();
        let mut behaviour = ConnectionAdmissionBehaviour::new(config());
        behaviour
            .admit_pending(ConnectionId::new_unchecked(1), &address(1), now)
            .unwrap();
        behaviour.remove_pending(ConnectionId::new_unchecked(1));
        behaviour
            .admit_pending(ConnectionId::new_unchecked(2), &address(1), now)
            .unwrap();
        behaviour.remove_pending(ConnectionId::new_unchecked(2));
        assert_eq!(
            behaviour.admit_pending(ConnectionId::new_unchecked(3), &address(1), now),
            Err(AdmissionDenied::IpRate)
        );
        behaviour
            .admit_pending(
                ConnectionId::new_unchecked(4),
                &address(1),
                now + RATE_WINDOW,
            )
            .unwrap();
    }

    #[test]
    fn routable_prefixes_are_stable_and_separate_adjacent_networks() {
        assert_eq!(
            network_prefix("192.0.2.1".parse().unwrap()),
            network_prefix("192.0.2.254".parse().unwrap())
        );
        assert_ne!(
            network_prefix("192.0.2.1".parse().unwrap()),
            network_prefix("192.0.3.1".parse().unwrap())
        );
        assert_eq!(
            network_prefix("2001:db8:abcd::1".parse().unwrap()),
            network_prefix("2001:db8:abcd:ffff::1".parse().unwrap())
        );
        assert_ne!(
            network_prefix("2001:db8:abcd::1".parse().unwrap()),
            network_prefix("2001:db8:abce::1".parse().unwrap())
        );
    }
}
