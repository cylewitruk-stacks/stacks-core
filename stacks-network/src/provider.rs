// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Transport-neutral provider health and diversity selection.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use libp2p::PeerId;

const BASE_FAILURE_BACKOFF: Duration = Duration::from_secs(1);
const MAX_FAILURE_BACKOFF: Duration = Duration::from_secs(60);
const OVERLOAD_BACKOFF: Duration = Duration::from_millis(250);
const INVALID_DATA_QUARANTINE: Duration = Duration::from_secs(10 * 60);
const MAX_RETAINED_PROVIDERS: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderOutcome {
    Success {
        latency: Duration,
    },
    /// The authenticated provider answered but its bounded ingress was full.
    /// This is positive liveness evidence, not a transport failure.
    Busy,
    Unavailable,
    InvalidData,
}

#[derive(Clone, Debug, Default)]
struct ProviderHealth {
    failure_domain: Option<Vec<u8>>,
    outbound: bool,
    connected: bool,
    last_seen: Option<Instant>,
    successes: u64,
    consecutive_failures: u32,
    invalid_data: u64,
    latency_ewma_ms: Option<u64>,
    unavailable_until: Option<Instant>,
    invalid_until: Option<Instant>,
}

/// Scores providers without owning transport requests. Selection first takes
/// one provider per failure domain, then fills from the remaining ranked set.
pub struct ProviderPool {
    providers: HashMap<PeerId, ProviderHealth>,
    /// Operator-configured recovery anchors. Pinning affects selection order
    /// only: the peer must still be connected, capability-authenticated, and
    /// outside the ordinary availability and invalid-data quarantines.
    pinned: HashSet<PeerId>,
}

impl Default for ProviderPool {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderPool {
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
            pinned: HashSet::new(),
        }
    }

    pub fn pin(&mut self, peer: PeerId) {
        self.pinned.insert(peer);
    }

    pub fn upsert(&mut self, peer: PeerId, failure_domain: Option<Vec<u8>>, outbound: bool) {
        if self.providers.len() >= MAX_RETAINED_PROVIDERS && !self.providers.contains_key(&peer) {
            if let Some(expired) = self
                .providers
                .iter()
                .filter(|(_, health)| !health.connected)
                .min_by_key(|(_, health)| health.last_seen)
                .map(|(peer, _)| *peer)
            {
                self.providers.remove(&expired);
            } else {
                return;
            }
        }
        let health = self.providers.entry(peer).or_default();
        health.failure_domain = failure_domain;
        health.outbound = outbound;
        health.connected = true;
        health.last_seen = Some(Instant::now());
    }

    pub fn disconnect(&mut self, peer: &PeerId) {
        if let Some(health) = self.providers.get_mut(peer) {
            health.connected = false;
            health.last_seen = Some(Instant::now());
        }
    }

    pub fn observe(&mut self, peer: PeerId, outcome: ProviderOutcome, now: Instant) {
        let health = self.providers.entry(peer).or_default();
        match outcome {
            ProviderOutcome::Success { latency } => {
                health.successes = health.successes.saturating_add(1);
                health.consecutive_failures = 0;
                // Successful delivery rehabilitates transient availability,
                // but never erases a semantic-invalid quarantine early. A
                // peer may answer one object correctly after corrupting a
                // different request.
                health.unavailable_until = None;
                let sample = latency.as_millis().try_into().unwrap_or(u64::MAX);
                health.latency_ewma_ms = Some(match health.latency_ewma_ms {
                    Some(previous) => previous.saturating_mul(7).saturating_add(sample) / 8,
                    None => sample,
                });
            }
            ProviderOutcome::Unavailable => {
                health.consecutive_failures = health.consecutive_failures.saturating_add(1);
                let exponent = health.consecutive_failures.saturating_sub(1).min(6);
                let backoff = BASE_FAILURE_BACKOFF
                    .checked_mul(1_u32 << exponent)
                    .unwrap_or(MAX_FAILURE_BACKOFF)
                    .min(MAX_FAILURE_BACKOFF);
                health.unavailable_until = Some(now + backoff);
            }
            ProviderOutcome::Busy => {
                // Avoid synchronously hammering a saturated peer without
                // escalating the failure backoff. Treating Busy as
                // Unavailable can exile a healthy bootstrap for a minute
                // under a simultaneous IBD fan-in.
                health.unavailable_until = Some(now + OVERLOAD_BACKOFF);
            }
            ProviderOutcome::InvalidData => {
                health.invalid_data = health.invalid_data.saturating_add(1);
                health.consecutive_failures = health.consecutive_failures.saturating_add(1);
                health.invalid_until = Some(now + INVALID_DATA_QUARANTINE);
            }
        }
    }

    pub fn note_latency(&mut self, peer: PeerId, latency: Duration) {
        let health = self.providers.entry(peer).or_default();
        let sample = latency.as_millis().try_into().unwrap_or(u64::MAX);
        health.latency_ewma_ms = Some(match health.latency_ewma_ms {
            Some(previous) => previous.saturating_mul(7).saturating_add(sample) / 8,
            None => sample,
        });
    }

    pub fn latency(&self, peer: &PeerId) -> Option<Duration> {
        self.providers
            .get(peer)
            .and_then(|health| health.latency_ewma_ms)
            .map(Duration::from_millis)
    }

    pub fn connected_latencies(&self) -> impl Iterator<Item = (PeerId, Duration)> + '_ {
        self.providers.iter().filter_map(|(peer, health)| {
            health
                .connected
                .then_some(health.latency_ewma_ms)
                .flatten()
                .map(|milliseconds| (*peer, Duration::from_millis(milliseconds)))
        })
    }

    pub fn select(
        &self,
        eligible: impl IntoIterator<Item = PeerId>,
        excluded: &HashSet<PeerId>,
        limit: usize,
        now: Instant,
    ) -> Vec<PeerId> {
        let mut ranked = eligible
            .into_iter()
            .filter(|peer| !excluded.contains(peer))
            .filter_map(|peer| {
                let health = self.providers.get(&peer)?;
                if !health.connected {
                    return None;
                }
                if health.unavailable_until.is_some_and(|until| until > now) {
                    return None;
                }
                if health.invalid_until.is_some_and(|until| until > now) {
                    return None;
                }
                Some((peer, health))
            })
            .collect::<Vec<_>>();
        ranked.sort_by(|(left_peer, left), (right_peer, right)| {
            self.pinned
                .contains(right_peer)
                .cmp(&self.pinned.contains(left_peer))
                .then_with(|| right.outbound.cmp(&left.outbound))
                .then_with(|| left.invalid_data.cmp(&right.invalid_data))
                .then_with(|| left.consecutive_failures.cmp(&right.consecutive_failures))
                .then_with(|| right.successes.cmp(&left.successes))
                .then_with(|| {
                    left.latency_ewma_ms
                        .unwrap_or(u64::MAX)
                        .cmp(&right.latency_ewma_ms.unwrap_or(u64::MAX))
                })
                .then_with(|| left_peer.to_bytes().cmp(&right_peer.to_bytes()))
        });

        let mut selected = Vec::with_capacity(limit.min(ranked.len()));
        let mut deferred = Vec::new();
        let mut domains = HashSet::new();
        for (peer, health) in ranked {
            if health
                .failure_domain
                .as_ref()
                .is_none_or(|domain| domains.insert(domain.clone()))
            {
                selected.push(peer);
            } else {
                deferred.push(peer);
            }
            if selected.len() == limit {
                return selected;
            }
        }
        for peer in deferred {
            selected.push(peer);
            if selected.len() == limit {
                break;
            }
        }
        selected
    }
}

/// Backpressure-aware upper bound for independent sync requests.
pub fn adaptive_sync_concurrency(
    configured_max: usize,
    validation_slots_available: usize,
    relayer_backlog: usize,
    relayer_capacity: usize,
) -> usize {
    if configured_max == 0 || validation_slots_available == 0 {
        return 0;
    }
    let pressure = if relayer_capacity == 0 {
        1.0
    } else {
        relayer_backlog as f64 / relayer_capacity as f64
    };
    let pressure_limit = if pressure >= 0.9 {
        1
    } else if pressure >= 0.5 {
        configured_max.div_ceil(2)
    } else {
        configured_max
    };
    configured_max
        .min(validation_slots_available)
        .min(pressure_limit)
        .max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_is_diverse_ranked_and_quarantines_invalid_data() {
        let now = Instant::now();
        let mut pool = ProviderPool::new();
        let first = PeerId::random();
        let sibling = PeerId::random();
        let diverse = PeerId::random();
        pool.upsert(first, Some(vec![1]), true);
        pool.upsert(sibling, Some(vec![1]), true);
        pool.upsert(diverse, Some(vec![2]), false);
        pool.observe(
            first,
            ProviderOutcome::Success {
                latency: Duration::from_millis(5),
            },
            now,
        );

        let eligible = [first, sibling, diverse];
        let selected = pool.select(eligible, &HashSet::new(), 2, now);
        assert_eq!(selected[0], first);
        assert_eq!(selected[1], diverse);

        pool.observe(first, ProviderOutcome::InvalidData, now);
        pool.observe(
            first,
            ProviderOutcome::Success {
                latency: Duration::from_millis(4),
            },
            now + Duration::from_secs(1),
        );
        let selected = pool.select(eligible, &HashSet::new(), 3, now);
        assert!(!selected.contains(&first));
        assert!(pool
            .select(eligible, &HashSet::new(), 3, now + INVALID_DATA_QUARANTINE)
            .contains(&first));
    }

    #[test]
    fn pinned_recovery_anchor_is_preferred_but_never_bypasses_quarantine() {
        let now = Instant::now();
        let mut pool = ProviderPool::new();
        let proven = PeerId::random();
        let bootstrap = PeerId::random();
        pool.upsert(proven, Some(vec![1]), true);
        pool.upsert(bootstrap, Some(vec![2]), true);
        pool.observe(
            proven,
            ProviderOutcome::Success {
                latency: Duration::from_millis(1),
            },
            now,
        );
        pool.pin(bootstrap);

        assert_eq!(
            pool.select([proven, bootstrap], &HashSet::new(), 2, now)[0],
            bootstrap
        );

        pool.observe(bootstrap, ProviderOutcome::InvalidData, now);
        assert_eq!(
            pool.select([proven, bootstrap], &HashSet::new(), 2, now),
            vec![proven]
        );
    }

    #[test]
    fn busy_is_a_short_overload_delay_not_an_exponential_failure() {
        let now = Instant::now();
        let mut pool = ProviderPool::new();
        let bootstrap = PeerId::random();
        pool.upsert(bootstrap, Some(vec![1]), true);
        pool.pin(bootstrap);

        for _ in 0..32 {
            pool.observe(bootstrap, ProviderOutcome::Busy, now);
        }
        assert!(pool.select([bootstrap], &HashSet::new(), 1, now).is_empty());
        assert_eq!(
            pool.select([bootstrap], &HashSet::new(), 1, now + OVERLOAD_BACKOFF),
            vec![bootstrap]
        );
    }

    #[test]
    fn adaptive_concurrency_respects_validation_and_relayer_pressure() {
        assert_eq!(adaptive_sync_concurrency(8, 8, 0, 16), 8);
        assert_eq!(adaptive_sync_concurrency(8, 3, 0, 16), 3);
        assert_eq!(adaptive_sync_concurrency(8, 8, 10, 16), 4);
        assert_eq!(adaptive_sync_concurrency(8, 8, 15, 16), 1);
        assert_eq!(adaptive_sync_concurrency(8, 0, 0, 16), 0);
    }
}
