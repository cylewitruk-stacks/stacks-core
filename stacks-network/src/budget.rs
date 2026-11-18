use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

/// Independent byte and validation-cost token buckets for one authenticated
/// transport peer. This protects allocation bandwidth and CPU-heavy parsing or
/// signature checks without conflating the two resources.
#[derive(Clone, Debug)]
pub struct PeerResourceBudget<K> {
    peers: HashMap<K, PeerBuckets>,
    byte_rate: u64,
    byte_burst: u64,
    work_rate: u64,
    work_burst: u64,
    idle_ttl: Duration,
}

#[derive(Clone, Debug)]
struct PeerBuckets {
    bytes: TokenBucket,
    work: TokenBucket,
    last_seen: Instant,
}

#[derive(Clone, Debug)]
struct TokenBucket {
    available: u64,
    last_refill: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetRejection {
    Bytes,
    ValidationWork,
}

impl<K: Clone + Eq + Hash> PeerResourceBudget<K> {
    pub fn new(
        byte_rate: u64,
        byte_burst: u64,
        work_rate: u64,
        work_burst: u64,
        idle_ttl: Duration,
    ) -> Result<Self, String> {
        if byte_rate == 0 || byte_burst == 0 || work_rate == 0 || work_burst == 0 {
            return Err("peer resource limits must be nonzero".to_owned());
        }
        if byte_burst < byte_rate || work_burst < work_rate {
            return Err("peer resource bursts must cover at least one second".to_owned());
        }
        Ok(Self {
            peers: HashMap::new(),
            byte_rate,
            byte_burst,
            work_rate,
            work_burst,
            idle_ttl,
        })
    }

    pub fn admit(
        &mut self,
        peer: K,
        bytes: u64,
        validation_work: u64,
    ) -> Result<(), BudgetRejection> {
        self.admit_at(peer, bytes, validation_work, Instant::now())
    }

    fn admit_at(
        &mut self,
        peer: K,
        bytes: u64,
        validation_work: u64,
        now: Instant,
    ) -> Result<(), BudgetRejection> {
        let buckets = self.peers.entry(peer).or_insert_with(|| PeerBuckets {
            bytes: TokenBucket::full(self.byte_burst, now),
            work: TokenBucket::full(self.work_burst, now),
            last_seen: now,
        });
        buckets.last_seen = now;
        buckets.bytes.refill(self.byte_rate, self.byte_burst, now);
        buckets.work.refill(self.work_rate, self.work_burst, now);

        // Check both dimensions before debiting either so a rejected request is
        // never partially charged and retry behavior remains deterministic.
        if buckets.bytes.available < bytes {
            return Err(BudgetRejection::Bytes);
        }
        if buckets.work.available < validation_work {
            return Err(BudgetRejection::ValidationWork);
        }
        buckets.bytes.available -= bytes;
        buckets.work.available -= validation_work;
        Ok(())
    }

    pub fn remove(&mut self, peer: &K) {
        self.peers.remove(peer);
    }

    pub fn prune_idle(&mut self) {
        let cutoff = Instant::now() - self.idle_ttl;
        self.peers.retain(|_, buckets| buckets.last_seen >= cutoff);
    }
}

impl TokenBucket {
    fn full(capacity: u64, now: Instant) -> Self {
        Self {
            available: capacity,
            last_refill: now,
        }
    }

    fn refill(&mut self, rate: u64, capacity: u64, now: Instant) {
        let elapsed_nanos = now.duration_since(self.last_refill).as_nanos();
        let refill = (u128::from(rate) * elapsed_nanos / 1_000_000_000)
            .try_into()
            .unwrap_or(u64::MAX);
        self.available = self.available.saturating_add(refill).min(capacity);
        self.last_refill = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resources_are_independent_and_refill_without_partial_debits() {
        let start = Instant::now();
        let mut budget =
            PeerResourceBudget::new(100, 100, 10, 10, Duration::from_secs(60)).unwrap();

        assert_eq!(budget.admit_at(1, 90, 1, start), Ok(()));
        assert_eq!(
            budget.admit_at(1, 11, 1, start),
            Err(BudgetRejection::Bytes)
        );
        assert_eq!(budget.admit_at(1, 10, 9, start), Ok(()));
        assert_eq!(
            budget.admit_at(1, 0, 1, start),
            Err(BudgetRejection::ValidationWork)
        );
        assert_eq!(
            budget.admit_at(1, 50, 5, start + Duration::from_millis(500)),
            Ok(())
        );
        assert_eq!(budget.admit_at(2, 100, 10, start), Ok(()));
    }
}
