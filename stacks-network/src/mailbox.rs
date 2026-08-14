use std::array;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Independently reserved network-to-relayer admission classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum Priority {
    SignerConsensus = 0,
    CurrentTenure = 1,
    ControlSync = 2,
    Transaction = 3,
    BulkSync = 4,
    Attachment = 5,
}

const PRIORITY_COUNT: usize = 6;
const FAIR_SCHEDULE: [Priority; 16] = [
    Priority::SignerConsensus,
    Priority::CurrentTenure,
    Priority::SignerConsensus,
    Priority::ControlSync,
    Priority::SignerConsensus,
    Priority::Transaction,
    Priority::CurrentTenure,
    Priority::BulkSync,
    Priority::SignerConsensus,
    Priority::CurrentTenure,
    Priority::ControlSync,
    Priority::Attachment,
    Priority::SignerConsensus,
    Priority::Transaction,
    Priority::CurrentTenure,
    Priority::BulkSync,
];

/// Item and byte capacity reserved for one lane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LaneLimit {
    pub items: usize,
    pub bytes: usize,
}

/// Explicit bounded-admission failure; callers choose drop, retry, or backpressure policy.
#[derive(Clone, Copy, Debug, thiserror::Error, Eq, PartialEq)]
pub enum MailboxError {
    #[error("item size {actual} exceeds lane byte limit {limit}")]
    ItemTooLarge { actual: usize, limit: usize },
    #[error("priority lane is full")]
    Full,
}

struct Queued<T> {
    value: T,
    bytes: usize,
    admitted_at: Instant,
}

/// A bounded, byte-accounted, fairly drained mailbox with reserved critical capacity.
pub struct PriorityMailbox<T> {
    queues: [VecDeque<Queued<T>>; PRIORITY_COUNT],
    bytes: [usize; PRIORITY_COUNT],
    limits: [LaneLimit; PRIORITY_COUNT],
    cursor: usize,
}

impl<T> PriorityMailbox<T> {
    pub fn new(limits: [LaneLimit; PRIORITY_COUNT]) -> Self {
        Self {
            queues: array::from_fn(|_| VecDeque::new()),
            bytes: [0; PRIORITY_COUNT],
            limits,
            cursor: 0,
        }
    }

    pub fn try_push(
        &mut self,
        priority: Priority,
        encoded_bytes: usize,
        value: T,
    ) -> Result<(), MailboxError> {
        let lane = priority as usize;
        let limit = self.limits[lane];
        if encoded_bytes > limit.bytes {
            return Err(MailboxError::ItemTooLarge {
                actual: encoded_bytes,
                limit: limit.bytes,
            });
        }
        if self.queues[lane].len() >= limit.items
            || self.bytes[lane].saturating_add(encoded_bytes) > limit.bytes
        {
            return Err(MailboxError::Full);
        }
        self.queues[lane].push_back(Queued {
            value,
            bytes: encoded_bytes,
            admitted_at: Instant::now(),
        });
        self.bytes[lane] += encoded_bytes;
        Ok(())
    }

    /// Drain according to a fixed weighted schedule. Empty lanes are skipped, so work
    /// conservation does not trade away guaranteed opportunities for lower priorities.
    pub fn pop_fair(&mut self) -> Option<(Priority, T, Duration)> {
        for _ in 0..FAIR_SCHEDULE.len() {
            let priority = FAIR_SCHEDULE[self.cursor];
            self.cursor = (self.cursor + 1) % FAIR_SCHEDULE.len();
            let lane = priority as usize;
            if let Some(queued) = self.queues[lane].pop_front() {
                self.bytes[lane] -= queued.bytes;
                return Some((priority, queued.value, queued.admitted_at.elapsed()));
            }
        }
        None
    }

    pub fn lane_usage(&self, priority: Priority) -> (usize, usize) {
        let lane = priority as usize;
        (self.queues[lane].len(), self.bytes[lane])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mailbox() -> PriorityMailbox<u64> {
        PriorityMailbox::new(
            [LaneLimit {
                items: 2,
                bytes: 16,
            }; PRIORITY_COUNT],
        )
    }

    #[test]
    fn low_priority_flood_cannot_consume_consensus_reservation() {
        let mut mailbox = mailbox();
        mailbox.try_push(Priority::Transaction, 8, 1).unwrap();
        mailbox.try_push(Priority::Transaction, 8, 2).unwrap();
        assert_eq!(
            mailbox.try_push(Priority::Transaction, 1, 3),
            Err(MailboxError::Full)
        );
        mailbox.try_push(Priority::SignerConsensus, 16, 4).unwrap();
        assert_eq!(mailbox.lane_usage(Priority::SignerConsensus), (1, 16));
    }

    #[test]
    fn fixed_schedule_gives_bulk_work_a_bounded_opportunity() {
        let mut mailbox = PriorityMailbox::new(
            [LaneLimit {
                items: 64,
                bytes: 1024,
            }; PRIORITY_COUNT],
        );
        for value in 0..32 {
            mailbox
                .try_push(Priority::SignerConsensus, 1, value)
                .unwrap();
        }
        mailbox.try_push(Priority::BulkSync, 1, 99).unwrap();
        let drained: Vec<_> = (0..8).filter_map(|_| mailbox.pop_fair()).collect();
        assert!(drained
            .iter()
            .any(|(priority, value, _)| *priority == Priority::BulkSync && *value == 99));
    }

    #[test]
    fn bytes_are_released_when_drained() {
        let mut mailbox = mailbox();
        mailbox.try_push(Priority::CurrentTenure, 12, 1).unwrap();
        assert_eq!(mailbox.lane_usage(Priority::CurrentTenure), (1, 12));
        assert!(mailbox.pop_fair().is_some());
        assert_eq!(mailbox.lane_usage(Priority::CurrentTenure), (0, 0));
    }
}
