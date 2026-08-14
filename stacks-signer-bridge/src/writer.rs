use std::collections::HashMap;
use std::time::Duration;

use clarity::vm::types::QualifiedContractIdentifier;
use libsigner::{SignerSession, StackerDBSession};

use crate::PendingLegacyWrite;

/// Bounded result of attempting one origin-authorized legacy write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyWriteResult {
    pub succeeded: bool,
    pub observed_latest_version: Option<u32>,
    pub last_error: Option<String>,
}

/// Worker-local StackerDB sessions keyed by contract. This type is deliberately
/// synchronous: callers own the bounded worker thread so legacy HTTP can never
/// block a native libp2p swarm or signer/miner policy thread.
pub struct StackerDbLegacyWriter {
    node_host: String,
    timeout: Duration,
    sessions: HashMap<String, StackerDBSession>,
}

impl StackerDbLegacyWriter {
    pub fn new(node_host: String, timeout: Duration) -> Self {
        Self {
            node_host,
            timeout,
            sessions: HashMap::new(),
        }
    }

    /// Try a write a bounded number of times with capped exponential backoff.
    pub fn write(&mut self, pending: &PendingLegacyWrite, attempts: u32) -> LegacyWriteResult {
        let contract = match QualifiedContractIdentifier::parse(&pending.locator.contract) {
            Ok(contract) => contract,
            Err(error) => {
                return LegacyWriteResult {
                    succeeded: false,
                    observed_latest_version: None,
                    last_error: Some(format!("invalid contract identifier: {error}")),
                };
            }
        };
        let session = self
            .sessions
            .entry(pending.locator.contract.clone())
            .or_insert_with(|| StackerDBSession::new(&self.node_host, contract, self.timeout));
        let mut result = LegacyWriteResult {
            succeeded: false,
            observed_latest_version: None,
            last_error: None,
        };
        for attempt in 0..attempts.clamp(1, 8) {
            match session.put_chunk(&pending.chunk) {
                Ok(ack) if ack.accepted => {
                    result.succeeded = true;
                    result.last_error = None;
                    return result;
                }
                Ok(ack) => {
                    result.observed_latest_version =
                        ack.metadata.map(|metadata| metadata.slot_version);
                    result.last_error = ack.reason.or(Some("legacy write rejected".to_owned()));
                }
                Err(error) => result.last_error = Some(error.to_string()),
            }
            if attempt + 1 < attempts {
                std::thread::sleep(Duration::from_millis(100_u64 << attempt.min(3)));
            }
        }
        result
    }
}
