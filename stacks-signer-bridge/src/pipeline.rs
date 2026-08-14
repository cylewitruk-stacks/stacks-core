use std::collections::VecDeque;
use std::io;
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::thread::JoinHandle;
use std::time::Duration;

use libsigner::SignerNetworkMessage;
use stacks_common::types::chainstate::StacksPrivateKey;

use crate::{LegacyWriteResult, PendingLegacyWrite, StackerDbLegacyWriter, TemporarySignerBridge};

const WRITE_ATTEMPTS: u32 = 3;
const MAX_OUTCOMES_PER_PUMP: usize = 256;
const MAX_WRITES_PER_PUMP: usize = 16;

trait LegacyWriteExecutor: Send + 'static {
    fn write(&mut self, pending: &PendingLegacyWrite) -> LegacyWriteResult;
}

impl LegacyWriteExecutor for StackerDbLegacyWriter {
    fn write(&mut self, pending: &PendingLegacyWrite) -> LegacyWriteResult {
        self.write(pending, WRITE_ATTEMPTS)
    }
}

#[derive(Debug)]
struct LegacyWriteOutcome {
    pending: PendingLegacyWrite,
    result: LegacyWriteResult,
}

/// A bounded, contextual warning produced while pumping compatibility writes.
/// Callers choose their logging facade but do not reimplement pipeline policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LegacyWritePipelineWarning {
    WriteFailed {
        contract: String,
        slot_id: u32,
        slot_version: u32,
        error: String,
    },
    OutcomePersistenceFailed(String),
    VersionFloorAdvanceFailed(String),
    VersionExhausted {
        contract: String,
        slot_id: u32,
    },
    RequeueFailed(String),
    WorkerDisconnected,
}

impl std::fmt::Display for LegacyWritePipelineWarning {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WriteFailed {
                contract,
                slot_id,
                slot_version,
                error,
            } => write!(
                formatter,
                "legacy write failed contract={contract} slot_id={slot_id} slot_version={slot_version}: {error}"
            ),
            Self::OutcomePersistenceFailed(error) => {
                write!(formatter, "failed to persist legacy write outcome: {error}")
            }
            Self::VersionFloorAdvanceFailed(error) => {
                write!(formatter, "failed to advance legacy version floor: {error}")
            }
            Self::VersionExhausted { contract, slot_id } => write!(
                formatter,
                "legacy version exhausted contract={contract} slot_id={slot_id}"
            ),
            Self::RequeueFailed(error) => {
                write!(formatter, "failed to requeue legacy write after version resync: {error}")
            }
            Self::WorkerDisconnected => formatter.write_str("legacy writer worker disconnected"),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LegacyWritePumpReport {
    pub outcomes_processed: usize,
    pub writes_submitted: usize,
    pub warnings: Vec<LegacyWritePipelineWarning>,
}

/// Owns the complete bounded lifecycle of the synchronous legacy HTTP writer.
///
/// Native callers enqueue through [`TemporarySignerBridge`]. `pump` transfers
/// those writes without blocking, records outcomes, and performs the one
/// permitted stale-version recovery. No caller can update one side of the
/// channel/retry/outcome state independently.
pub struct LegacyWritePipeline {
    writer: Option<SyncSender<PendingLegacyWrite>>,
    outcomes: Receiver<LegacyWriteOutcome>,
    retry: VecDeque<PendingLegacyWrite>,
    worker: Option<JoinHandle<()>>,
}

impl LegacyWritePipeline {
    pub fn disabled() -> Self {
        let (outcomes_tx, outcomes) = mpsc::sync_channel(1);
        drop(outcomes_tx);
        Self {
            writer: None,
            outcomes,
            retry: VecDeque::new(),
            worker: None,
        }
    }

    pub fn spawn(
        thread_name: impl Into<String>,
        node_host: String,
        timeout: Duration,
        queue_items: usize,
    ) -> io::Result<Self> {
        Self::spawn_with_executor(
            thread_name,
            StackerDbLegacyWriter::new(node_host, timeout),
            queue_items,
        )
    }

    fn spawn_with_executor(
        thread_name: impl Into<String>,
        executor: impl LegacyWriteExecutor,
        queue_items: usize,
    ) -> io::Result<Self> {
        if queue_items == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "legacy writer queue must be nonzero",
            ));
        }
        let (writer, writes) = mpsc::sync_channel(queue_items);
        let (outcomes_tx, outcomes) = mpsc::sync_channel(queue_items);
        let worker = std::thread::Builder::new()
            .name(thread_name.into())
            .spawn(move || run_writer(executor, writes, outcomes_tx))?;
        Ok(Self {
            writer: Some(writer),
            outcomes,
            retry: VecDeque::new(),
            worker: Some(worker),
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.writer.is_some()
    }

    /// Drop retry state outside the active reward-cycle window. The bridge
    /// applies the same rule to writes it still owns.
    pub fn retain_cycles(&mut self, current: u64, next: Option<u64>) {
        self.retry.retain(|write| {
            write.locator.reward_cycle == current || Some(write.locator.reward_cycle) == next
        });
    }

    pub fn pump(
        &mut self,
        bridge: &mut TemporarySignerBridge,
        author: &StacksPrivateKey,
        observed_at: u64,
    ) -> LegacyWritePumpReport {
        let mut report = LegacyWritePumpReport::default();
        for _ in 0..MAX_OUTCOMES_PER_PUMP {
            let outcome = match self.outcomes.try_recv() {
                Ok(outcome) => outcome,
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            };
            report.outcomes_processed += 1;
            self.apply_outcome(bridge, author, observed_at, outcome, &mut report);
        }

        let Some(writer) = self.writer.as_ref() else {
            return report;
        };
        for _ in 0..MAX_WRITES_PER_PUMP {
            let pending = self.retry.pop_front().or_else(|| bridge.try_next_write());
            let Some(pending) = pending else {
                break;
            };
            match writer.try_send(pending) {
                Ok(()) => report.writes_submitted += 1,
                Err(TrySendError::Full(pending)) => {
                    self.retry.push_front(pending);
                    break;
                }
                Err(TrySendError::Disconnected(pending)) => {
                    self.retry.push_front(pending);
                    self.writer = None;
                    report
                        .warnings
                        .push(LegacyWritePipelineWarning::WorkerDisconnected);
                    break;
                }
            }
        }
        report
    }

    fn apply_outcome(
        &mut self,
        bridge: &mut TemporarySignerBridge,
        author: &StacksPrivateKey,
        observed_at: u64,
        outcome: LegacyWriteOutcome,
        report: &mut LegacyWritePumpReport,
    ) {
        let pending = outcome.pending;
        let result = outcome.result;
        if !result.succeeded {
            report
                .warnings
                .push(LegacyWritePipelineWarning::WriteFailed {
                    contract: pending.locator.contract.clone(),
                    slot_id: pending.locator.slot_id,
                    slot_version: pending.chunk.slot_version,
                    error: result
                        .last_error
                        .clone()
                        .unwrap_or_else(|| "legacy writer returned no reason".to_owned()),
                });
        }
        if let Err(error) =
            bridge.record_write_outcome(pending.chunk_id, result.succeeded, observed_at)
        {
            report
                .warnings
                .push(LegacyWritePipelineWarning::OutcomePersistenceFailed(
                    error.to_string(),
                ));
        }
        if result.succeeded {
            return;
        }
        let Some(latest) = result.observed_latest_version else {
            return;
        };
        let Some(next_version) = latest.checked_add(1) else {
            report
                .warnings
                .push(LegacyWritePipelineWarning::VersionExhausted {
                    contract: pending.locator.contract,
                    slot_id: pending.locator.slot_id,
                });
            return;
        };
        if let Err(error) = bridge.advance_legacy_version_floor(
            &pending.locator.contract,
            pending.locator.slot_id,
            next_version,
        ) {
            report
                .warnings
                .push(LegacyWritePipelineWarning::VersionFloorAdvanceFailed(
                    error.to_string(),
                ));
            return;
        }
        let message = SignerNetworkMessage {
            reward_cycle: pending.locator.reward_cycle,
            lane: pending.locator.lane,
            burn_view_consensus_hash: Vec::new(),
            payload: pending.chunk.data,
        };
        if let Err(error) = bridge.enqueue_origin_egress(
            &message,
            pending.native_envelope_id,
            pending.locator,
            author,
            observed_at,
        ) {
            report
                .warnings
                .push(LegacyWritePipelineWarning::RequeueFailed(error.to_string()));
        }
    }

    /// Close the producer, keep draining outcomes while the worker finishes,
    /// and join it. The callback is invoked with exclusive pipeline access so
    /// the owner can pump its bridge and record contextual warnings.
    pub fn shutdown(&mut self, mut pump: impl FnMut(&mut Self)) -> std::thread::Result<()> {
        pump(self);
        self.writer.take();
        let Some(worker) = self.worker.take() else {
            pump(self);
            return Ok(());
        };
        while !worker.is_finished() {
            pump(self);
            std::thread::sleep(Duration::from_millis(10));
        }
        pump(self);
        worker.join()
    }
}

fn run_writer(
    mut executor: impl LegacyWriteExecutor,
    writes: Receiver<PendingLegacyWrite>,
    outcomes: SyncSender<LegacyWriteOutcome>,
) {
    while let Ok(pending) = writes.recv() {
        let result = executor.write(&pending);
        if outcomes
            .send(LegacyWriteOutcome { pending, result })
            .is_err()
        {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use clarity::codec::StacksMessageCodec;
    use libsigner::v0::messages::SignerMessage;
    use stacks_common::types::chainstate::StacksPublicKey;
    use stacks_common::util::hash::Sha512Trunc256Sum;
    use stacks_network_types::wire::v1::SignerLane;
    use tempfile::TempDir;

    use super::*;
    use crate::{
        BridgeJournal, LegacyAuthor, LegacyLocator, SignerBridgeConfig, TemporarySignerBridge,
    };

    struct ScriptedWriter(VecDeque<LegacyWriteResult>);

    impl LegacyWriteExecutor for ScriptedWriter {
        fn write(&mut self, _pending: &PendingLegacyWrite) -> LegacyWriteResult {
            self.0.pop_front().expect("one scripted result per write")
        }
    }

    fn fixture() -> (
        TempDir,
        TemporarySignerBridge,
        StacksPrivateKey,
        LegacyLocator,
        SignerNetworkMessage,
    ) {
        let tempdir = TempDir::new().unwrap();
        let key = StacksPrivateKey::from_seed(&[91; 32]);
        let locator = LegacyLocator {
            contract: "ST000000000000000000002AMW42H.signers-0-3".to_owned(),
            reward_cycle: 12,
            lane: SignerLane::BlockPreCommit,
            slot_id: 4,
            author: LegacyAuthor::PublicKey(
                StacksPublicKey::from_private(&key)
                    .to_bytes_compressed()
                    .try_into()
                    .unwrap(),
            ),
            allow_epoch25: false,
        };
        let mut payload = Vec::new();
        SignerMessage::BlockPreCommit(Sha512Trunc256Sum([7; 32]))
            .consensus_serialize(&mut payload)
            .unwrap();
        let message = SignerNetworkMessage {
            reward_cycle: locator.reward_cycle,
            lane: locator.lane,
            burn_view_consensus_hash: Vec::new(),
            payload,
        };
        let bridge = TemporarySignerBridge::new(
            SignerBridgeConfig::default(),
            BridgeJournal::open(tempdir.path().join("bridge.sqlite")).unwrap(),
        )
        .unwrap();
        (tempdir, bridge, key, locator, message)
    }

    #[test]
    fn disabled_pipeline_has_no_writer() {
        assert!(!LegacyWritePipeline::disabled().is_enabled());
    }

    #[test]
    fn worker_success_is_recorded_during_owned_shutdown() {
        let (_tempdir, mut bridge, key, locator, message) = fixture();
        bridge
            .enqueue_origin_egress(&message, None, locator, &key, 1)
            .unwrap();
        let writer = ScriptedWriter(VecDeque::from([LegacyWriteResult {
            succeeded: true,
            observed_latest_version: None,
            last_error: None,
        }]));
        let mut pipeline =
            LegacyWritePipeline::spawn_with_executor("bridge-test", writer, 1).unwrap();
        let mut reports = Vec::new();
        pipeline
            .shutdown(|pipeline| reports.push(pipeline.pump(&mut bridge, &key, 2)))
            .unwrap();
        assert_eq!(bridge.diagnostics().egress_succeeded, 1);
        assert_eq!(bridge.diagnostics().egress_failed, 0);
        assert!(reports.iter().all(|report| report.warnings.is_empty()));
    }

    #[test]
    fn stale_version_requeues_at_observed_floor() {
        let (_tempdir, mut bridge, key, locator, message) = fixture();
        bridge
            .enqueue_origin_egress(&message, None, locator, &key, 1)
            .unwrap();
        let pending = bridge.try_next_write().unwrap();
        let (writer, writes) = mpsc::sync_channel(1);
        let (outcomes_tx, outcomes) = mpsc::sync_channel(1);
        outcomes_tx
            .send(LegacyWriteOutcome {
                pending,
                result: LegacyWriteResult {
                    succeeded: false,
                    observed_latest_version: Some(8),
                    last_error: Some("stale".to_owned()),
                },
            })
            .unwrap();
        let mut pipeline = LegacyWritePipeline {
            writer: Some(writer),
            outcomes,
            retry: VecDeque::new(),
            worker: None,
        };
        let report = pipeline.pump(&mut bridge, &key, 2);
        assert_eq!(report.outcomes_processed, 1);
        assert_eq!(report.writes_submitted, 1);
        assert!(matches!(
            report.warnings.as_slice(),
            [LegacyWritePipelineWarning::WriteFailed { .. }]
        ));
        assert_eq!(writes.recv().unwrap().chunk.slot_version, 9);
        assert_eq!(bridge.diagnostics().egress_failed, 1);
    }
}
