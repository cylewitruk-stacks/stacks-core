// Copyright (C) 2024 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
#[cfg(test)]
use std::sync::LazyLock;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use libsigner::v0::messages::{
    BlockRejection, BlockResponse, MessageSlotID, RejectCode, SignerMessage as SignerMessageV0,
    StateMachineUpdate,
};
use libsigner::v0::signer_state::{GlobalStateEvaluator, SignerStateMachine};
use libsigner::{SignerEntries, SignerEvent};
use stacks::burnchains::{Burnchain, Txid};
use stacks::chainstate::burn::BlockSnapshot;
use stacks::chainstate::nakamoto::NakamotoBlockHeader;
use stacks::chainstate::stacks::boot::{NakamotoSignerEntry, RewardSet, SIGNERS_NAME};
use stacks::chainstate::stacks::events::StackerDBChunksEvent;
use stacks::chainstate::stacks::Error as ChainstateError;
use stacks::codec::StacksMessageCodec;
use stacks::net::api::postblock_proposal::ValidateRejectCode;
use stacks::net::stackerdb::StackerDBs;
use stacks::types::chainstate::{StacksAddress, StacksPublicKey};
use stacks::types::PublicKey;
use stacks::util::get_epoch_time_secs;
use stacks::util::hash::{MerkleHashFunc, Sha512Trunc256Sum};
use stacks::util::secp256k1::MessageSignature;
#[cfg(test)]
use stacks_common::util::tests::TestFlag;
use stacks_network_types::wire::v1::{ProposalUnavailable, SignerLane};
use stacks_signer_bridge::{
    BridgeJournal, LegacyChunkPolicy, LegacyLocator, TemporarySignerBridge,
};

use super::miner_db::MinerDB;
use super::Error as NakamotoNodeError;
use crate::event_dispatcher::StackerDBChannel;
use crate::Config;

#[cfg(test)]
/// Fault injection flag to prevent the miner from seeing enough signer signatures.
/// Used to test that the signers will broadcast a block if it gets enough signatures
pub static TEST_IGNORE_SIGNERS: LazyLock<TestFlag<bool>> = LazyLock::new(TestFlag::default);

/// How long should the coordinator poll on the event receiver before
/// waking up to check timeouts?
pub static EVENT_RECEIVER_POLL: Duration = Duration::from_millis(500);

/// Tracks per-txid rejection data from signers
#[derive(Debug, Clone, Default)]
pub struct FailedTxInfo {
    /// The total weight of signers who reported this txid as failed
    pub total_weight: u32,
    /// The weight of signers who specifically reported this txid as
    /// genuinely problematic (e.g. DDoS vector, parse error, Clarity crash)
    pub problematic_weight: u32,
}

#[derive(Debug, Clone)]
pub struct BlockStatus {
    /// Set of the slot ids of signers who have responded
    pub responded_signers: HashSet<u32>,
    /// Map of the slot id of signers who have signed the block and their signature
    pub gathered_signatures: BTreeMap<u32, MessageSignature>,
    /// Total weight of signers who have signed the block
    pub total_weight_approved: u32,
    /// Total weight of signers who have rejected the block
    pub total_weight_rejected: u32,
    /// Rejection weight attributable to reasons reconsidered on re-proposal.
    pub total_weight_rejected_transient: u32,
    /// Signer weight that explicitly could not evaluate this proposal. This
    /// carries no rejection weight and may later be replaced by a real vote.
    pub total_weight_unavailable: u32,
    /// Slots currently reporting temporary unavailability.
    pub unavailable_signers: HashSet<u32>,
    /// Per-txid rejection tracking from signers
    pub failed_txids: HashMap<Txid, FailedTxInfo>,
}

#[derive(Debug, Clone)]
pub(super) struct TimestampInfo {
    pub timestamp: u64,
    pub weight: u32,
}

/// Loads initial legacy signer state from the local replicated chunk store.
pub struct InitialChunksLoader<'a> {
    /// Reward cycle whose state is loaded.
    reward_cycle_id: u64,
    /// Number of registered signer slots.
    signer_count: u32,
    /// Local replicated chunk store.
    stacker_dbs: &'a StackerDBs,
}

impl<'a> InitialChunksLoader<'a> {
    /// Bind the initial state read to the local store and reward set.
    pub fn new(
        reward_cycle_id: u64,
        signer_count: u32,
        stacker_dbs: &'a StackerDBs,
    ) -> InitialChunksLoader<'a> {
        InitialChunksLoader {
            reward_cycle_id,
            signer_count,
            stacker_dbs,
        }
    }

    /// Read state updates in signer-slot order.
    fn load_chunks(&self, config: &Config) -> Vec<Option<Vec<u8>>> {
        if self.signer_count == 0 {
            return vec![];
        }

        // the contract that a SignerMessageProcessor actually cares about: The one with
        // the signer state machine updates
        let signers_contract = MessageSlotID::StateMachineUpdate
            .stacker_db_contract(config.is_mainnet(), self.reward_cycle_id);
        let slot_ids: Vec<u32> = (0..self.signer_count).collect();

        self.stacker_dbs
            .get_latest_chunks(&signers_contract, slot_ids.as_slice())
            .inspect_err(|e| warn!("Unable to read the latest signer state from signer db: {e}."))
            .unwrap_or_default()
    }
}

/// Transport-neutral signer message processor and weighted response state.
///
/// The optional legacy receiver is a quarantined compatibility source. Native
/// signer operation does not register a StackerDB channel, open a signer-slot
/// session, or spawn a polling thread.
pub struct SignerMessageProcessor {
    /// Legacy event channel retained only while compatibility ingress is enabled.
    stackerdb_channel: Option<Arc<Mutex<StackerDBChannel>>>,
    /// Receiver end of the optional legacy StackerDB event source.
    receiver: Option<Receiver<StackerDBChunksEvent>>,
    /// Flag to shut the node down
    node_keep_running: Arc<AtomicBool>,
    /// Flag to shut the listener down
    keep_running: Arc<AtomicBool>,
    /// The signer set for this tenure (0 or 1)
    signer_set: u32,
    /// The total weight of all signers
    pub(super) total_weight: u32,
    /// The weight threshold for block approval
    pub(super) weight_threshold: u32,
    /// The signer entries for this tenure (keyed by slot_id)
    signer_entries: HashMap<u32, NakamotoSignerEntry>,
    /// Tracks signatures for blocks
    ///   - key: Sha512Trunc256Sum (signer signature hash)
    ///   - value: BlockStatus
    pub(super) blocks: Arc<(Mutex<HashMap<Sha512Trunc256Sum, BlockStatus>>, Condvar)>,
    /// Tracks the timestamps from signers to decide when they should be
    /// willing to accept time-based tenure extensions
    ///  - key: StacksPublicKey
    ///  - value: TimestampInfo
    pub(super) signer_idle_timestamps: Arc<Mutex<HashMap<StacksPublicKey, TimestampInfo>>>,
    /// Tracks the timestamps from signers to decide when they should be
    /// willing to accept time-based read-count extensions
    ///  - key: StacksPublicKey
    ///  - value: TimestampInfo
    pub(super) signer_read_count_timestamps: Arc<Mutex<HashMap<StacksPublicKey, TimestampInfo>>>,
    /// Tracks the signer's global state machine through signer state machine update messages
    pub(super) global_state_evaluator: Arc<Mutex<GlobalStateEvaluator>>,
    /// Wehther we are operating on mainnet
    is_mainnet: bool,
    /// Quarantined verifier for legacy signer chunks. It emits local semantic
    /// events only and cannot manufacture native author signatures.
    compatibility_bridge: Option<TemporarySignerBridge>,
    /// Whether verified bridge events replace incumbent signer-message parsing.
    compatibility_bridge_emits_events: bool,
    /// Chainstate-derived contract/slot authorization for bridge ingress.
    compatibility_policy: ListenerBridgePolicy,
}

#[derive(Default)]
struct ListenerBridgePolicy {
    locators: HashMap<(String, u32), LegacyLocator>,
}

impl LegacyChunkPolicy for ListenerBridgePolicy {
    fn resolve(&self, contract: &str, slot_id: u32) -> Option<LegacyLocator> {
        self.locators.get(&(contract.to_owned(), slot_id)).cloned()
    }
}

/// Transport-neutral interface to the signer response accumulator.
pub struct SignerMessageProcessorComms {
    /// Tracks signatures for blocks
    ///   - key: Sha512Trunc256Sum (signer signature hash)
    ///   - value: BlockStatus
    blocks: Arc<(Mutex<HashMap<Sha512Trunc256Sum, BlockStatus>>, Condvar)>,
    /// Tracks the timestamps from signers to decide when they should be
    /// willing to accept time-based tenure extensions
    ///  - key: StacksPublicKey
    ///  - value: TimestampInfo
    signer_idle_timestamps: Arc<Mutex<HashMap<StacksPublicKey, TimestampInfo>>>,
    /// Tracks the timestamps from signers to decide when they should be
    /// willing to accept time-based read-count extensions
    ///  - key: StacksPublicKey
    ///  - value: TimestampInfo
    signer_read_count_timestamps: Arc<Mutex<HashMap<StacksPublicKey, TimestampInfo>>>,
    /// Tracks the signer's global state machine through signer state machine update messages
    global_state_evaluator: Arc<Mutex<GlobalStateEvaluator>>,
    /// Reward-set identity, slot, and weight used by native authenticated ingress.
    signer_entries_by_key: HashMap<StacksPublicKey, (u32, NakamotoSignerEntry)>,
    /// Total signer weight for rejection accounting.
    total_weight: u32,
    /// Approval threshold for this tenure.
    weight_threshold: u32,
    /// Address version used by the shared state-machine evaluator.
    is_mainnet: bool,
}

impl SignerMessageProcessor {
    pub fn new(
        stackerdb_channel: Arc<Mutex<StackerDBChannel>>,
        node_keep_running: Arc<AtomicBool>,
        keep_running: Arc<AtomicBool>,
        reward_set: &RewardSet,
        initial_chunks_loader: InitialChunksLoader,
        burn_tip: &BlockSnapshot,
        burnchain: &Burnchain,
        config: &Config,
    ) -> Result<Self, ChainstateError> {
        let legacy_ingress_enabled = config.node.libp2p.signer_bridge.mode.accepts_ingress();
        let receiver = if legacy_ingress_enabled {
            let (receiver, replaced_other) = stackerdb_channel
                .lock()
                .expect("FATAL: failed to lock StackerDB channel")
                .register_miner_coordinator();
            if replaced_other {
                warn!("Replaced the miner/coordinator receiver of a prior legacy signer adapter. Prior adapter may have crashed.");
            }
            Some(receiver)
        } else {
            None
        };

        let total_weight = reward_set.total_signing_weight().map_err(|e| {
            warn!("Failed to calculate total weight for the reward set: {e:?}");
            ChainstateError::NoRegisteredSigners(0)
        })?;

        let weight_threshold = NakamotoBlockHeader::compute_voting_weight_threshold(total_weight)?;

        let reward_cycle_id = burnchain
            .block_height_to_reward_cycle(burn_tip.block_height)
            .expect("FATAL: tried to initialize coordinator before first burn block height");
        let signer_set =
            u32::try_from(reward_cycle_id % 2).expect("FATAL: reward cycle id % 2 exceeds u32");

        let Some(reward_set_signers) = reward_set.signers() else {
            error!("Could not initialize signing coordinator for reward set without signer");
            debug!("reward set: {reward_set:?}");
            return Err(ChainstateError::NoRegisteredSigners(0));
        };

        let signer_entries = reward_set_signers
            .iter()
            .cloned()
            .enumerate()
            .map(|(idx, signer)| {
                let Ok(slot_id) = u32::try_from(idx) else {
                    return Err(ChainstateError::InvalidStacksBlock(
                        "Signer index exceeds u32".into(),
                    ));
                };
                Ok((slot_id, signer))
            })
            .collect::<Result<HashMap<_, _>, ChainstateError>>()?;

        let mut compatibility_policy = ListenerBridgePolicy::default();
        if legacy_ingress_enabled {
            for (slot_id, entry) in &signer_entries {
                let Ok(author_public_key) = entry.signing_key.as_slice().try_into() else {
                    continue;
                };
                for (lane, message_slot) in [
                    (SignerLane::BlockResponse, MessageSlotID::BlockResponse),
                    (
                        SignerLane::StateMachineUpdate,
                        MessageSlotID::StateMachineUpdate,
                    ),
                    (SignerLane::BlockPreCommit, MessageSlotID::BlockPreCommit),
                ] {
                    let locator = LegacyLocator {
                        contract: message_slot
                            .stacker_db_contract(config.is_mainnet(), reward_cycle_id)
                            .to_string(),
                        reward_cycle: reward_cycle_id,
                        lane,
                        slot_id: *slot_id,
                        author: stacks_signer_bridge::LegacyAuthor::PublicKey(author_public_key),
                        allow_epoch25: false,
                    };
                    compatibility_policy
                        .locators
                        .insert((locator.contract.clone(), *slot_id), locator);
                }
            }
        }
        let compatibility_bridge = if config.node.libp2p.signer_bridge.mode.accepts_ingress() {
            Some(
                TemporarySignerBridge::new(
                    config.node.libp2p.signer_bridge.clone(),
                    BridgeJournal::open(MinerDB::miner_db_path(config)).map_err(|error| {
                        ChainstateError::InvalidStacksBlock(format!(
                            "failed to open signer bridge journal: {error}"
                        ))
                    })?,
                )
                .map_err(|error| {
                    ChainstateError::InvalidStacksBlock(format!(
                        "failed to initialize signer bridge: {error}"
                    ))
                })?,
            )
        } else {
            None
        };

        let entries: Vec<_> = signer_entries.values().cloned().collect();
        let parsed_entries = SignerEntries::parse(config.is_mainnet(), &entries)
            .expect("FATAL: could not parse retrieved signer entries");
        let address_weights = parsed_entries.signer_addr_to_weight;
        let mut global_state_evaluator = GlobalStateEvaluator::new(HashMap::new(), address_weights);
        if legacy_ingress_enabled {
            let slot_ids: Vec<_> = (0..initial_chunks_loader.signer_count).collect();
            let chunks = initial_chunks_loader.load_chunks(config);
            for (chunk, slot_id) in chunks.into_iter().zip(slot_ids) {
                let Some(chunk) = chunk else {
                    continue;
                };
                let Some(signer_entry) = &signer_entries.get(&slot_id) else {
                    continue;
                };
                let Ok(signer_pubkey) = StacksPublicKey::from_slice(&signer_entry.signing_key)
                else {
                    continue;
                };
                let address = StacksAddress::p2pkh(config.is_mainnet(), &signer_pubkey);
                if let Some(update) = StateMachineUpdate::from_signer_message_chunk(&chunk) {
                    global_state_evaluator.insert_update(address, update);
                }
            }
        }

        Ok(Self {
            stackerdb_channel: legacy_ingress_enabled.then_some(stackerdb_channel),
            receiver,
            node_keep_running,
            keep_running,
            signer_set,
            total_weight,
            weight_threshold,
            signer_entries,
            blocks: Arc::new((Mutex::new(HashMap::new()), Condvar::new())),
            signer_idle_timestamps: Arc::new(Mutex::new(HashMap::new())),
            global_state_evaluator: Arc::new(Mutex::new(global_state_evaluator)),
            is_mainnet: config.is_mainnet(),
            signer_read_count_timestamps: Arc::new(Mutex::new(HashMap::new())),
            compatibility_bridge,
            compatibility_bridge_emits_events: config.node.libp2p.signer_bridge.mode.emits_events(),
            compatibility_policy,
        })
    }

    pub fn get_comms(&self) -> SignerMessageProcessorComms {
        SignerMessageProcessorComms {
            blocks: self.blocks.clone(),
            signer_idle_timestamps: self.signer_idle_timestamps.clone(),
            global_state_evaluator: self.global_state_evaluator.clone(),
            signer_read_count_timestamps: self.signer_read_count_timestamps.clone(),
            signer_entries_by_key: self
                .signer_entries
                .iter()
                .filter_map(|(slot_id, entry)| {
                    StacksPublicKey::from_slice(&entry.signing_key)
                        .ok()
                        .map(|key| (key, (*slot_id, entry.clone())))
                })
                .collect(),
            total_weight: self.total_weight,
            weight_threshold: self.weight_threshold,
            is_mainnet: self.is_mainnet,
        }
    }

    pub fn has_legacy_event_source(&self) -> bool {
        self.receiver.is_some()
    }

    /// Run the optional legacy signer event adapter.
    pub fn run(&mut self) -> Result<(), NakamotoNodeError> {
        info!("Legacy signer event adapter: starting up");

        let Some(receiver) = &self.receiver else {
            return Err(NakamotoNodeError::SigningCoordinatorFailure(
                "legacy signer adapter has no event receiver".into(),
            ));
        };

        loop {
            // was the node asked to stop?
            if !self.node_keep_running.load(Ordering::SeqCst) {
                info!("Legacy signer adapter: received node exit request. Aborting");
                return Ok(());
            }

            // was the listener asked to stop?
            if !self.keep_running.load(Ordering::SeqCst) {
                info!("Legacy signer adapter: received adapter exit request. Aborting");
                return Ok(());
            }

            let event = match receiver.recv_timeout(EVENT_RECEIVER_POLL) {
                Ok(event) => event,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    debug!("Legacy signer adapter: no StackerDB event received; polling again");
                    continue;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    warn!("Legacy signer adapter: StackerDB event receiver disconnected");
                    return Err(NakamotoNodeError::SigningCoordinatorFailure(
                        "StackerDB event receiver disconnected".into(),
                    ));
                }
            };

            // check to see if this event we got is a signer event
            let is_signer_event =
                event.contract_id.name.starts_with(SIGNERS_NAME) && event.contract_id.is_boot();

            if !is_signer_event {
                debug!("Legacy signer adapter: ignoring StackerDB event for non-signer contract"; "contract" => %event.contract_id);
                continue;
            }

            let modified_slots = event.modified_slots.clone();
            let mut bridged_messages = Vec::new();
            if let Some(bridge) = self.compatibility_bridge.as_mut() {
                let contract = event.contract_id.to_string();
                for chunk in &event.modified_slots {
                    let authenticated = match bridge.ingest(
                        &contract,
                        chunk,
                        &self.compatibility_policy,
                        get_epoch_time_secs(),
                    ) {
                        Ok(Some(event)) if !event.is_equivocation => event,
                        Ok(_) => continue,
                        Err(error) => {
                            warn!("Legacy signer adapter: compatibility bridge rejected signer chunk";
                                "contract" => contract.clone(),
                                "slot_id" => chunk.slot_id,
                                "error" => error.to_string(),
                            );
                            continue;
                        }
                    };
                    let Some(author) = authenticated.author_public_key() else {
                        continue;
                    };
                    let Ok(author) = StacksPublicKey::from_slice(author) else {
                        continue;
                    };
                    let mut payload = authenticated.message.payload.as_slice();
                    let Ok(message) = SignerMessageV0::consensus_deserialize(&mut payload) else {
                        continue;
                    };
                    if payload.is_empty() {
                        bridged_messages.push((chunk.slot_id, author, message));
                    }
                }
            }
            let (signer_set, messages) = if self.compatibility_bridge_emits_events {
                (self.signer_set, bridged_messages)
            } else {
                let Ok(signer_event) = SignerEvent::<SignerMessageV0>::try_from(event).map_err(|e| {
                    warn!("Legacy signer adapter: failed to parse StackerDB event; ignoring message"; "err" => ?e);
                }) else {
                    continue;
                };
                let SignerEvent::SignerMessages {
                    signer_set,
                    messages,
                    ..
                } = signer_event
                else {
                    debug!("Legacy signer adapter: ignoring non-message signer event");
                    continue;
                };
                (signer_set, messages)
            };
            if signer_set != self.signer_set {
                debug!("Legacy signer adapter: ignoring event for another reward cycle");
                continue;
            };
            let slot_ids = modified_slots
                .into_iter()
                .map(|chunk| chunk.slot_id)
                .collect::<Vec<_>>();

            debug!("Legacy signer adapter: received authenticated signer messages";
                "count" => messages.len(),
                "slot_ids" => ?slot_ids,
            );

            for (_slot_id, signer_pubkey, message) in messages.into_iter() {
                self.get_comms()
                    .process_authenticated_message(&signer_pubkey, message);
            }
        }
    }

    /// Do we ignore signer signatures?
    #[cfg(test)]
    fn fault_injection_ignore_signatures() -> bool {
        TEST_IGNORE_SIGNERS.get()
    }

    #[cfg(not(test))]
    fn fault_injection_ignore_signatures() -> bool {
        false
    }
}

impl Drop for SignerMessageProcessor {
    fn drop(&mut self) {
        let (Some(stackerdb_channel), Some(receiver)) =
            (self.stackerdb_channel.as_ref(), self.receiver.take())
        else {
            return;
        };
        stackerdb_channel
            .lock()
            .expect("FATAL: failed to lock legacy signer channel")
            .replace_receiver(receiver);
    }
}

impl SignerMessageProcessorComms {
    /// Apply one authenticated semantic signer message, independent of its
    /// carrier. Legacy chunks reach this method only after the compatibility
    /// adapter has verified and translated them; native envelopes reach it
    /// after transport binding and reward-set authorization.
    pub fn process_authenticated_message(
        &self,
        signer_pubkey: &StacksPublicKey,
        message: SignerMessageV0,
    ) {
        match message {
            SignerMessageV0::BlockResponse(response) => {
                self.process_authenticated_block_response(signer_pubkey, response)
            }
            SignerMessageV0::StateMachineUpdate(update) => {
                let mut evaluator = self
                    .global_state_evaluator
                    .lock()
                    .expect("FATAL: failed to lock global state evaluator");
                evaluator
                    .insert_update(StacksAddress::p2pkh(self.is_mainnet, signer_pubkey), update);
            }
            SignerMessageV0::BlockProposal(_)
            | SignerMessageV0::BlockPushed(_)
            | SignerMessageV0::BlockPreCommit(_)
            | SignerMessageV0::MockSignature(_)
            | SignerMessageV0::MockProposal(_)
            | SignerMessageV0::MockBlock(_) => {
                debug!("Ignoring signer message that does not affect the miner accumulator");
            }
        }
    }

    /// Insert a block into the block status map with initial values.
    pub fn insert_block(&self, block: &NakamotoBlockHeader) {
        let (lock, _cvar) = &*self.blocks;
        let mut blocks = lock.lock().expect("FATAL: failed to lock block status");
        let block_status = BlockStatus {
            responded_signers: HashSet::new(),
            gathered_signatures: BTreeMap::new(),
            total_weight_approved: 0,
            total_weight_rejected: 0,
            total_weight_rejected_transient: 0,
            total_weight_unavailable: 0,
            unavailable_signers: HashSet::new(),
            failed_txids: HashMap::new(),
        };
        blocks.insert(block.signer_signature_hash(), block_status);
    }

    /// Apply one end-to-end authenticated native block response to the incumbent
    /// weighted status accumulator. Dual-path duplicates are idempotent by slot.
    pub fn process_authenticated_block_response(
        &self,
        signer_pubkey: &StacksPublicKey,
        response: BlockResponse,
    ) {
        let Some((slot_id, signer_entry)) = self.signer_entries_by_key.get(signer_pubkey) else {
            warn!("Native block response author is not in the active reward set");
            return;
        };
        let transient_rejection = matches!(&response, BlockResponse::Rejected(rejected) if rejected.response_data.reject_reason.is_transient());
        let (sighash, approved, signature, tenure_timestamp, read_count_timestamp, failed_tx) =
            match response {
                BlockResponse::Accepted(accepted) => {
                    let valid = signer_pubkey
                        .verify(accepted.signer_signature_hash.bits(), &accepted.signature)
                        .unwrap_or(false);
                    if !valid {
                        warn!("Native block acceptance carries an invalid inner signature");
                        return;
                    }
                    (
                        accepted.signer_signature_hash,
                        true,
                        Some(accepted.signature),
                        accepted.response_data.tenure_extend_timestamp,
                        accepted.response_data.tenure_extend_read_count_timestamp,
                        None,
                    )
                }
                BlockResponse::Rejected(rejected) => {
                    if rejected.chain_id != BlockRejection::chain_id_for_network(self.is_mainnet) {
                        warn!("Ignoring signer rejection for another network");
                        return;
                    }
                    if rejected.recover_public_key().ok().as_ref() != Some(signer_pubkey) {
                        warn!("Native block rejection inner author does not match its envelope");
                        return;
                    }
                    let failed_tx = rejected.response_data.failed_txid.clone().and_then(|txid| {
                        let problematic = matches!(
                            rejected.reason_code,
                            RejectCode::ValidationFailed(
                                ValidateRejectCode::ProblematicTransaction
                            )
                        );
                        matches!(
                            rejected.reason_code,
                            RejectCode::ValidationFailed(
                                ValidateRejectCode::BadTransaction
                                    | ValidateRejectCode::ProblematicTransaction
                            )
                        )
                        .then_some((txid, problematic))
                    });
                    (
                        rejected.signer_signature_hash,
                        false,
                        None,
                        rejected.response_data.tenure_extend_timestamp,
                        rejected.response_data.tenure_extend_read_count_timestamp,
                        failed_tx,
                    )
                }
            };

        let (lock, cvar) = &*self.blocks;
        let mut blocks = lock.lock().expect("FATAL: failed to lock block status");
        let Some(block) = blocks.get_mut(&sighash) else {
            debug!("Native block response is for an unrequested proposal";
                "signer_signature_hash" => %sighash,
                "signer_slot_id" => slot_id,
            );
            return;
        };
        if approved && SignerMessageProcessor::fault_injection_ignore_signatures() {
            warn!("Fault injection: ignoring authenticated signer approval";
                "signer_signature_hash" => %sighash,
                "signer_pubkey" => signer_pubkey.to_hex(),
                "signer_slot_id" => slot_id,
            );
            return;
        }
        if !block.responded_signers.insert(*slot_id) {
            return;
        }
        if block.unavailable_signers.remove(slot_id) {
            block.total_weight_unavailable = block
                .total_weight_unavailable
                .saturating_sub(signer_entry.weight);
        }
        if approved {
            block.total_weight_approved = block
                .total_weight_approved
                .saturating_add(signer_entry.weight);
            block.gathered_signatures.insert(
                *slot_id,
                signature.expect("approved responses always carry a signature"),
            );
        } else {
            block.total_weight_rejected = block
                .total_weight_rejected
                .saturating_add(signer_entry.weight);
            if transient_rejection {
                block.total_weight_rejected_transient = block
                    .total_weight_rejected_transient
                    .saturating_add(signer_entry.weight);
            }
            if let Some((txid, problematic)) = failed_tx {
                let info = block.failed_txids.entry(txid).or_default();
                info.total_weight = info.total_weight.saturating_add(signer_entry.weight);
                if problematic {
                    info.problematic_weight =
                        info.problematic_weight.saturating_add(signer_entry.weight);
                }
            }
        }
        info!("Applied authenticated semantic signer block response";
            "signer_signature_hash" => %sighash,
            "signer_pubkey" => signer_pubkey.to_hex(),
            "signer_slot_id" => slot_id,
            "approved" => approved,
            "signer_weight" => signer_entry.weight,
            "total_weight_approved" => block.total_weight_approved,
            "total_weight_rejected" => block.total_weight_rejected,
            "total_weight_unavailable" => block.total_weight_unavailable,
            "weight_threshold" => self.weight_threshold,
        );
        stacks::monitoring::record_libp2p_signer_vote(
            &sighash.to_string(),
            signer_pubkey.to_hex(),
            signer_entry.weight,
            approved,
            block.total_weight_approved,
            block.total_weight_rejected,
            block.total_weight_unavailable,
        );
        if block.total_weight_approved >= self.weight_threshold
            || block
                .total_weight_rejected
                .saturating_add(self.weight_threshold)
                > self.total_weight
        {
            cvar.notify_all();
        }
        drop(blocks);

        for (timestamps, timestamp) in [
            (&self.signer_idle_timestamps, tenure_timestamp),
            (&self.signer_read_count_timestamps, read_count_timestamp),
        ] {
            let mut timestamps = timestamps.lock().expect("FATAL: timestamp mutex poisoned");
            if timestamps
                .get(signer_pubkey)
                .map_or(true, |existing| timestamp > existing.timestamp)
            {
                timestamps.insert(
                    signer_pubkey.clone(),
                    TimestampInfo {
                        timestamp,
                        weight: signer_entry.weight,
                    },
                );
            }
        }
    }

    /// Record a signed, versioned liveness outcome without treating it as a
    /// consensus rejection. A later acceptance/rejection from the same signer
    /// replaces this temporary state.
    pub fn process_authenticated_unavailable(
        &self,
        signer_pubkey: &StacksPublicKey,
        unavailable: &ProposalUnavailable,
        envelope_reward_cycle: u64,
    ) {
        if stacks_network_types::validate_proposal_unavailable(unavailable, envelope_reward_cycle)
            .is_err()
        {
            warn!("Rejected malformed proposal-unavailable outcome");
            return;
        }
        let Some(sighash) = Sha512Trunc256Sum::from_vec(&unavailable.signer_signature_hash) else {
            return;
        };
        let Some((slot_id, signer_entry)) = self.signer_entries_by_key.get(signer_pubkey) else {
            warn!("Proposal-unavailable author is not in the active reward set");
            return;
        };
        let (lock, cvar) = &*self.blocks;
        let mut blocks = lock.lock().expect("FATAL: failed to lock block status");
        let Some(block) = blocks.get_mut(&sighash) else {
            return;
        };
        if block.responded_signers.contains(slot_id) || !block.unavailable_signers.insert(*slot_id)
        {
            return;
        }
        block.total_weight_unavailable = block
            .total_weight_unavailable
            .saturating_add(signer_entry.weight);
        info!("Applied authenticated proposal-unavailable outcome";
            "signer_signature_hash" => %sighash,
            "signer_slot_id" => slot_id,
            "signer_weight" => signer_entry.weight,
            "total_weight_unavailable" => block.total_weight_unavailable,
        );
        stacks::monitoring::record_libp2p_signer_unavailable(
            &sighash.to_string(),
            signer_pubkey.to_hex(),
            signer_entry.weight,
            block.total_weight_unavailable,
        );
        if block
            .total_weight_unavailable
            .saturating_add(self.weight_threshold)
            > self.total_weight
        {
            cvar.notify_all();
        }
    }

    /// Reset rejections for a block proposal.
    /// This is used when a block proposal times out and we need to retry it by
    /// clearing the block's rejections. Block approvals cannot be cleared
    /// because an old approval could always be used to make a block reach
    /// the approval threshold.
    pub fn reset_rejections(&self, signer_sighash: &Sha512Trunc256Sum) {
        let (lock, _cvar) = &*self.blocks;
        let mut blocks = lock.lock().expect("FATAL: failed to lock block status");
        if let Some(block) = blocks.get_mut(signer_sighash) {
            block.responded_signers.clear();
            block.total_weight_rejected = 0;
            block.total_weight_rejected_transient = 0;
            block.unavailable_signers.clear();
            block.total_weight_unavailable = 0;

            // Add approving signers back to the responded signers set
            for (slot_id, _) in block.gathered_signatures.iter() {
                block.responded_signers.insert(*slot_id);
            }
        }
        drop(blocks);
        stacks::monitoring::reset_libp2p_signer_rejections(&signer_sighash.to_string());
    }

    /// Clear only retryable liveness observations for the same proposal.
    /// Approvals and validity rejections remain attributable and cumulative.
    pub fn reset_unavailable(&self, signer_sighash: &Sha512Trunc256Sum) {
        let (lock, _cvar) = &*self.blocks;
        let mut blocks = lock.lock().expect("FATAL: failed to lock block status");
        if let Some(block) = blocks.get_mut(signer_sighash) {
            block.unavailable_signers.clear();
            block.total_weight_unavailable = 0;
        }
        drop(blocks);
        stacks::monitoring::reset_libp2p_signer_unavailable(&signer_sighash.to_string());
    }

    /// Get the status for `block` from the semantic signer processor.
    /// If the block is not found in the map, return an error.
    /// If the block is found, call `condition` to check if the block status
    /// satisfies the condition.
    /// If the condition is satisfied, return the block status as
    ///   `Ok(Some(status))`.
    /// If the condition is not satisfied, wait for it to be satisfied.
    /// If the timeout is reached, return `Ok(None)`.
    pub fn wait_for_block_status<F>(
        &self,
        block_signer_sighash: &Sha512Trunc256Sum,
        timeout: Duration,
        condition: F,
    ) -> Result<Option<BlockStatus>, NakamotoNodeError>
    where
        F: Fn(&BlockStatus) -> bool,
    {
        let (lock, cvar) = &*self.blocks;
        let blocks = lock.lock().expect("FATAL: failed to lock block status");

        let (guard, timeout_result) = cvar
            .wait_timeout_while(blocks, timeout, |map| {
                let Some(status) = map.get(block_signer_sighash) else {
                    return true;
                };
                condition(status)
            })
            .expect("FATAL: failed to wait on block status cond var");

        // If we timed out, return None
        if timeout_result.timed_out() {
            return Ok(None);
        }
        match guard.get(block_signer_sighash) {
            Some(status) => Ok(Some(status.clone())),
            None => Err(NakamotoNodeError::SigningCoordinatorFailure(
                "Block not found in status map".into(),
            )),
        }
    }

    /// Get the timestamp at which at least 70% of the signing power should be
    /// willing to accept a time-based tenure extension.
    pub fn get_tenure_extend_timestamp(&self, weight_threshold: u32) -> u64 {
        let signer_idle_timestamps = self
            .signer_idle_timestamps
            .lock()
            .expect("FATAL: failed to lock signer idle timestamps");
        debug!("SignerCoordinator: signer_idle_timestamps: {signer_idle_timestamps:?}");
        Self::find_weighted_timestamp_by_threshold(
            weight_threshold,
            signer_idle_timestamps.values(),
        )
    }

    /// Get the timestamp at which at least 70% of the signing power should be
    /// willing to accept a time-based tenure extension.
    pub fn get_read_count_extend_timestamp(&self, weight_threshold: u32) -> u64 {
        let signer_read_count_timestamps = self
            .signer_read_count_timestamps
            .lock()
            .expect("FATAL: failed to lock signer idle timestamps");
        debug!("SignerCoordinator: signer_read_count_timestamps: {signer_read_count_timestamps:?}");
        Self::find_weighted_timestamp_by_threshold(
            weight_threshold,
            signer_read_count_timestamps.values(),
        )
    }

    fn find_weighted_timestamp_by_threshold<'a, T: Iterator<Item = &'a TimestampInfo>>(
        weight_threshold: u32,
        timestamps: T,
    ) -> u64 {
        let mut timestamps: Vec<_> = timestamps.collect();
        timestamps.sort_by_key(|info| info.timestamp);
        let mut weight_sum = 0;
        for info in timestamps {
            weight_sum += info.weight;
            if weight_sum >= weight_threshold {
                debug!("SignerCoordinator: threshold reached for tenure extension timestamp";
                       "weight_threshold" => weight_threshold,
                       "tenure_extend_timestamp" => info.timestamp,
                       "tenure_extend_in" => (info.timestamp as i64 - get_epoch_time_secs() as i64)
                );
                return info.timestamp;
            }
        }

        // We don't have enough information to reach a threshold at any
        // time, so return u64::MAX to indicate that we should not extend the
        // tenure.
        u64::MAX
    }

    /// Get the global state if there is one
    pub fn get_signer_global_state(&self) -> Option<SignerStateMachine> {
        let eval = self
            .global_state_evaluator
            .lock()
            .expect("FATAL: failed to lock global state evaluator");
        eval.determine_global_state()
    }
}

#[cfg(test)]
mod unavailable_tests {
    use libsigner::v0::messages::{
        BlockAccepted, BlockRejection, BlockResponseData, RejectReason, SignerMessageMetadata,
    };
    use stacks::net::api::postblock_proposal::{BlockValidateReject, ValidateRejectCode};
    use stacks::types::chainstate::StacksPrivateKey;
    use stacks::types::PrivateKey;
    use stacks_network_types::wire::v1::ProposalUnavailableReason;
    use stacks_network_types::PROPOSAL_UNAVAILABLE_VERSION;

    use super::*;

    fn comms(
        signer_key: &StacksPrivateKey,
        sighash: Sha512Trunc256Sum,
    ) -> SignerMessageProcessorComms {
        let signer_pubkey = StacksPublicKey::from_private(signer_key);
        let signer_entry = NakamotoSignerEntry {
            signing_key: signer_pubkey
                .to_bytes_compressed()
                .try_into()
                .expect("compressed signer key"),
            stacked_amt: 1,
            weight: 3,
        };
        let status = BlockStatus {
            responded_signers: HashSet::new(),
            gathered_signatures: BTreeMap::new(),
            total_weight_approved: 0,
            total_weight_rejected: 0,
            total_weight_rejected_transient: 0,
            total_weight_unavailable: 0,
            unavailable_signers: HashSet::new(),
            failed_txids: HashMap::new(),
        };
        SignerMessageProcessorComms {
            blocks: Arc::new((
                Mutex::new(HashMap::from([(sighash, status)])),
                Condvar::new(),
            )),
            signer_idle_timestamps: Arc::new(Mutex::new(HashMap::new())),
            signer_read_count_timestamps: Arc::new(Mutex::new(HashMap::new())),
            global_state_evaluator: Arc::new(Mutex::new(GlobalStateEvaluator::new(
                HashMap::new(),
                HashMap::new(),
            ))),
            signer_entries_by_key: HashMap::from([(signer_pubkey, (0, signer_entry))]),
            total_weight: 3,
            weight_threshold: 3,
            is_mainnet: false,
        }
    }

    #[test]
    fn unavailable_never_rejects_and_a_later_vote_replaces_it() {
        let signer_key = StacksPrivateKey::from_seed(b"temporary-unavailable-signer");
        let signer_pubkey = StacksPublicKey::from_private(&signer_key);
        let sighash = Sha512Trunc256Sum::from_data(b"proposal");
        let comms = comms(&signer_key, sighash.clone());
        let unavailable = ProposalUnavailable {
            version: PROPOSAL_UNAVAILABLE_VERSION,
            signer_signature_hash: sighash.as_bytes().to_vec(),
            reward_cycle: 4,
            reason: ProposalUnavailableReason::CompanionTimeout as i32,
        };

        comms.process_authenticated_unavailable(&signer_pubkey, &unavailable, 5);
        let status = comms
            .wait_for_block_status(&sighash, Duration::ZERO, |_| false)
            .unwrap()
            .expect("status exists");
        assert_eq!(status.total_weight_unavailable, 0);

        comms.process_authenticated_unavailable(&signer_pubkey, &unavailable, 4);
        comms.process_authenticated_unavailable(&signer_pubkey, &unavailable, 4);
        let status = comms
            .wait_for_block_status(&sighash, Duration::ZERO, |_| false)
            .unwrap()
            .expect("status exists");
        assert_eq!(status.total_weight_unavailable, 3);
        assert_eq!(status.total_weight_rejected, 0);
        assert!(status.responded_signers.is_empty());

        {
            let mut blocks = comms.blocks.0.lock().unwrap();
            let status = blocks.get_mut(&sighash).unwrap();
            status.total_weight_rejected = 1;
            status.responded_signers.insert(9);
        }
        comms.reset_unavailable(&sighash);
        let status = comms
            .wait_for_block_status(&sighash, Duration::ZERO, |_| false)
            .unwrap()
            .expect("status exists");
        assert_eq!(status.total_weight_unavailable, 0);
        assert_eq!(status.total_weight_rejected, 1);
        assert_eq!(status.responded_signers, HashSet::from([9]));

        comms.process_authenticated_unavailable(&signer_pubkey, &unavailable, 4);

        let signature = signer_key.sign(sighash.bits()).unwrap();
        let accepted = BlockAccepted {
            signer_signature_hash: sighash.clone(),
            signature,
            metadata: SignerMessageMetadata::default(),
            response_data: BlockResponseData::empty(),
        };
        comms.process_authenticated_block_response(
            &signer_pubkey,
            BlockResponse::Accepted(accepted),
        );
        let status = comms
            .wait_for_block_status(&sighash, Duration::ZERO, |_| false)
            .unwrap()
            .expect("status exists");
        assert_eq!(status.total_weight_unavailable, 0);
        assert_eq!(status.total_weight_rejected, 1);
        assert_eq!(status.total_weight_approved, 3);
        assert_eq!(status.responded_signers, HashSet::from([0, 9]));
    }

    #[test]
    /// Both adapters share chain-domain checks and reset transient weight on retry.
    fn authenticated_rejections_check_chain_and_reset_transient_weight() {
        let key = StacksPrivateKey::from_seed(b"transient-rejection");
        let public_key = StacksPublicKey::from_private(&key);
        let header = NakamotoBlockHeader::empty();
        let hash = header.signer_signature_hash();
        let comms = comms(&key, hash.clone());
        for mainnet in [true, false] {
            let rejection = BlockRejection::new(
                hash.clone(),
                RejectReason::NoSignerConsensus,
                &key,
                mainnet,
                0,
                0,
            );
            for _ in 0..2 {
                comms.process_authenticated_message(
                    &public_key,
                    SignerMessageV0::BlockResponse(BlockResponse::Rejected(rejection.clone())),
                );
            }
            let status = comms
                .wait_for_block_status(&hash, Duration::ZERO, |_| false)
                .unwrap()
                .unwrap();
            let expected = if mainnet { 0 } else { 3 };
            assert_eq!(status.total_weight_rejected, expected);
            assert_eq!(status.total_weight_rejected_transient, expected);
            assert_eq!(status.responded_signers.len(), usize::from(!mainnet));
        }
        comms.reset_rejections(&hash);
        let status = comms
            .wait_for_block_status(&hash, Duration::ZERO, |_| false)
            .unwrap()
            .unwrap();
        assert_eq!(status.total_weight_rejected, 0);
        assert_eq!(status.total_weight_rejected_transient, 0);
        assert!(status.responded_signers.is_empty());
    }

    #[test]
    fn genuine_validation_rejection_survives_unavailable_reset_and_terminates_round() {
        let signer_key = StacksPrivateKey::from_seed(b"validation-rejecting-signer");
        let signer_pubkey = StacksPublicKey::from_private(&signer_key);
        let sighash = Sha512Trunc256Sum::from_data(b"invalid-proposal");
        let comms = comms(&signer_key, sighash.clone());
        let unavailable = ProposalUnavailable {
            version: PROPOSAL_UNAVAILABLE_VERSION,
            signer_signature_hash: sighash.as_bytes().to_vec(),
            reward_cycle: 4,
            reason: ProposalUnavailableReason::CompanionTimeout as i32,
        };
        comms.process_authenticated_unavailable(&signer_pubkey, &unavailable, 4);

        // Start with the companion's production response type and use the
        // same conversion the signer handler uses. Feeding that exact signed
        // response into the miner accumulator prevents this test from
        // silently proving only a synthetic policy rejection.
        let companion_rejection = BlockValidateReject {
            signer_signature_hash: sighash.clone(),
            reason: "companion rejected invalid proposal".try_into().unwrap(),
            reason_code: ValidateRejectCode::InvalidBlock,
            failed_txid: None,
        };
        let rejection =
            BlockRejection::from_validate_rejection(companion_rejection, &signer_key, false, 0, 0);
        assert_eq!(
            rejection.response_data.reject_reason,
            RejectReason::ValidationFailed(ValidateRejectCode::InvalidBlock)
        );
        comms.process_authenticated_block_response(
            &signer_pubkey,
            BlockResponse::Rejected(rejection),
        );
        comms.reset_unavailable(&sighash);

        let status = comms
            .wait_for_block_status(&sighash, Duration::ZERO, |_| false)
            .unwrap()
            .expect("status exists");
        assert_eq!(status.total_weight_unavailable, 0);
        assert_eq!(status.total_weight_rejected, 3);
        std::assert_matches!(
            crate::nakamoto_node::signer_coordinator::signer_rejection_error(&status, 3, 3),
            Some(NakamotoNodeError::SignersRejected { .. })
        );
    }
}
