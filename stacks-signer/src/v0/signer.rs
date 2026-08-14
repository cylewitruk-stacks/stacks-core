// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::mpsc::Sender;
#[cfg(any(test, feature = "testing"))]
use std::sync::LazyLock;
use std::time::{Duration, Instant, SystemTime};

use blockstack_lib::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader};
use blockstack_lib::net::api::postblock_proposal::{
    BlockValidateOk, BlockValidateReject, BlockValidateResponse, ValidateRejectCode,
    TOO_MANY_REQUESTS_STATUS,
};
use blockstack_lib::util_lib::db::Error as DBError;
use clarity::codec::StacksMessageCodec;
use clarity::types::chainstate::{StacksBlockId, StacksPrivateKey};
use clarity::types::PrivateKey;
use clarity::util::hash::{MerkleHashFunc, Sha512Trunc256Sum};
use clarity::util::secp256k1::Secp256k1PublicKey;
#[cfg(any(test, feature = "testing"))]
use clarity::util::sleep_ms;
#[cfg(any(test, feature = "testing"))]
use clarity::util::tests::TestFlag;
use libsigner::v0::messages::{
    BlockAccepted, BlockRejection, BlockResponse, RejectReason, RejectReasonPrefix, SignerMessage,
    StateMachineUpdate,
};
use libsigner::v0::signer_state::GlobalStateEvaluator;
use libsigner::{BlockProposal, SignerEvent, SignerNetworkMessage};
use prost::Message as ProstMessage;
use stacks_common::types::chainstate::{StacksAddress, StacksPublicKey};
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::secp256k1::MessageSignature;
use stacks_common::{debug, error, info, warn};
use stacks_network_types::wire::v1::{ProposalUnavailable, ProposalUnavailableReason, SignerLane};
use stacks_network_types::PROPOSAL_UNAVAILABLE_VERSION;

use super::signer_state::LocalStateMachine;
use crate::chainstate::v1::{SortitionMinerStatus, SortitionsView};
use crate::chainstate::v2::GlobalStateView;
use crate::chainstate::{ProposalEvalConfig, SortitionData, SortitionStateVersion};
use crate::client::{ClientError, SignerSlotID, StacksClient};
use crate::config::{SignerConfig, SignerConfigMode};
use crate::network::SignerNetworkHandle;
use crate::runloop::SignerResult;
use crate::signerdb::{BlockInfo, BlockState, PendingBlockResponses, SignerDb};
#[cfg(not(any(test, feature = "testing")))]
use crate::v0::signer_state::SUPPORTED_SIGNER_PROTOCOL_VERSION;
use crate::v0::signer_state::{NewBurnBlock, ReplayScopeOpt};
use crate::Signer as SignerTrait;

/// A global variable that can be used to make signers repeat their proposal
/// response if their public key is in the provided list
#[cfg(any(test, feature = "testing"))]
pub static TEST_REPEAT_PROPOSAL_RESPONSE: LazyLock<TestFlag<Vec<StacksPublicKey>>> =
    LazyLock::new(TestFlag::default);

const STATE_UPDATE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

/// Bounds repeated publication attempts while making reconstructed signer
/// state independent of one-shot startup and GossipSub mesh timing.
#[derive(Debug, Default)]
struct StateUpdateHeartbeat {
    last_attempt: Option<Instant>,
}

impl StateUpdateHeartbeat {
    fn due(&self, now: Instant) -> bool {
        self.last_attempt.is_none_or(|last_attempt| {
            now.saturating_duration_since(last_attempt) >= STATE_UPDATE_HEARTBEAT_INTERVAL
        })
    }

    fn record_attempt(&mut self, now: Instant) {
        self.last_attempt = Some(now);
    }
}

/// Signer running mode (whether dry-run or real)
#[derive(Debug)]
pub enum SignerMode {
    /// Dry run operation: signer is not actually registered, the signer
    ///  will not submit stackerdb messages, etc.
    DryRun,
    /// Normal signer operation: if registered, the signer will submit
    /// stackerdb messages, etc.
    Normal {
        /// The signer ID assigned to this signer (may be different from signer_slot_id)
        signer_id: u32,
    },
}

/// Track N most recently processed block identifiers
pub struct RecentlyProcessedBlocks<const N: usize> {
    blocks: Vec<StacksBlockId>,
    write_head: usize,
}

/// The stacks signer registered for the reward cycle
#[derive(Debug)]
pub struct Signer {
    /// The private key of the signer
    #[cfg(any(test, feature = "testing"))]
    pub private_key: StacksPrivateKey,
    #[cfg(not(any(test, feature = "testing")))]
    /// The private key of the signer
    private_key: StacksPrivateKey,
    /// The signer address
    pub stacks_address: StacksAddress,
    /// Native signer transport. Legacy translation, when explicitly enabled,
    /// is owned exclusively by the quarantined process-wide bridge.
    signer_network: Option<SignerNetworkHandle>,
    /// Whether the signer is a mainnet signer or not
    pub mainnet: bool,
    /// The running mode of the signer (whether dry-run or normal)
    pub mode: SignerMode,
    /// The signer slot ids for the signers in the reward cycle
    pub signer_slot_ids: Vec<SignerSlotID>,
    /// The addresses of other signers
    pub signer_addresses: Vec<StacksAddress>,
    /// The reward cycle this signer belongs to
    pub reward_cycle: u64,
    /// Reward set signer addresses and their weights
    pub signer_weights: HashMap<StacksAddress, u32>,
    /// SignerDB for state management
    pub signer_db: SignerDb,
    /// Configuration for proposal evaluation
    pub proposal_config: ProposalEvalConfig,
    /// How long to wait for a block proposal validation response to arrive before
    /// marking a submitted block as invalid
    pub block_proposal_validation_timeout: Duration,
    /// The current submitted block proposal and its submission time
    pub submitted_block_proposal: Option<(Sha512Trunc256Sum, Instant)>,
    /// Maximum age of a block proposal in seconds before it is dropped without processing
    pub block_proposal_max_age_secs: u64,
    /// The signer's local state machine used in signer set agreement
    pub local_state_machine: LocalStateMachine,
    /// Cache of stacks block IDs for blocks recently processed by our stacks-node
    recently_processed: RecentlyProcessedBlocks<100>,
    /// The signer's global state evaluator
    pub global_state_evaluator: GlobalStateEvaluator,
    state_update_heartbeat: StateUpdateHeartbeat,
    /// Whether to validate blocks with replay transactions
    pub validate_with_replay_tx: bool,
    /// Scope of Tx Replay in terms of Burn block boundaries
    pub tx_replay_scope: ReplayScopeOpt,
    /// The number of blocks after the past tip to reset the replay set
    pub reset_replay_set_after_fork_blocks: u64,
    /// Time to wait between updating our local state machine view point and capitulating to other signers miner view
    pub capitulate_miner_view_timeout: Duration,
    /// The last time we capitulated our miner viewpoint
    pub last_capitulate_miner_view: SystemTime,
    /// The signer supported protocol version. used only in testing
    #[cfg(any(test, feature = "testing"))]
    pub supported_signer_protocol_version: u64,
}

impl std::fmt::Display for SignerMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignerMode::DryRun => write!(f, "Dry-Run signer"),
            SignerMode::Normal { signer_id } => write!(f, "Signer #{signer_id}"),
        }
    }
}

impl std::fmt::Display for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Cycle #{} {}", self.reward_cycle, self.mode)
    }
}

impl<const N: usize> std::fmt::Debug for RecentlyProcessedBlocks<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RecentlyProcessed({:?})", self.blocks)
    }
}

impl<const N: usize> Default for RecentlyProcessedBlocks<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> RecentlyProcessedBlocks<N> {
    /// Construct a new recently processed blocks cache
    pub fn new() -> Self {
        Self {
            blocks: Vec::with_capacity(N),
            write_head: 0,
        }
    }

    /// Is `block` known to have been processed by our stacks-node?
    pub fn is_processed(&self, block: &StacksBlockId) -> bool {
        self.blocks.contains(block)
    }

    /// Add a block that we know has been processed by our stacks-node
    pub fn add_block(&mut self, block: StacksBlockId) {
        if self.blocks.len() < N {
            self.blocks.push(block);
            return;
        }
        let Some(location) = self.blocks.get_mut(self.write_head) else {
            warn!(
                "Failed to cache processing information about {block}, write_head {} was improperly set for cache size {N} with blocks length {}",
                self.write_head,
                self.blocks.len()
            );
            return;
        };
        *location = block;
        self.write_head = (self.write_head + 1) % self.blocks.len();
    }
}

impl SignerTrait<SignerMessage> for Signer {
    /// Create a new signer from the given configuration
    fn new(stacks_client: &StacksClient, signer_config: SignerConfig) -> Self {
        let mode = match signer_config.signer_mode {
            SignerConfigMode::DryRun => SignerMode::DryRun,
            SignerConfigMode::Normal { signer_id, .. } => SignerMode::Normal { signer_id },
        };

        debug!("Reward cycle #{} {mode}", signer_config.reward_cycle);

        let mut signer_db =
            SignerDb::new(&signer_config.db_path).expect("Failed to connect to signer Db");
        let proposal_config = ProposalEvalConfig::from(&signer_config);

        let stacks_address = StacksAddress::p2pkh(
            signer_config.mainnet,
            &StacksPublicKey::from_private(&signer_config.stacks_private_key),
        );

        let updates = signer_db
            .get_signer_state_machine_updates(signer_config.reward_cycle)
            .inspect_err(|e| {
                warn!("An error occurred retrieving state machine updates from the db: {e}")
            })
            .unwrap_or_default();

        let global_state_evaluator = GlobalStateEvaluator::new(
            updates,
            signer_config.signer_entries.signer_addr_to_weight.clone(),
        );
        #[cfg(any(test, feature = "testing"))]
        let version = signer_config.supported_signer_protocol_version;
        #[cfg(not(any(test, feature = "testing")))]
        let version = SUPPORTED_SIGNER_PROTOCOL_VERSION;
        let signer_state = LocalStateMachine::new(
            &signer_db,
            stacks_client,
            &proposal_config,
            &global_state_evaluator,
            version,
        )
        .unwrap_or_else(|e| {
            warn!("Failed to initialize local state machine for signer: {e:?}");
            LocalStateMachine::Uninitialized
        });
        crate::monitoring::actions::record_local_state(signer_state.clone());
        Self {
            private_key: signer_config.stacks_private_key,
            stacks_address,
            signer_network: None,
            mainnet: signer_config.mainnet,
            mode,
            signer_addresses: signer_config.signer_entries.signer_addresses.clone(),
            signer_weights: signer_config.signer_entries.signer_addr_to_weight.clone(),
            signer_slot_ids: signer_config.signer_slot_ids.clone(),
            reward_cycle: signer_config.reward_cycle,
            signer_db,
            proposal_config,
            submitted_block_proposal: None,
            block_proposal_validation_timeout: signer_config.block_proposal_validation_timeout,
            block_proposal_max_age_secs: signer_config.block_proposal_max_age_secs,
            local_state_machine: signer_state,
            recently_processed: RecentlyProcessedBlocks::new(),
            global_state_evaluator,
            state_update_heartbeat: StateUpdateHeartbeat::default(),
            validate_with_replay_tx: signer_config.validate_with_replay_tx,
            tx_replay_scope: None,
            reset_replay_set_after_fork_blocks: signer_config.reset_replay_set_after_fork_blocks,
            capitulate_miner_view_timeout: signer_config.capitulate_miner_view_timeout,
            last_capitulate_miner_view: SystemTime::now(),
            #[cfg(any(test, feature = "testing"))]
            supported_signer_protocol_version: signer_config.supported_signer_protocol_version,
        }
    }

    /// Return the reward cycle of the signer
    fn reward_cycle(&self) -> u64 {
        self.reward_cycle
    }

    fn set_signer_network(&mut self, network: Option<SignerNetworkHandle>) {
        self.signer_network = network;
        // A signer can reconstruct its local state from its node and database
        // without observing a state transition. Publish that reconstructed
        // state as soon as the native network becomes available so a
        // simultaneous signer-set restart cannot deadlock waiting for the
        // first post-restart transition. The native journal persists the
        // envelope before dissemination, so peers joining after this call can
        // recover it through signer replay even when no gossip mesh exists yet.
        if self.signer_network.is_some() {
            self.send_signer_update_message(self.get_signer_protocol_version());
        }
    }

    /// Process the event
    fn process_event(
        &mut self,
        stacks_client: &StacksClient,
        sortition_state: &mut Option<SortitionsView>,
        event: Option<&SignerEvent<SignerMessage>>,
        _res: &Sender<SignerResult>,
        current_reward_cycle: u64,
    ) {
        self.check_submitted_block_proposal();
        self.check_pending_block_validations(stacks_client);

        let mut prior_state = self.local_state_machine.clone();
        let local_signer_protocol_version = self.get_signer_protocol_version();
        if self.reward_cycle <= current_reward_cycle {
            self.local_state_machine.handle_pending_update(&self.signer_db, stacks_client,
                &self.proposal_config,
                &mut self.tx_replay_scope, &self.global_state_evaluator, local_signer_protocol_version)
                .unwrap_or_else(|e| error!("{self}: failed to update local state machine for pending update"; "err" => ?e));
        }
        // See if we should capitulate our viewpoint...
        self.local_state_machine.capitulate_viewpoint(
            stacks_client,
            &mut self.signer_db,
            &mut self.global_state_evaluator,
            local_signer_protocol_version,
            sortition_state,
            self.capitulate_miner_view_timeout,
            self.proposal_config.tenure_last_block_proposal_timeout,
            &mut self.last_capitulate_miner_view,
        );

        if prior_state != self.local_state_machine {
            let version = self.get_signer_protocol_version();
            self.send_signer_update_message(version);
            prior_state = self.local_state_machine.clone();
        }
        if self.state_update_heartbeat.due(Instant::now()) {
            self.send_signer_update_message(self.get_signer_protocol_version());
        }
        crate::monitoring::actions::record_local_state(self.local_state_machine.clone());

        let event_parity = match event {
            // Block proposal events do have reward cycles, but each proposal has its own cycle,
            //  and the vec could be heterogeneous, so, don't differentiate.
            Some(SignerEvent::BlockValidationResponse(_))
            | Some(SignerEvent::MinerMessages(..))
            | Some(SignerEvent::NewBurnBlock { .. })
            | Some(SignerEvent::NewBlock { .. })
            | Some(SignerEvent::StatusCheck)
            | None => None,
            Some(SignerEvent::SignerMessages { signer_set, .. }) => {
                Some(u64::from(*signer_set) % 2)
            }
        };
        let other_signer_parity = (self.reward_cycle + 1) % 2;
        if event_parity == Some(other_signer_parity) {
            return;
        }
        debug!("{self}: Processing event: {event:?}");
        let Some(event) = event else {
            // No event. Do nothing.
            debug!("{self}: No event received");
            return;
        };
        if self.reward_cycle > current_reward_cycle
            && !matches!(
                event,
                SignerEvent::StatusCheck | SignerEvent::NewBurnBlock { .. }
            )
        {
            // The reward cycle has not yet started for this signer instance
            // Do not process any events other than status checks or new burn blocks
            debug!("{self}: Signer reward cycle has not yet started. Ignoring event.");
            return;
        }

        self.handle_event_match(stacks_client, sortition_state, event);

        self.check_submitted_block_proposal();
        self.check_pending_block_validations(stacks_client);

        if prior_state != self.local_state_machine {
            let version = self.get_signer_protocol_version();
            self.send_signer_update_message(version);
        }
        crate::monitoring::actions::record_local_state(self.local_state_machine.clone());
    }

    fn has_unprocessed_blocks(&self) -> bool {
        self.signer_db
            .has_unprocessed_blocks(self.reward_cycle)
            .unwrap_or_else(|e| {
                error!("{self}: Failed to check for pending blocks: {e:?}",);
                // Assume we have pending blocks to prevent premature cleanup
                true
            })
    }

    fn get_local_state_machine(&self) -> &LocalStateMachine {
        &self.local_state_machine
    }

    #[cfg(not(any(test, feature = "testing")))]
    fn get_pending_proposals_count(&self) -> u64 {
        0
    }

    #[cfg(any(test, feature = "testing"))]
    fn get_pending_proposals_count(&self) -> u64 {
        self.signer_db
            .get_all_pending_block_validations()
            .map(|results| u64::try_from(results.len()).unwrap())
            .unwrap_or(0)
    }

    fn get_canonical_tip(&self) -> Option<BlockInfo> {
        self.signer_db
            .get_canonical_tip()
            .inspect_err(|e| error!("{self}: Failed to check for canonical tip: {e:?}"))
            .ok()
            .flatten()
    }
}

impl Signer {
    fn burn_view_consensus_hash(&self) -> Vec<u8> {
        let state = match &self.local_state_machine {
            LocalStateMachine::Initialized(state) => Some(state),
            LocalStateMachine::Pending { prior, .. } => Some(prior),
            LocalStateMachine::Uninitialized => None,
        };
        state
            .map(|state| state.burn_block.as_bytes().to_vec())
            .unwrap_or_default()
    }

    fn publish_semantic_message(&self, message: &SignerMessage) {
        let Some(network) = self.signer_network.as_ref() else {
            return;
        };
        if !network.accepts_local_publication() {
            return;
        }
        if matches!(self.mode, SignerMode::DryRun) {
            return;
        }
        let lane = match message {
            SignerMessage::BlockResponse(_) => SignerLane::BlockResponse,
            SignerMessage::BlockPreCommit(_) => SignerLane::BlockPreCommit,
            SignerMessage::StateMachineUpdate(_) => SignerLane::StateMachineUpdate,
            SignerMessage::BlockProposal(_) => SignerLane::BlockProposal,
            SignerMessage::BlockPushed(_) => SignerLane::BlockPushed,
            SignerMessage::MockSignature(_)
            | SignerMessage::MockProposal(_)
            | SignerMessage::MockBlock(_) => {
                debug!("Skipping historical epoch-2.5 message on semantic signer transport");
                return;
            }
        };
        let result = network.publish(SignerNetworkMessage {
            reward_cycle: self.reward_cycle,
            lane,
            burn_view_consensus_hash: self.burn_view_consensus_hash(),
            payload: message.serialize_to_vec(),
        });
        match result {
            Ok(receipt) => info!(
                "Queued semantic signer message";
                "reward_cycle" => self.reward_cycle,
                "lane" => ?lane,
                "envelope_id" => ?receipt.envelope_id,
            ),
            Err(error) => warn!(
                "Failed to queue semantic signer message";
                "reward_cycle" => self.reward_cycle,
                "lane" => ?lane,
                "error" => %error,
            ),
        }
    }

    fn publish_proposal_unavailable(
        &self,
        signer_signature_hash: &Sha512Trunc256Sum,
        reason: ProposalUnavailableReason,
    ) {
        crate::monitoring::actions::increment_block_validation_abstentions();
        let Some(network) = self.signer_network.as_ref() else {
            return;
        };
        if !network.accepts_local_publication() || matches!(self.mode, SignerMode::DryRun) {
            return;
        }
        let unavailable = ProposalUnavailable {
            version: PROPOSAL_UNAVAILABLE_VERSION,
            signer_signature_hash: signer_signature_hash.0.to_vec(),
            reward_cycle: self.reward_cycle,
            reason: reason as i32,
        };
        if let Err(error) = network.publish(SignerNetworkMessage {
            reward_cycle: self.reward_cycle,
            lane: SignerLane::ProposalUnavailable,
            burn_view_consensus_hash: self.burn_view_consensus_hash(),
            payload: unavailable.encode_to_vec(),
        }) {
            warn!("Failed to publish proposal-unavailable outcome";
                "signer_signature_hash" => %signer_signature_hash,
                "reason" => ?reason,
                "error" => %error,
            );
        }
    }

    fn send_signer_update_message(&mut self, version: u64) {
        self.state_update_heartbeat.record_attempt(Instant::now());
        let update = match self
            .local_state_machine
            .try_into_update_message_with_version(version)
        {
            Ok(update) => update,
            Err(error) => {
                warn!("Failed to convert local signer state to a signer message: {error:?}");
                return;
            }
        };
        let message = SignerMessage::StateMachineUpdate(update);
        self.publish_semantic_message(&message);
    }

    /// Determine this signers response to a proposed block
    /// Returns a BlockResponse if we have already validated the block
    /// Returns None otherwise
    fn determine_response(&mut self, block_info: &BlockInfo) -> Option<BlockResponse> {
        // We will only have the valid field set if we have already validated this block
        // against our stacks-node/local state.
        let valid = block_info.valid?;
        let response = if valid {
            debug!("{self}: Accepting block {}", block_info.block.block_id());
            self.create_block_acceptance(&block_info.block).into()
        } else {
            debug!("{self}: Rejecting block {}", block_info.block.block_id());
            self.create_block_rejection(RejectReason::RejectedInPriorRound, &block_info.block)
                .into()
        };
        Some(response)
    }

    /// Create a block acceptance for a block
    pub fn create_block_acceptance(&self, block: &NakamotoBlock) -> BlockAccepted {
        let signature = self
            .private_key
            .sign(block.header.signer_signature_hash().bits())
            .expect("Failed to sign block");
        BlockAccepted::new(
            block.header.signer_signature_hash(),
            signature,
            self.signer_db.calculate_full_extend_timestamp(
                self.proposal_config
                    .tenure_idle_timeout
                    .saturating_add(self.proposal_config.tenure_idle_timeout_buffer),
                block,
                true,
            ),
            self.signer_db.calculate_read_count_extend_timestamp(
                self.proposal_config
                    .read_count_idle_timeout
                    .saturating_add(self.proposal_config.tenure_idle_timeout_buffer),
                block,
                true,
            ),
        )
    }

    /// The actual switch-on-event processing of an event.
    /// This is separated from the Signer trait implementation of process_event
    /// so that the "do on every event" functionality can run after every event processing
    /// (i.e. even if the event_match does an early return).
    fn handle_event_match(
        &mut self,
        stacks_client: &StacksClient,
        sortition_state: &mut Option<SortitionsView>,
        event: &SignerEvent<SignerMessage>,
    ) {
        match event {
            SignerEvent::BlockValidationResponse(block_validate_response) => {
                debug!("{self}: Received a block proposal result from the stacks node...");
                self.handle_block_validate_response(
                    stacks_client,
                    block_validate_response,
                    sortition_state,
                )
            }
            SignerEvent::SignerMessages {
                received_time,
                messages,
                ..
            } => {
                debug!(
                    "{self}: Received {} messages from the other signers",
                    messages.len()
                );
                // try and gather signatures
                for (_slot_id, signer_public_key, message) in messages {
                    let signer_address = StacksAddress::p2pkh(self.mainnet, signer_public_key);
                    if !self.is_valid_signer(&signer_address) {
                        debug!("{self}: Received a message from an unknown signer. Ignoring...";
                            "signer_public_key" => ?signer_public_key,
                            "signer_address" => %signer_address,
                            "message" => ?message,
                        );
                        continue;
                    }
                    match message {
                        SignerMessage::BlockResponse(block_response) => {
                            #[cfg(any(test, feature = "testing"))]
                            if self.test_ignore_all_block_responses(block_response) {
                                continue;
                            }
                            self.handle_block_response(
                                stacks_client,
                                block_response,
                                sortition_state,
                            )
                        }
                        SignerMessage::StateMachineUpdate(update) => self
                            .handle_state_machine_update(signer_public_key, update, received_time),
                        SignerMessage::BlockPreCommit(signer_signature_hash) => {
                            #[cfg(any(test, feature = "testing"))]
                            if self
                                .test_ignore_all_pre_commits(&signer_address, signer_signature_hash)
                            {
                                continue;
                            }
                            self.handle_block_pre_commit(
                                stacks_client,
                                &signer_address,
                                signer_signature_hash,
                            )
                        }
                        _ => {}
                    }
                }
            }
            SignerEvent::MinerMessages(messages) => {
                debug!(
                    "{self}: Received {} messages from the miner",
                    messages.len();
                );
                for message in messages {
                    match message {
                        SignerMessage::BlockProposal(block_proposal) => {
                            #[cfg(any(test, feature = "testing"))]
                            if self.test_ignore_all_block_proposals(block_proposal) {
                                continue;
                            }
                            #[cfg(any(test, feature = "testing"))]
                            if self.test_insert_block_proposal_without_processing(block_proposal) {
                                continue;
                            }
                            self.handle_block_proposal(
                                stacks_client,
                                sortition_state,
                                block_proposal,
                            );
                        }
                        SignerMessage::BlockPushed(b) => {
                            // This will infinitely loop until the block is acknowledged by the node
                            info!(
                                "{self}: Got block pushed message";
                                "block_id" => %b.block_id(),
                                "block_height" => b.header.chain_length,
                                "signer_signature_hash" => %b.header.signer_signature_hash(),
                            );
                            self.handle_post_block(stacks_client, b);
                        }
                        SignerMessage::MockProposal(_) => {
                            // Epoch 2.5 mock-signing is historical wire
                            // compatibility, not an active signer protocol.
                            // The test-only incumbent adapter retains codec
                            // coverage; current signers never publish it.
                            debug!("Ignoring historical epoch-2.5 mock proposal");
                        }
                        _ => {}
                    }
                }
            }
            SignerEvent::StatusCheck => {
                debug!("{self}: Received a status check event.");
            }
            SignerEvent::NewBurnBlock {
                burn_height,
                burn_header_hash,
                consensus_hash,
                received_time,
                parent_burn_block_hash,
            } => {
                info!("{self}: Received a new burn block event for block height {burn_height}");
                self.signer_db
                    .insert_burn_block(
                        burn_header_hash,
                        consensus_hash,
                        *burn_height,
                        received_time,
                        parent_burn_block_hash,
                    )
                    .unwrap_or_else(|e| {
                        error!(
                            "Failed to write burn block event to signerdb";
                            "err" => ?e,
                            "burn_header_hash" => %burn_header_hash,
                            "burn_height" => burn_height
                        );
                        panic!("{self} Failed to write burn block event to signerdb: {e}");
                    });

                let active_signer_protocol_version = self.get_signer_protocol_version();
                self.local_state_machine
                    .bitcoin_block_arrival(&self.signer_db, stacks_client, &self.proposal_config, Some(NewBurnBlock {
                        burn_block_height: *burn_height,
                        consensus_hash: consensus_hash.clone(),
                    }),
                    &mut self.tx_replay_scope
                , &self.global_state_evaluator, active_signer_protocol_version)
                    .unwrap_or_else(|e| error!("{self}: failed to update local state machine for latest bitcoin block arrival"; "err" => ?e));
                *sortition_state = None;
            }
            SignerEvent::NewBlock {
                block_height,
                block_id,
                consensus_hash,
                signer_sighash,
                transactions,
            } => {
                #[cfg(any(test, feature = "testing"))]
                if self.test_ignore_all_block_announcements(
                    *block_height,
                    block_id,
                    consensus_hash,
                    signer_sighash,
                    transactions,
                ) {
                    return;
                }

                let Some(signer_sighash) = signer_sighash else {
                    debug!(
                        "{self}: received a new block event for a pre-nakamoto block, no processing necessary"
                    );
                    return;
                };
                self.recently_processed.add_block(block_id.clone());
                info!(
                    "{self}: Received a new block event.";
                    "block_id" => %block_id,
                    "signer_signature_hash" => %signer_sighash,
                    "consensus_hash" => %consensus_hash,
                    "block_height" => block_height,
                    "total_txs" => transactions.len()
                );
                self.local_state_machine
                    .stacks_block_arrival(consensus_hash, *block_height, block_id, signer_sighash, &self.signer_db, transactions)
                    .unwrap_or_else(|e| error!("{self}: failed to update local state machine for latest stacks block arrival"; "err" => ?e));

                if let Ok(Some(mut block_info)) = self
                    .signer_db
                    .block_lookup(signer_sighash)
                    .inspect_err(|e| warn!("{self}: Failed to load block state: {e:?}"))
                {
                    if block_info.state == BlockState::GloballyAccepted {
                        // We have already globally accepted this block. Do nothing.
                        return;
                    }
                    if let Err(e) = block_info.mark_globally_accepted() {
                        warn!("{self}: Failed to mark block as globally accepted: {e:?}");
                        return;
                    }
                    if let Err(e) = self.signer_db.insert_block(&block_info) {
                        warn!("{self}: Failed to update block state to globally accepted: {e:?}");
                    }
                }
            }
        }
    }

    /// Create a block rejection response for a block with the given reject code
    pub fn create_block_rejection(
        &self,
        reject_reason: RejectReason,
        block: &NakamotoBlock,
    ) -> BlockRejection {
        BlockRejection::new(
            block.header.signer_signature_hash(),
            reject_reason,
            &self.private_key,
            self.mainnet,
            self.signer_db.calculate_full_extend_timestamp(
                self.proposal_config
                    .tenure_idle_timeout
                    .saturating_add(self.proposal_config.tenure_idle_timeout_buffer),
                block,
                false,
            ),
            self.signer_db.calculate_read_count_extend_timestamp(
                self.proposal_config
                    .read_count_idle_timeout
                    .saturating_add(self.proposal_config.tenure_idle_timeout_buffer),
                block,
                false,
            ),
        )
    }

    /// Check some heuristics to see if our stacks-node has processed the parent of `block`.
    ///  Note: this can be wrong in both directions. It may return false for some blocks that
    ///  have been processed, and it may return true for some blocks that have not been processed.
    ///  The caller should not depend on this being 100% accurate.
    fn maybe_processed_parent(&self, client: &StacksClient, block: &NakamotoBlock) -> bool {
        let parent_block_id = &block.header.parent_block_id;
        if self.recently_processed.is_processed(parent_block_id) {
            return true;
        }
        let Ok(peer_info) = client.get_peer_info().inspect_err(|e| {
            warn!(
                "Failed to fetch stacks-node peer info, assuming block not processed yet";
                "error" => ?e
            )
        }) else {
            return false;
        };

        // if our stacks node has processed block height >= block proposal's parent
        //  return true
        peer_info.stacks_tip_height >= block.header.chain_length.saturating_sub(1)
    }

    /// Get the global signer protocol version
    fn determine_active_signer_protocol_version(&mut self) -> Option<SortitionStateVersion> {
        let local_version = self.get_signer_protocol_version();
        if let Ok(update) = self
            .local_state_machine
            .try_into_update_message_with_version(local_version)
        {
            self.global_state_evaluator
                .insert_update(self.stacks_address.clone(), update);
        };
        let local_state_version = SortitionStateVersion::from_protocol_version(local_version);
        self
            .global_state_evaluator
            .determine_latest_supported_signer_protocol_version().map(|version| {
                SortitionStateVersion::from_protocol_version(version)
            })
            .or_else(|| {
                // Don't default if we are in a global consensus activation state as its pointless
                if local_state_version.uses_global_state() {
                    None
                } else {
                    warn!("{self}: No consensus on signer protocol version. Defaulting to local state version: {local_version}.");
                    Some(local_state_version)
                }
            })
    }

    /// Check if block should be rejected based on the appropriate state (either local or global)
    /// Will return a BlockRejection if the block is invalid, none otherwise.
    fn check_block_against_state(
        &mut self,
        stacks_client: &StacksClient,
        sortition_state: &mut Option<SortitionsView>,
        block_info: &BlockInfo,
    ) -> Option<BlockRejection> {
        // First update our global state evaluator with our local state if we have one
        let local_version = self.get_signer_protocol_version();
        if let Ok(update) = self
            .local_state_machine
            .try_into_update_message_with_version(local_version)
        {
            self.global_state_evaluator
                .insert_update(self.stacks_address.clone(), update);
        };
        let Some(state_version) = self.determine_active_signer_protocol_version() else {
            warn!(
                "{self}: No consensus on signer protocol version. Unable to validate block. Rejecting.";
                "signer_signature_hash" => %block_info.block.header.signer_signature_hash(),
                "block_id" => %block_info.block.block_id(),
            );
            return Some(
                self.create_block_rejection(RejectReason::NoSignerConsensus, &block_info.block),
            );
        };

        // reject if the block itself is malformed
        if !block_info.check_static_valid_block() {
            debug!("{self}: Block is syntatically invalid; will not process");
            return Some(self.create_block_rejection(
                RejectReason::ValidationFailed(ValidateRejectCode::InvalidBlock),
                &block_info.block,
            ));
        }

        // For this first version, reject any block that marks transactions as
        // problematic. The criteria for what may legitimately appear in
        // `problematic_txs` has not been decided yet, so signers reject all
        // such blocks until that policy is established.
        if !block_info.block.header.problematic_txs.is_empty() {
            warn!(
                "{self}: Block proposal marks transactions as problematic, which signers do not yet allow; rejecting";
                "signer_signature_hash" => %block_info.block.header.signer_signature_hash(),
                "block_id" => %block_info.block.block_id(),
                "problematic_tx_count" => block_info.block.header.problematic_txs.len(),
            );
            return Some(
                self.create_block_rejection(
                    RejectReason::ProblematicTransactions,
                    &block_info.block,
                ),
            );
        }

        if state_version.uses_global_state() {
            self.check_block_against_global_state(stacks_client, &block_info.block)
        } else {
            self.check_block_against_local_state(stacks_client, sortition_state, &block_info.block)
        }
    }

    /// Check if block should be rejected based on the local view of the sortition state
    /// Will return a BlockRejection if the block is invalid, none otherwise.
    /// This is the pre-global signer state activation path.
    fn check_block_against_local_state(
        &mut self,
        stacks_client: &StacksClient,
        sortition_state: &mut Option<SortitionsView>,
        block: &NakamotoBlock,
    ) -> Option<BlockRejection> {
        let signer_signature_hash = block.header.signer_signature_hash();
        let block_id = block.block_id();
        // Get sortition view if we don't have it
        if sortition_state.is_none() {
            *sortition_state =
                SortitionsView::fetch_view(self.proposal_config.clone(), stacks_client)
                    .inspect_err(|e| {
                        warn!(
                            "{self}: Failed to update sortition view: {e:?}";
                            "signer_signature_hash" => %signer_signature_hash,
                            "block_id" => %block_id,
                        )
                    })
                    .ok();
        }

        // Check if proposal can be rejected now if not valid against sortition view
        if let Some(sortition_state) = sortition_state {
            match sortition_state.check_proposal(
                stacks_client,
                &mut self.signer_db,
                block,
                true,
                self.global_state_evaluator
                    .get_global_tx_replay_set()
                    .unwrap_or_default(),
            ) {
                // Error validating block
                Err(RejectReason::ConnectivityIssues(e)) => {
                    warn!(
                        "{self}: Error checking block proposal: {e}";
                        "signer_signature_hash" => %signer_signature_hash,
                        "block_id" => %block_id,
                    );
                    None
                }
                // Block proposal is bad
                Err(reject_code) => {
                    warn!(
                        "{self}: Block proposal invalid";
                        "signer_signature_hash" => %signer_signature_hash,
                        "block_id" => %block_id,
                        "reject_reason" => %reject_code,
                        "reject_code" => ?reject_code,
                    );
                    Some(self.create_block_rejection(reject_code, block))
                }
                // Block proposal passed check, still don't know if valid
                Ok(_) => None,
            }
        } else {
            warn!(
                "{self}: Cannot validate block, no sortition view";
                "signer_signature_hash" => %signer_signature_hash,
                "block_id" => %block_id,
            );
            None
        }
    }

    /// Check if block should be rejected based on global signer state
    /// Will return a BlockRejection if the block is invalid, none otherwise.
    /// This is the Post-global signer state activation path
    fn check_block_against_global_state(
        &mut self,
        stacks_client: &StacksClient,
        block: &NakamotoBlock,
    ) -> Option<BlockRejection> {
        let signer_signature_hash = block.header.signer_signature_hash();
        let block_id = block.block_id();
        let Some(global_state) = self.global_state_evaluator.determine_global_state() else {
            warn!(
                "{self}: Cannot validate block, no global signer state";
                "signer_signature_hash" => %signer_signature_hash,
                "block_id" => %block_id,
                "local_signer_state" => ?self.local_state_machine
            );
            return None;
        };

        let global_state_view = GlobalStateView {
            signer_state: global_state,
            config: self.proposal_config.clone(),
        };

        info!(
            "{self}: Evaluating proposal against global state";
            "signer_state" => ?global_state_view.signer_state,
            "signer_signature_hash" => %signer_signature_hash,
            "block_id" => %block_id,
            "local_signer_state" => ?self.local_state_machine,
        );

        // Check if proposal can be rejected now if not valid against the global state
        match global_state_view.check_proposal(stacks_client, &mut self.signer_db, block) {
            // Error validating block
            Err(RejectReason::ConnectivityIssues(e)) => {
                warn!(
                    "{self}: Error checking block proposal: {e}";
                    "signer_signature_hash" => %signer_signature_hash,
                    "block_id" => %block_id,
                );
                None
            }
            // Block proposal is bad
            Err(reject_code) => {
                warn!(
                    "{self}: Block proposal invalid";
                    "signer_signature_hash" => %signer_signature_hash,
                    "block_id" => %block_id,
                    "reject_reason" => %reject_code,
                    "reject_code" => ?reject_code,
                );
                Some(self.create_block_rejection(reject_code, block))
            }
            // Block proposal passed check, still don't know if valid
            Ok(_) => None,
        }
    }

    /// The actual `send_block_response` implementation. Declared so that we do
    /// not need to duplicate in testing.
    fn impl_send_block_response(&mut self, block: &NakamotoBlock, block_response: BlockResponse) {
        info!(
            "{self}: Broadcasting block response to stacks node: {block_response:?}";
        );
        let accepted = matches!(block_response, BlockResponse::Accepted(..));
        let message = SignerMessage::from(block_response);
        self.publish_semantic_message(&message);
        crate::monitoring::actions::increment_block_responses_sent(accepted);
        crate::monitoring::actions::record_block_response_latency(block);
    }

    #[cfg(any(test, feature = "testing"))]
    fn send_block_response(&mut self, block: &NakamotoBlock, block_response: BlockResponse) {
        if self.test_skip_block_response_broadcast(&block_response) {
            return;
        }

        self.test_stall_block_response();

        const NUM_REPEATS: usize = 1;
        let mut count = 0;
        let public_keys = TEST_REPEAT_PROPOSAL_RESPONSE.get();
        if !public_keys.contains(
            &stacks_common::types::chainstate::StacksPublicKey::from_private(&self.private_key),
        ) {
            count = NUM_REPEATS;
        }
        while count <= NUM_REPEATS {
            self.impl_send_block_response(block, block_response.clone());

            count += 1;
            sleep_ms(1000);
        }
    }

    #[cfg(not(any(test, feature = "testing")))]
    fn send_block_response(&mut self, block: &NakamotoBlock, block_response: BlockResponse) {
        self.impl_send_block_response(block, block_response)
    }

    /// Send a pre block commit message to signers to indicate that we will be signing the proposed block
    fn send_block_pre_commit(&mut self, signer_signature_hash: Sha512Trunc256Sum) {
        info!(
            "{self}: Broadcasting block pre-commit to stacks node for {signer_signature_hash}";
        );
        let message = SignerMessage::BlockPreCommit(signer_signature_hash);
        self.publish_semantic_message(&message);
        crate::monitoring::actions::increment_block_pre_commits_sent();
    }

    /// Handle signer state update message
    fn handle_state_machine_update(
        &mut self,
        signer_public_key: &Secp256k1PublicKey,
        update: &StateMachineUpdate,
        received_time: &SystemTime,
    ) {
        let replay_txids = update.content.replay_txids();
        let pubkey = signer_public_key.to_hex();
        info!(
            "{self}: Received state machine update from signer {pubkey}: {update}";
            "replay_txids" => ?replay_txids
        );
        let address = StacksAddress::p2pkh(self.mainnet, signer_public_key);
        // Store the state machine update so we can reload it if we crash
        if let Err(e) = self.signer_db.insert_state_machine_update(
            self.reward_cycle,
            &address,
            update,
            received_time,
        ) {
            warn!("{self}: Failed to update global state in signerdb: {e}");
        }
        self.global_state_evaluator
            .insert_update(address, update.clone());
    }

    /// Handle pre-commit message from another signer
    fn handle_block_pre_commit(
        &mut self,
        stacks_client: &StacksClient,
        stacker_address: &StacksAddress,
        block_hash: &Sha512Trunc256Sum,
    ) {
        debug!(
            "{self}: Received pre-commit from signer ({stacker_address:?}) for block ({block_hash})",
        );
        let Some(mut block_info) = self.block_lookup_by_reward_cycle(block_hash) else {
            if let Err(e) = self
                .signer_db
                .add_pending_block_pre_commit_response(block_hash, stacker_address)
            {
                warn!("{self}: Failed to save pending block pre-commit response: {e:?}");
            }
            return;
        };
        // Always save the pre-commit - we will need to store signer responses for determining which
        // are misbehaving, offline, etc.
        // commit message is from a valid sender! store it
        self.signer_db
            .add_block_pre_commit(block_hash, stacker_address)
            .unwrap_or_else(|_| panic!("{self}: Failed to save block pre-commit"));

        if block_info.signed_self.is_some() {
            debug!(
                "{self}: Received pre-commit for a block that we have already signed. Doing nothing...",
            );
            return;
        }

        if !block_info.valid.unwrap_or(false) {
            // We received a pre-commit for a block that we have not validated or we have already marked this block as invalid.
            // We should not do anything further as we do not know what our response should be and we do not change our votes on rejected
            // blocks unless we receive a new block proposal for it and the reject reason allows us to reconsider.
            debug!(
                "{self}: Received a pre-commit for a block that we have not determined to be valid: {:?}. Doing nothing...",
                block_info.valid
            );
            return;
        }

        let block_hash = block_info.block.header.signer_signature_hash();
        // do we have enough pre-commits to reach consensus?
        // i.e. is the threshold reached?
        let committers = self
            .signer_db
            .get_block_pre_committers(&block_hash)
            .unwrap_or_else(|_| panic!("{self}: Failed to load block commits"));

        let commit_weight = self.compute_signature_signing_weight(committers.iter());
        let total_weight = self.compute_signature_total_weight();

        let min_weight = NakamotoBlockHeader::compute_voting_weight_threshold(total_weight)
            .unwrap_or_else(|_| {
                panic!("{self}: Failed to compute threshold weight for {total_weight}")
            });

        if min_weight > commit_weight {
            debug!(
                "{self}: Not enough pre-committed to block {block_hash} (have {commit_weight}, need at least {min_weight}/{total_weight})"
            );
            return;
        }
        // It is only considered globally accepted IFF we receive a new block event confirming it OR see the chain tip of the node advance to it.
        if let Err(e) = block_info.mark_locally_accepted(false) {
            if !block_info.has_reached_consensus() {
                warn!("{self}: Failed to mark block as locally accepted: {e:?}",);
            }
        }
        self.signer_db
            .insert_block(&block_info)
            .unwrap_or_else(|e| self.handle_insert_block_error(e));
        let accepted = self.create_block_acceptance(&block_info.block);
        // have to save the signature _after_ the block info
        self.handle_block_signature(stacks_client, &accepted);
        self.send_block_response(&block_info.block, accepted.into());
    }

    /// Determine if an already tracked block should be re-evaluated based on a new block proposal for it.
    /// Returns true if the block should be re-evaluated, false if it should be ignored.
    fn should_reevaluate_block(
        &mut self,
        block_info: &BlockInfo,
        block_proposal: &BlockProposal,
    ) -> bool {
        let signer_signature_hash = block_info.block.header.signer_signature_hash();
        if block_info.globally_approved_and_responded() {
            info!("{self}: received a block proposal for a globally accepted block to which we have already responded. Ignoring.";
                "signer_signature_hash" => %signer_signature_hash,
                "block_id" => %block_info.block.block_id(),
                "block_height" => block_info.block.header.chain_length,
                "burn_height" => block_proposal.burn_height,
                "consensus_hash" => %block_info.block.header.consensus_hash,
                "timestamp" => block_info.block.header.timestamp,
                "signed_group" => block_info.signed_group,
                "signed_self" => block_info.signed_self,
                "valid" => ?block_info.valid
            );
            return false;
        }
        if !should_reevaluate_reject_reason(block_info) {
            if let Some(block_response) = self.determine_response(block_info) {
                self.send_block_response(&block_info.block, block_response);
                return false;
            } else {
                let is_pending = self
                    .signer_db
                    .has_pending_block_validation(&signer_signature_hash)
                    .unwrap_or_else(|e| {
                        warn!("{self}: Failed to load pending block validations: {e:?}");
                        false
                    });
                if is_pending {
                    debug!(
                        "{self}: received a block proposal for a block for which we is already pending validation. Do nothing.";
                        "signer_signature_hash" => %block_info.block.header.signer_signature_hash(),
                        "block_id" => %block_info.block.block_id()
                    );
                    return false;
                } else {
                    info!(
                        "{self}: received a block proposal for this block before, but we do not have a pending validation for it.";
                        "reject_reason" => ?block_info.reject_reason,
                        "signer_signature_hash" => %signer_signature_hash,
                        "block_id" => %block_info.block.block_id(),
                        "block_height" => block_info.block.header.chain_length,
                        "burn_height" => block_proposal.burn_height,
                        "consensus_hash" => %block_info.block.header.consensus_hash
                    );
                }
            }
        } else {
            info!(
                "{self}: received a block proposal for this block before, but our rejection reason allows us to reconsider";
                "reject_reason" => ?block_info.reject_reason,
                "signer_signature_hash" => %signer_signature_hash,
                "block_id" => %block_proposal.block.block_id(),
                "block_height" => block_proposal.block.header.chain_length,
                "burn_height" => block_proposal.burn_height,
                "consensus_hash" => %block_proposal.block.header.consensus_hash
            );
        }
        true
    }

    /// Handle block proposal messages submitted to signers stackerdb
    fn handle_block_proposal(
        &mut self,
        stacks_client: &StacksClient,
        sortition_state: &mut Option<SortitionsView>,
        block_proposal: &BlockProposal,
    ) {
        debug!("{self}: Received a block proposal: {block_proposal:?}");
        if block_proposal.reward_cycle != self.reward_cycle {
            // We are not signing for this reward cycle. Ignore the block.
            debug!(
                "{self}: Received a block proposal for a different reward cycle. Ignore it.";
                "requested_reward_cycle" => block_proposal.reward_cycle
            );
            return;
        }

        if block_proposal
            .block
            .header
            .timestamp
            .saturating_add(self.block_proposal_max_age_secs)
            < get_epoch_time_secs()
        {
            // Block is too old. Drop it with a warning. Don't even bother broadcasting to the node.
            warn!("{self}: Received a block proposal that is more than {} secs old. Ignoring...", self.block_proposal_max_age_secs;
                "signer_signature_hash" => %block_proposal.block.header.signer_signature_hash(),
                "block_id" => %block_proposal.block.block_id(),
                "block_height" => block_proposal.block.header.chain_length,
                "burn_height" => block_proposal.burn_height,
                "timestamp" => block_proposal.block.header.timestamp,
            );
            return;
        }

        // TODO: should add a check to ignore an old burn block height if we know its outdated. Would require us to store the burn block height we last saw on the side.
        //  the signer needs to be able to determine whether or not the block they're about to sign would conflict with an already-signed Stacks block
        let signer_signature_hash = block_proposal.block.header.signer_signature_hash();
        let pending_responses =
            if let Some(block_info) = self.block_lookup_by_reward_cycle(&signer_signature_hash) {
                if !self.should_reevaluate_block(&block_info, block_proposal) {
                    return;
                }
                PendingBlockResponses::empty()
            } else {
                info!(
                    "{self}: received a block proposal for a new block.";
                    "signer_signature_hash" => %signer_signature_hash,
                    "block_id" => %block_proposal.block.block_id(),
                    "block_height" => block_proposal.block.header.chain_length,
                    "burn_height" => block_proposal.burn_height,
                    "consensus_hash" => %block_proposal.block.header.consensus_hash,
                );
                self.signer_db
                .drain_pending_block_responses(&signer_signature_hash)
                .unwrap_or_else(|e| {
                    warn!(
                        "{self}: Failed to drain pending block responses for block proposal: {e:?}";
                        "signer_signature_hash" => %signer_signature_hash,
                        "block_id" => %block_proposal.block.block_id(),
                    );
                    PendingBlockResponses::empty()
                })
            };
        crate::monitoring::actions::increment_block_proposals_received();
        // Creating a new proposal will overwrite any prior proposal info on the block if it exists, e.g. validity, signed_timestamps, etc.
        let mut block_info = BlockInfo::from(block_proposal.clone());

        // Get sortition view if we don't have it
        if sortition_state.is_none() {
            match SortitionsView::fetch_view(self.proposal_config.clone(), stacks_client) {
                Ok(view) => *sortition_state = Some(view),
                Err(error) => {
                    // A cached signer state cannot prove that this proposal's
                    // sortition is canonical. Treat absent companion evidence
                    // as unavailability, never as acceptance or invalidity.
                    warn!(
                        "{self}: Canonical sortition view is unavailable; abstaining from proposal";
                        "signer_signature_hash" => %signer_signature_hash,
                        "block_id" => %block_proposal.block.block_id(),
                        "error" => ?error,
                    );
                    self.publish_proposal_unavailable(
                        &signer_signature_hash,
                        ProposalUnavailableReason::ChainView,
                    );
                    return;
                }
            }
        }

        // Check if proposal can be rejected now if not valid against sortition view
        let block_rejection =
            self.check_block_against_state(stacks_client, sortition_state, &block_info);

        #[cfg(any(test, feature = "testing"))]
        let block_rejection =
            self.test_reject_block_proposal(block_proposal, &mut block_info, block_rejection);

        if let Some(block_rejection) = block_rejection {
            // We know proposal is invalid. Send rejection message, do not do further validation and do not store it.
            let policy_reason =
                RejectReasonPrefix::from(&block_rejection.response_data.reject_reason)
                    .to_u8()
                    .to_string();
            crate::monitoring::actions::increment_block_policy_rejection(&policy_reason);
            self.send_block_response(&block_info.block, block_rejection.into());
        } else {
            // Durably track the proposal before submitting validation. A fast
            // local callback must never observe a submission whose proposal is
            // still absent from signer state.
            self.signer_db
                .insert_block(&block_info)
                .unwrap_or_else(|e| self.handle_insert_block_error(e));
            self.process_pending_responses_for_block(
                stacks_client,
                sortition_state,
                &mut block_info,
                pending_responses,
            );

            // Just in case check if the last block validation submission timed out.
            self.check_submitted_block_proposal();
            if self.submitted_block_proposal.is_none() {
                // We don't know if proposal is valid, submit to stacks-node for further checks.
                info!(
                    "{self}: submitting block proposal for validation";
                    "signer_signature_hash" => %signer_signature_hash,
                    "block_id" => %block_proposal.block.block_id(),
                    "block_height" => block_proposal.block.header.chain_length,
                    "burn_height" => block_proposal.burn_height,
                );

                #[cfg(any(test, feature = "testing"))]
                self.test_stall_block_validation_submission();
                self.submit_block_for_validation(
                    stacks_client,
                    &block_proposal.block,
                    get_epoch_time_secs(),
                );
            } else {
                // Still store the block but log we can't submit it for validation. We may receive enough signatures/rejections
                // from other signers to push the proposed block into a global rejection/acceptance regardless of our participation.
                // However, we will not be able to participate beyond this until our block submission times out or we receive a response
                // from our node.
                warn!("{self}: cannot submit block proposal for validation as we are already waiting for a response for a prior submission. Inserting pending proposal.";
                    "signer_signature_hash" => signer_signature_hash.to_string(),
                );
                self.signer_db
                    .insert_pending_block_validation(&signer_signature_hash, get_epoch_time_secs())
                    .unwrap_or_else(|e| {
                        warn!("{self}: Failed to insert pending block validation: {e:?}")
                    });
            }
        }
    }

    /// Process pending responses for a block proposal that we may have received late.
    fn process_pending_responses_for_block(
        &mut self,
        stacks_client: &StacksClient,
        sortition_state: &mut Option<SortitionsView>,
        block_info: &mut BlockInfo,
        pending_responses: PendingBlockResponses,
    ) {
        let signer_signature_hash = block_info.block.header.signer_signature_hash();
        for stacker_address in pending_responses.pre_commits {
            debug!("{self}: Processing pending pre-commit.";
                "stacker_address" => %stacker_address,
                "signer_signature_hash" => %signer_signature_hash,
                "block_id" => %block_info.block.block_id(),
            );
            self.handle_block_pre_commit(stacks_client, &stacker_address, &signer_signature_hash);
        }
        for (stacker_address, reject_reason) in pending_responses.rejections {
            debug!("{self}: Processing pending rejection.";
                "stacker_address" => %stacker_address,
                "signer_signature_hash" => %signer_signature_hash,
                "block_id" => %block_info.block.block_id(),
                "reject_reason" => ?reject_reason,
            );
            self.store_and_process_block_rejection(
                sortition_state,
                block_info,
                &stacker_address,
                reject_reason,
            );
        }
        let block_id = block_info.block.block_id();
        for (stackers_address, signature) in pending_responses.signatures {
            debug!("{self}: Processing pending signature.";
                "stacker_address" => %stackers_address,
                "signer_signature_hash" => %signer_signature_hash,
                "block_id" => %block_id,
            );
            self.store_and_process_block_signature(
                stacks_client,
                block_info,
                &stackers_address,
                &signature,
            );
        }
    }

    /// Handle block response messages from a signer
    fn handle_block_response(
        &mut self,
        stacks_client: &StacksClient,
        block_response: &BlockResponse,
        sortition_state: &mut Option<SortitionsView>,
    ) {
        match block_response {
            BlockResponse::Accepted(accepted) => {
                self.handle_block_signature(stacks_client, accepted);
            }
            BlockResponse::Rejected(block_rejection) => {
                self.handle_block_rejection(block_rejection, sortition_state);
            }
        };
    }

    /// WARNING: This is an incomplete check. Do NOT call this function PRIOR to check_proposal or block_proposal validation succeeds.
    ///
    /// Re-verify a block's chain length against the last signed block within signerdb.
    /// This is required in case a block has been approved since the initial checks of the block validation endpoint.
    fn check_block_against_signer_db_state(
        &mut self,
        stacks_client: &StacksClient,
        proposed_block: &NakamotoBlock,
    ) -> Result<Option<BlockRejection>, String> {
        let signer_signature_hash = proposed_block.header.signer_signature_hash();
        // If this is a tenure change block, ensure that it confirms the correct number of blocks from the parent tenure.
        if let Some(tenure_change) = proposed_block.get_tenure_change_tx_payload() {
            // Ensure that the tenure change block confirms the expected parent block
            match SortitionData::check_tenure_change_confirms_parent(
                tenure_change,
                proposed_block,
                &mut self.signer_db,
                stacks_client,
                self.proposal_config.tenure_last_block_proposal_timeout,
                self.proposal_config.reorg_attempts_activity_timeout,
            ) {
                Ok(true) => return Ok(None),
                Ok(false) => {
                    return Ok(Some(self.create_block_rejection(
                        RejectReason::SortitionViewMismatch,
                        proposed_block,
                    )));
                }
                Err(e) => {
                    warn!("{self}: Error checking block proposal: {e}";
                        "signer_signature_hash" => %signer_signature_hash,
                        "block_id" => %proposed_block.block_id()
                    );
                    return Err("error checking tenure-change parent".to_owned());
                }
            }
        }

        // Ensure that the block is the last block in the chain of its current tenure.
        match SortitionData::check_latest_block_in_tenure(
            &proposed_block.header.consensus_hash,
            proposed_block,
            &mut self.signer_db,
            stacks_client,
            self.proposal_config.tenure_last_block_proposal_timeout,
            self.proposal_config.reorg_attempts_activity_timeout,
        ) {
            Ok(is_latest) => {
                if !is_latest {
                    warn!(
                        "Miner's block proposal does not confirm as many blocks as we expect";
                        "proposed_block_consensus_hash" => %proposed_block.header.consensus_hash,
                        "proposed_block_signer_signature_hash" => %signer_signature_hash,
                        "proposed_chain_length" => proposed_block.header.chain_length,
                    );
                    Ok(Some(self.create_block_rejection(
                        RejectReason::SortitionViewMismatch,
                        proposed_block,
                    )))
                } else {
                    Ok(None)
                }
            }
            Err(e) => {
                warn!("{self}: Failed to check block against signer db: {e}";
                    "signer_signature_hash" => %signer_signature_hash,
                    "block_id" => %proposed_block.block_id()
                );
                Err("failed to check latest block against signer db".to_owned())
            }
        }
    }

    /// Handle the block validate ok response
    fn handle_block_validate_ok(
        &mut self,
        stacks_client: &StacksClient,
        block_validate_ok: &BlockValidateOk,
        sortition_state: &mut Option<SortitionsView>,
    ) {
        crate::monitoring::actions::increment_block_validation_responses(true);
        let signer_signature_hash = &block_validate_ok.signer_signature_hash;
        info!("{self}: Companion validation accepted block proposal";
            "signer_signature_hash" => %signer_signature_hash,
            "validation_time_ms" => block_validate_ok.validation_time_ms,
        );
        if self
            .submitted_block_proposal
            .as_ref()
            .map(|(proposal_hash, _)| proposal_hash == signer_signature_hash)
            .unwrap_or(false)
        {
            self.submitted_block_proposal = None;
        }
        if let Some(replay_tx_hash) = block_validate_ok.replay_tx_hash {
            info!("Inserting block validated by replay tx";
                "signer_signature_hash" => %signer_signature_hash,
                "replay_tx_hash" => replay_tx_hash
            );
            self.signer_db
                .insert_block_validated_by_replay_tx(
                    signer_signature_hash,
                    replay_tx_hash,
                    block_validate_ok.replay_tx_exhausted,
                )
                .unwrap_or_else(|e| {
                    warn!("{self}: Failed to insert block validated by replay tx: {e:?}")
                });
        }
        // For mutability reasons, we need to take the block_info out of the map and add it back after processing
        let Some(mut block_info) = self.block_lookup_by_reward_cycle(signer_signature_hash) else {
            // We have not seen this block before. Why are we getting a response for it?
            debug!(
                "{self}: Received a block validate response for a block we have are not tracking. Ignoring..."
            );
            return;
        };

        // Record the block validation time but do not consider stx transfers or boot contract calls
        block_info.validation_time_ms = if block_validate_ok.cost.is_zero() {
            Some(0)
        } else {
            Some(block_validate_ok.validation_time_ms)
        };

        self.signer_db
            .insert_block(&block_info)
            .unwrap_or_else(|e| self.handle_insert_block_error(e));

        if block_info.valid.is_some() {
            // We should only have valid set if we have already processed a validation response for this block OR we locally marked it as rejected
            // and responded to it. If we received a new proposal for it that we wished to consider, we would have reset valid to None.
            // This is only really possible when a signer is sharing a node or we have timed out a pending validation and it suddenly arrives.
            warn!(
                "{self}: Already processed a block validate response for block {}. Ignoring validation response.", block_info.block.header.signer_signature_hash(); "valid" => ?block_info.valid,
            );
            return;
        }
        if !block_info.check_static_valid_block() {
            debug!("{self}: Block is syntatically invalid; will not store");
            return;
        }

        match self.check_block_against_signer_db_state(stacks_client, &block_info.block) {
            Ok(Some(block_rejection)) => {
                // The signer db state has changed. We no longer view this block as valid. Override the validation response.
                if let Err(e) = block_info.mark_locally_rejected() {
                    if !block_info.has_reached_consensus() {
                        warn!("{self}: Failed to mark block as locally rejected: {e:?}");
                    }
                };
                self.signer_db
                    .insert_block(&block_info)
                    .unwrap_or_else(|e| self.handle_insert_block_error(e));
                self.handle_block_rejection(&block_rejection, sortition_state);
                self.send_block_response(&block_info.block, block_rejection.into());
            }
            Err(error) => {
                warn!("{self}: Companion accepted proposal, but local post-validation state is unavailable; abstaining";
                    "signer_signature_hash" => %signer_signature_hash,
                    "error" => %error,
                );
                self.publish_proposal_unavailable(
                    signer_signature_hash,
                    ProposalUnavailableReason::ChainView,
                );
            }
            Ok(None) => {
                if let Err(e) = block_info.mark_pre_committed() {
                    // The block may have reached enough signatures before we validated the block so should fail to mark pre-committed
                    // but still call to make sure the timestamps and validity are updated correctly.
                    if !block_info.has_reached_consensus()
                        && block_info.state != BlockState::LocallyAccepted
                    {
                        warn!("{self}: Failed to mark block as approved: {e:?}",);
                        return;
                    }
                }

                self.signer_db
                    .insert_block(&block_info)
                    .unwrap_or_else(|e| self.handle_insert_block_error(e));
                self.send_block_pre_commit(signer_signature_hash.clone());
                // have to save the signature _after_ the block info
                let address = self.stacks_address.clone();
                self.handle_block_pre_commit(stacks_client, &address, signer_signature_hash);
            }
        }
    }

    /// Handle the block validate reject response
    fn handle_block_validate_reject(
        &mut self,
        block_validate_reject: &BlockValidateReject,
        sortition_state: &mut Option<SortitionsView>,
    ) {
        crate::monitoring::actions::increment_block_validation_responses(false);
        let signer_signature_hash = &block_validate_reject.signer_signature_hash;
        info!("{self}: Companion validation rejected block proposal";
            "signer_signature_hash" => %signer_signature_hash,
            "reject_code" => ?block_validate_reject.reason_code,
        );
        if self
            .submitted_block_proposal
            .as_ref()
            .map(|(proposal_hash, _)| proposal_hash == signer_signature_hash)
            .unwrap_or(false)
        {
            self.submitted_block_proposal = None;
        }
        let Some(mut block_info) = self.block_lookup_by_reward_cycle(signer_signature_hash) else {
            // We have not seen this block before. Why are we getting a response for it?
            debug!(
                "{self}: Received a block validate response for a block we are not tracking. Ignoring..."
            );
            return;
        };
        if block_info.valid.is_some() {
            // We should only have valid set if we have already processed a validation response for this block OR we locally marked it as rejected.
            // and responded to it. If we received a new proposal for it, we would have reset valid to None.
            warn!(
                "{self}: Already processed a block validate response for block {}. Ignoring validation response.", block_info.block.header.signer_signature_hash(); "valid" => ?block_info.valid,
            );
            return;
        }
        if !block_info.check_static_valid_block() {
            debug!("{self}: Block is syntatically invalid; will not store");
            return;
        }
        if let Err(e) = block_info.mark_locally_rejected() {
            if !block_info.has_reached_consensus() {
                warn!("{self}: Failed to mark block as locally rejected: {e:?}");
            }
        }
        let block_rejection = BlockRejection::from_validate_rejection(
            block_validate_reject.clone(),
            &self.private_key,
            self.mainnet,
            self.signer_db.calculate_full_extend_timestamp(
                self.proposal_config
                    .tenure_idle_timeout
                    .saturating_add(self.proposal_config.tenure_idle_timeout_buffer),
                &block_info.block,
                false,
            ),
            self.signer_db.calculate_read_count_extend_timestamp(
                self.proposal_config
                    .read_count_idle_timeout
                    .saturating_add(self.proposal_config.tenure_idle_timeout_buffer),
                &block_info.block,
                false,
            ),
        );

        block_info.reject_reason = Some(block_rejection.response_data.reject_reason.clone());
        self.signer_db
            .insert_block(&block_info)
            .unwrap_or_else(|e| self.handle_insert_block_error(e));
        self.handle_block_rejection(&block_rejection, sortition_state);
        self.send_block_response(&block_info.block, block_rejection.into());
    }

    /// Handle the block validate response returned from our prior calls to submit a block for validation
    fn handle_block_validate_response(
        &mut self,
        stacks_client: &StacksClient,
        block_validate_response: &BlockValidateResponse,
        sortition_state: &mut Option<SortitionsView>,
    ) {
        let signer_signature_hash = block_validate_response.signer_signature_hash();
        let is_current_submission = self
            .submitted_block_proposal
            .as_ref()
            .is_some_and(|(expected, _)| expected == signer_signature_hash);
        if !is_current_submission {
            warn!(
                "{self}: Ignoring unsolicited or stale block validation response";
                "signer_signature_hash" => %signer_signature_hash,
            );
            return;
        }
        info!("{self}: Received a block validate response: {block_validate_response:?}");
        match block_validate_response {
            BlockValidateResponse::Ok(block_validate_ok) => {
                crate::monitoring::actions::record_block_validation_latency(
                    block_validate_ok.validation_time_ms,
                );
                self.handle_block_validate_ok(stacks_client, block_validate_ok, sortition_state);
            }
            BlockValidateResponse::Reject(block_validate_reject) => {
                self.handle_block_validate_reject(block_validate_reject, sortition_state);
            }
        };
        // Remove this block validation from the pending table
        self.signer_db
            .remove_pending_block_validation(signer_signature_hash)
            .unwrap_or_else(|e| warn!("{self}: Failed to remove pending block validation: {e:?}"));

        // Check if there is a pending block validation that we need to submit to the node
        self.check_pending_block_validations(stacks_client);
    }

    /// Check if we can submit a block validation, and do so if we have pending block proposals
    fn check_pending_block_validations(&mut self, stacks_client: &StacksClient) {
        // if we're already waiting on a submitted block proposal, we cannot submit yet.
        if self.submitted_block_proposal.is_some() {
            return;
        }

        // A missing companion response must not turn already-finalized proposals
        // into a multi-minute FIFO backlog. Consume a bounded number per pass;
        // later events continue draining if an old database contains more.
        const MAX_FINALIZED_VALIDATIONS_PER_PASS: usize = 64;
        for _ in 0..MAX_FINALIZED_VALIDATIONS_PER_PASS {
            let (signer_sig_hash, insert_ts) =
                match self.signer_db.get_and_remove_pending_block_validation() {
                    Ok(Some(entry)) => entry,
                    Ok(None) => return,
                    Err(e) => {
                        warn!("{self}: Failed to get pending block validation: {e:?}");
                        return;
                    }
                };

            info!("{self}: Found a pending block validation: {signer_sig_hash:?}");
            match self.signer_db.block_lookup(&signer_sig_hash) {
                Ok(Some(block_info)) if block_info.has_reached_consensus() => {
                    debug!(
                        "{self}: Discarding pending validation for a finalized block";
                        "signer_signature_hash" => %signer_sig_hash,
                    );
                }
                Ok(Some(block_info)) => {
                    self.submit_block_for_validation(stacks_client, &block_info.block, insert_ts);
                    return;
                }
                Ok(None) => {
                    // This should never happen, but one corrupt queue entry
                    // must not prevent later valid proposals from progressing.
                    error!("{self}: Pending block validation not found in DB: {signer_sig_hash:?}");
                }
                Err(e) => {
                    error!("{self}: Failed to get block info: {e:?}");
                    return;
                }
            }
        }
        debug!("{self}: Yielding after bounded finalized validation cleanup");
    }

    /// Check the current tracked submitted block proposal to see if it has timed out.
    /// Abstains if the companion has not answered before the bounded timeout.
    fn check_submitted_block_proposal(&mut self) {
        let Some((proposal_signer_sighash, block_submission)) =
            self.submitted_block_proposal.take()
        else {
            // Nothing to check.
            return;
        };
        // Consensus is stronger completion evidence than this signer's local
        // companion response. Retire the obligation immediately when the block
        // has finalized; waiting for the timeout would serialize every later
        // proposal behind work that can no longer affect the decision.
        match self.signer_db.block_lookup(&proposal_signer_sighash) {
            Ok(Some(block_info)) => {
                if block_info.has_reached_consensus() {
                    return;
                }
            }
            Ok(None) => {
                error!("{self}: tracking an unknown block validation submission.";
                    "signer_signature_hash" => %proposal_signer_sighash,
                );
                return;
            }
            Err(e) => {
                error!("{self}: Failed to lookup block in signer db: {e:?}",);
                return;
            }
        }
        if block_submission.elapsed() < self.block_proposal_validation_timeout {
            self.submitted_block_proposal = Some((proposal_signer_sighash, block_submission));
            return;
        }
        warn!(
            "{self}: Companion validation timed out; abstaining from this proposal";
            "signer_signature_hash" => %proposal_signer_sighash,
            "timeout_ms" => self.block_proposal_validation_timeout.as_millis(),
        );
        self.publish_proposal_unavailable(
            &proposal_signer_sighash,
            ProposalUnavailableReason::CompanionTimeout,
        );
        self.signer_db
            .remove_pending_block_validation(&proposal_signer_sighash)
            .unwrap_or_else(|e| warn!("{self}: Failed to retire timed-out validation: {e:?}"));
    }

    /// Compute the signing weight, given a list of signatures
    fn compute_signature_signing_weight<'a>(
        &self,
        addrs: impl Iterator<Item = &'a StacksAddress>,
    ) -> u32 {
        addrs.fold(0u32, |signing_weight, stacker_address| {
            let stacker_weight = self.signer_weights.get(stacker_address).unwrap_or(&0);
            signing_weight.saturating_add(*stacker_weight)
        })
    }

    /// Compute the rejection weight for the given reject code, given a list of signatures
    fn compute_reject_code_signing_weight<'a>(
        &self,
        addrs: impl Iterator<Item = &'a (StacksAddress, RejectReasonPrefix)>,
        reject_code: RejectReasonPrefix,
    ) -> u32 {
        addrs.filter(|(_, code)| *code == reject_code).fold(
            0u32,
            |signing_weight, (stacker_address, _)| {
                let stacker_weight = self.signer_weights.get(stacker_address).unwrap_or(&0);
                signing_weight.saturating_add(*stacker_weight)
            },
        )
    }

    /// Compute the total signing weight
    fn compute_signature_total_weight(&self) -> u32 {
        self.signer_weights
            .values()
            .fold(0u32, |acc, val| acc.saturating_add(*val))
    }

    /// Handle an observed rejection from another signer
    fn handle_block_rejection(
        &mut self,
        rejection: &BlockRejection,
        sortition_state: &mut Option<SortitionsView>,
    ) {
        debug!("{self}: Received a block-reject signature: {rejection:?}");

        let block_hash = &rejection.signer_signature_hash;
        let signature = &rejection.signature;

        // recover public key
        let Ok(public_key) = rejection.recover_public_key() else {
            debug!("{self}: Received block rejection with an unrecovarable signature. Will not store.";
               "signer_signature_hash" => %block_hash,
               "signature" => %signature
            );
            return;
        };

        // authenticate the signature -- it must be signed by one of the stacking set
        let signer_address = StacksAddress::p2pkh(self.mainnet, &public_key);
        if !self.is_valid_signer(&signer_address) {
            debug!("{self}: Received block rejection with an invalid signature. Will not store.";
                "signer_public_key" => ?public_key,
                "signer_address" => %signer_address,
                "signer_signature_hash" => %block_hash,
                "signature" => %signature
            );
            return;
        }

        let Some(mut block_info) = self.block_lookup_by_reward_cycle(block_hash) else {
            if let Err(e) = self.signer_db.add_pending_block_rejection_response(
                block_hash,
                &signer_address,
                (&rejection.response_data.reject_reason).into(),
            ) {
                warn!("{self}: Failed to add pending block rejection response: {e:?}");
            }
            return;
        };

        info!("{self}: Received block rejection";
            "signer_pubkey" => public_key.to_hex(),
            "signer_signature_hash" => %block_hash,
            "consensus_hash" => %block_info.block.header.consensus_hash,
            "block_height" => block_info.block.header.chain_length,
            "reject_reason" => ?rejection.response_data.reject_reason,
        );

        self.store_and_process_block_rejection(
            sortition_state,
            &mut block_info,
            &signer_address,
            (&rejection.response_data.reject_reason).into(),
        );
    }

    // Store the block rejection signature and check if we have reached a consensus decision on the block because of it. If we have, update the block state accordingly.
    fn store_and_process_block_rejection(
        &mut self,
        sortition_state: &mut Option<SortitionsView>,
        block_info: &mut BlockInfo,
        signer_address: &StacksAddress,
        reject_reason: RejectReasonPrefix,
    ) {
        let block_hash = &block_info.signer_signature_hash();
        // We should still store signatures even on consensus reached blocks for auditing purposes.
        // signature is valid! store it
        match self.signer_db.add_block_rejection_signer_addr(
            block_hash,
            signer_address,
            reject_reason,
        ) {
            Err(e) => {
                warn!("{self}: Failed to save block rejection signature: {e:?}",);
            }
            Ok(false) => return, // We already have this signature, do not process it again.
            Ok(true) => (),
        }

        if block_info.has_reached_consensus() {
            // Checking the rejection signatures is pointless. We have already reached consensus on this block.
            return;
        }

        // do we have enough signatures to mark a block a globally rejected?
        // i.e. is (set-size) - (threshold) + 1 reached.
        let rejection_addrs = match self.signer_db.get_block_rejection_signer_addrs(block_hash) {
            Ok(addrs) => addrs,
            Err(e) => {
                warn!("{self}: Failed to load block rejection addresses: {e:?}.",);
                return;
            }
        };
        let signature_weight = self.signer_weights.get(signer_address).unwrap_or(&0);
        let total_reject_weight =
            self.compute_signature_signing_weight(rejection_addrs.iter().map(|(addr, _)| addr));
        let total_weight = self.compute_signature_total_weight();

        let min_weight = NakamotoBlockHeader::compute_voting_weight_threshold(total_weight)
            .unwrap_or_else(|_| {
                panic!("{self}: Failed to compute threshold weight for {total_weight}")
            });
        if total_reject_weight.saturating_add(min_weight) <= total_weight {
            // Not enough rejection signatures to make a decision
            info!("{self}: Have not yet received enough block rejections to reach a consensus decision on this block";
                "signer_signature_hash" => %block_hash,
                "signature_weight" => signature_weight,
                "consensus_hash" => %block_info.block.header.consensus_hash,
                "block_height" => block_info.block.header.chain_length,
                "total_weight_rejected" => total_reject_weight,
                "total_weight" => total_weight,
                "percent_rejected" => (total_reject_weight as f64 / total_weight as f64 * 100.0),
            );
            return;
        }
        info!("{self}: have reached the block rejection threshold";
            "signer_signature_hash" => %block_hash,
            "signature_weight" => signature_weight,
            "consensus_hash" => %block_info.block.header.consensus_hash,
            "block_height" => block_info.block.header.chain_length,
            "total_weight_rejected" => total_reject_weight,
            "total_weight" => total_weight,
            "percent_rejected" => (total_reject_weight as f64 / total_weight as f64 * 100.0),
        );
        if let Err(e) = block_info.mark_globally_rejected() {
            warn!("{self}: Failed to mark block as globally rejected: {e:?}",);
        }
        if let Err(e) = self.signer_db.insert_block(block_info) {
            error!("{self}: Failed to update block state: {e:?}",);
            panic!("{self} Failed to update block state: {e}");
        }
        // NOTE: This is only used by active signer protocol versions < Global state activation
        // If 30% of the signers have rejected the block due to an invalid
        // reorg, mark the miner as invalid.
        // If we cannot determine the active signer protocol version it means we are
        // running a global state machine version that couldn't reach consensus, so we can skip this check
        if self
            .determine_active_signer_protocol_version()
            .map(|version| version.uses_global_state())
            .unwrap_or(true)
        {
            return;
        };
        let total_reorg_reject_weight = self.compute_reject_code_signing_weight(
            rejection_addrs.iter(),
            RejectReasonPrefix::ReorgNotAllowed,
        );
        if total_reorg_reject_weight.saturating_add(min_weight) > total_weight {
            // Mark the miner as invalid
            if let Some(sortition_state) = sortition_state {
                let ch = block_info.block.header.consensus_hash.clone();
                if sortition_state.cur_sortition.data.consensus_hash == ch {
                    info!("{self}: Marking miner as invalid for attempted reorg");
                    sortition_state.cur_sortition.miner_status =
                        SortitionMinerStatus::InvalidatedBeforeFirstBlock;
                }
            }
        }
    }

    /// Handle an observed signature from another signer
    fn handle_block_signature(&mut self, stacks_client: &StacksClient, accepted: &BlockAccepted) {
        let BlockAccepted {
            signer_signature_hash: block_hash,
            signature,
            metadata,
            ..
        } = accepted;
        debug!(
            "{self}: Received a block-accept signature: ({block_hash}, {signature}, {})",
            metadata.server_version
        );

        // recover public key
        let Ok(public_key) = Secp256k1PublicKey::recover_to_pubkey_without_validating_low_s(
            block_hash.bits(),
            signature,
        ) else {
            debug!("{self}: Received unrecovarable signature. Will not store.";
                   "signature" => %signature,
                   "signer_signature_hash" => %block_hash);

            return;
        };

        // authenticate the signature -- it must be signed by one of the stacking set
        let signer_address = StacksAddress::p2pkh(self.mainnet, &public_key);
        if !self.is_valid_signer(&signer_address) {
            debug!("{self}: Received block acceptance with an invalid signature. Will not store.";
                "signer_public_key" => ?public_key,
                "signer_address" => %signer_address,
                "signer_signature_hash" => %block_hash,
                "signature" => %signature
            );
            return;
        }
        let Some(mut block_info) = self.block_lookup_by_reward_cycle(block_hash) else {
            if let Err(e) = self.signer_db.add_pending_block_signature_response(
                block_hash,
                &signer_address,
                signature,
            ) {
                warn!("{self}: Failed to add pending block signature response: {e:?}");
            }
            return;
        };

        info!("{self}: Received block acceptance";
            "signer_pubkey" => public_key.to_hex(),
            "signer_signature_hash" => %block_hash,
            "consensus_hash" => %block_info.block.header.consensus_hash,
            "block_height" => block_info.block.header.chain_length,
            "signer_weight" => self.signer_weights.get(&signer_address).copied().unwrap_or(0),
            "tenure_extend_timestamp" => accepted.response_data.tenure_extend_timestamp,
            "tenure_extend_read_count_timestamp" => accepted.response_data.tenure_extend_read_count_timestamp
        );
        self.store_and_process_block_signature(
            stacks_client,
            &mut block_info,
            &signer_address,
            signature,
        );
    }

    /// Store the block acceptance signature and check if we have reached a consensus decision on the block because of it. If we have, update the block state accordingly and broadcast the block if accepted.
    fn store_and_process_block_signature(
        &mut self,
        stacks_client: &StacksClient,
        block_info: &mut BlockInfo,
        signer_address: &StacksAddress,
        signature: &MessageSignature,
    ) {
        let block_hash = &block_info.signer_signature_hash();
        // signature is valid! store it.
        // if this returns false, it means the signature already exists in the DB, so just return.
        if !self
            .signer_db
            .add_block_signature(block_hash, signer_address, signature)
            .unwrap_or_else(|_| panic!("{self}: Failed to save block signature"))
        {
            return;
        }

        // If this isn't our own signature and we haven't seen a pre-commit from this signer yet, try treating it as a pre-commit in case the caller is running an outdated version
        if signer_address != &self.stacks_address && !self.signer_db.has_committed(block_hash, signer_address).inspect_err(|e| warn!("Failed to check if pre-commit message already considered for {signer_address:?} for {block_hash}: {e}")).unwrap_or(false) {
            self.handle_block_pre_commit(stacks_client, signer_address, block_hash);
            return;
        }

        if block_info.signed_group.is_some() {
            // We have already processed this block to the accepted state. Adding more signatures will not change anything so nothing to check.
            return;
        }
        // do we have enough signatures to broadcast?
        // i.e. is the threshold reached?
        let signatures = self
            .signer_db
            .get_block_signatures(block_hash)
            .unwrap_or_else(|_| panic!("{self}: Failed to load block signatures"));

        // put signatures in order by signer address (i.e. reward cycle order)
        let addrs_to_sigs: HashMap<_, _> = signatures
            .into_iter()
            .filter_map(|sig| {
                let Ok(public_key) = Secp256k1PublicKey::recover_to_pubkey_without_validating_low_s(
                    block_hash.bits(),
                    &sig,
                ) else {
                    return None;
                };
                let addr = StacksAddress::p2pkh(self.mainnet, &public_key);
                Some((addr, sig))
            })
            .collect();

        let signature_weight = self.signer_weights.get(signer_address).unwrap_or(&0);
        let total_signature_weight = self.compute_signature_signing_weight(addrs_to_sigs.keys());
        let total_weight = self.compute_signature_total_weight();

        let min_weight = NakamotoBlockHeader::compute_voting_weight_threshold(total_weight)
            .unwrap_or_else(|_| {
                panic!("{self}: Failed to compute threshold weight for {total_weight}")
            });

        if min_weight > total_signature_weight {
            info!("{self}: Received block acceptance, but have not yet reached the acceptance threshold.";
                "signer_signature_hash" => %block_hash,
                "signature_weight" => signature_weight,
                "consensus_hash" => %block_info.block.header.consensus_hash,
                "block_height" => block_info.block.header.chain_length,
                "total_weight_approved" => total_signature_weight,
                "total_weight" => total_weight,
                "percent_approved" => (total_signature_weight as f64 / total_weight as f64 * 100.0),
            );
            return;
        }
        info!("{self}: have reached the block acceptance threshold";
            "signer_signature_hash" => %block_hash,
            "signature_weight" => signature_weight,
            "consensus_hash" => %block_info.block.header.consensus_hash,
            "block_height" => block_info.block.header.chain_length,
            "total_weight_approved" => total_signature_weight,
            "total_weight" => total_weight,
            "percent_approved" => (total_signature_weight as f64 / total_weight as f64 * 100.0),
        );

        // have enough signatures to broadcast!
        // move block to LOCALLY accepted state.
        // It is only considered globally accepted IFF we receive a new block event confirming it OR see the chain tip of the node advance to it.
        if let Err(e) = block_info.mark_locally_accepted(true) {
            if !block_info.has_reached_consensus() {
                warn!("{self}: Failed to mark block as locally accepted: {e:?}");
            }
        }
        let _ = self.signer_db.insert_block(block_info).map_err(|e| {
            warn!("Failed to set group threshold signature timestamp for {block_hash}: {e:?}");
            panic!("{self} Failed to write block to signerdb: {e}");
        });
        self.broadcast_signed_block(stacks_client, block_info.block.clone(), &addrs_to_sigs);
    }

    fn broadcast_signed_block(
        &mut self,
        stacks_client: &StacksClient,
        mut block: NakamotoBlock,
        addrs_to_sigs: &HashMap<StacksAddress, MessageSignature>,
    ) {
        #[cfg(any(test, feature = "testing"))]
        self.test_pause_block_broadcast(&block);

        // collect signatures for the block
        let signatures: Vec<_> = self
            .signer_addresses
            .iter()
            .filter_map(|addr| addrs_to_sigs.get(addr).cloned())
            .collect();

        block.header.signer_signature_hash();
        block.header.signer_signature = signatures;

        self.handle_post_block(stacks_client, &block);
    }

    /// Attempt to post a block to the stacks-node and handle the result
    pub fn handle_post_block(&mut self, stacks_client: &StacksClient, block: &NakamotoBlock) {
        #[cfg(any(test, feature = "testing"))]
        if self.test_skip_block_broadcast(block) {
            return;
        }
        let block_hash = block.header.signer_signature_hash();
        match stacks_client.post_block(block) {
            Ok(accepted) => {
                debug!("{self}: Block {block_hash} accepted by stacks node: {accepted}");
                if let Err(e) = self
                    .signer_db
                    .set_block_broadcasted(&block_hash, get_epoch_time_secs())
                {
                    warn!("{self}: Failed to set block broadcasted for {block_hash}: {e:?}");
                }
            }
            Err(e) => {
                warn!("{self}: Failed to broadcast block {block_hash} to the node: {e}")
            }
        }
    }

    /// Submit a block for validation, and mark it as pending if the node
    /// is busy with a previous request.
    fn submit_block_for_validation(
        &mut self,
        stacks_client: &StacksClient,
        block: &NakamotoBlock,
        added_epoch_time: u64,
    ) {
        let signer_signature_hash = block.header.signer_signature_hash();
        if !self.maybe_processed_parent(stacks_client, block) {
            let time_elapsed = get_epoch_time_secs().saturating_sub(added_epoch_time);
            if Duration::from_secs(time_elapsed)
                < self.proposal_config.proposal_wait_for_parent_time
            {
                info!("{self}: Have not processed parent of block proposal yet, inserting pending block validation and will try again later";
                        "signer_signature_hash" => %signer_signature_hash,
                        "parent_block_id" => %block.header.parent_block_id,
                );
                self.signer_db
                    .insert_pending_block_validation(&signer_signature_hash, added_epoch_time)
                    .unwrap_or_else(|e| {
                        warn!("{self}: Failed to insert pending block validation: {e:?}")
                    });
                return;
            } else {
                debug!(
                    "{self}: Cannot confirm that we have processed parent, but we've waited proposal_wait_for_parent_time, will submit proposal"
                );
            }
        }
        let replay_txs = if self.validate_with_replay_tx {
            self.global_state_evaluator
                .get_global_tx_replay_set()
                .unwrap_or_default()
                .clone_as_optional()
        } else {
            None
        };
        match stacks_client.submit_block_for_validation(
            block.clone(),
            replay_txs,
            self.block_proposal_validation_timeout,
        ) {
            Ok(_) => {
                self.submitted_block_proposal = Some((signer_signature_hash, Instant::now()));
            }
            Err(ClientError::RequestFailure(status)) => {
                if status.as_u16() == TOO_MANY_REQUESTS_STATUS {
                    info!("{self}: Received 429 from stacks node for block validation request. Inserting pending block validation...";
                        "signer_signature_hash" => %signer_signature_hash,
                    );
                    self.signer_db
                        .insert_pending_block_validation(&signer_signature_hash, added_epoch_time)
                        .unwrap_or_else(|e| {
                            warn!("{self}: Failed to insert pending block validation: {e:?}")
                        });
                } else {
                    warn!("{self}: Received non-429 status from stacks node: {status}");
                    self.publish_proposal_unavailable(
                        &signer_signature_hash,
                        ProposalUnavailableReason::CompanionRequest,
                    );
                }
            }
            Err(ClientError::ReqwestError(e)) if e.is_timeout() => {
                warn!("{self}: Companion block-validation request timed out; abstaining";
                    "signer_signature_hash" => %signer_signature_hash,
                    "timeout_ms" => self.block_proposal_validation_timeout.as_millis(),
                );
                self.publish_proposal_unavailable(
                    &signer_signature_hash,
                    ProposalUnavailableReason::CompanionTimeout,
                );
            }
            Err(e) => {
                warn!("{self}: Failed to submit block for validation: {e:?}");
                self.publish_proposal_unavailable(
                    &signer_signature_hash,
                    ProposalUnavailableReason::CompanionRequest,
                );
            }
        }
    }

    /// Helper for logging insert_block error
    pub fn handle_insert_block_error(&self, e: DBError) {
        error!("{self}: Failed to insert block into signer-db: {e:?}");
        panic!("{self} Failed to write block to signerdb: {e}");
    }

    /// Helper for getting the block info from the db while accommodating for reward cycle
    pub fn block_lookup_by_reward_cycle(
        &self,
        block_hash: &Sha512Trunc256Sum,
    ) -> Option<BlockInfo> {
        let block_info = self
            .signer_db
            .block_lookup(block_hash)
            .inspect_err(|e| {
                error!("{self}: Failed to lookup block hash {block_hash} in signer db: {e:?}");
            })
            .ok()
            .flatten()?;
        if block_info.reward_cycle == self.reward_cycle {
            Some(block_info)
        } else {
            None
        }
    }

    /// Check if the signer identified by the StacksAddress is part of the signer's list of signer addresses
    pub fn is_valid_signer(&self, address: &StacksAddress) -> bool {
        self.signer_addresses.iter().any(|addr| {
            // it only matters that the address hash bytes match
            address.bytes() == addr.bytes()
        })
    }

    #[cfg(not(any(test, feature = "testing")))]
    fn get_signer_protocol_version(&self) -> u64 {
        crate::v0::signer_state::SUPPORTED_SIGNER_PROTOCOL_VERSION
    }

    #[cfg(any(test, feature = "testing"))]
    fn get_signer_protocol_version(&self) -> u64 {
        self.test_get_signer_protocol_version()
    }
}

/// Determine if a block should be re-evaluated based on its rejection reason˝
fn should_reevaluate_reject_reason(block_info: &BlockInfo) -> bool {
    if let Some(reject_reason) = &block_info.reject_reason {
        match reject_reason {
            RejectReason::ValidationFailed(ValidateRejectCode::UnknownParent)
            | RejectReason::ValidationFailed(ValidateRejectCode::NotFoundError)
            | RejectReason::NoSortitionView
            | RejectReason::ConnectivityIssues(_)
            | RejectReason::TestingDirective
            | RejectReason::InvalidTenureExtend
            | RejectReason::ConsensusHashMismatch { .. }
            | RejectReason::NoSignerConsensus
            | RejectReason::NotRejected
            | RejectReason::Unknown(_) => true,
            RejectReason::ValidationFailed(_)
            | RejectReason::RejectedInPriorRound
            | RejectReason::SortitionViewMismatch
            | RejectReason::ReorgNotAllowed
            | RejectReason::InvalidBitvec
            | RejectReason::PubkeyHashMismatch
            | RejectReason::InvalidMiner
            | RejectReason::NotLatestSortitionWinner
            | RejectReason::InvalidParentBlock
            | RejectReason::DuplicateBlockFound
            | RejectReason::IrrecoverablePubkeyHash
            | RejectReason::ProblematicTransactions => {
                // No need to re-validate these types of rejections.
                false
            }
        }
    } else {
        false
    }
}

/// Complete the signer half of the native deferral integration test. The
/// caller supplies the exact authenticated event released by the production
/// libp2p service; this helper drives that event through the production
/// runloop translation, proposal policy, companion submission/response,
/// precommit, and accepted-vote paths.
#[cfg(test)]
pub(crate) fn assert_released_native_proposal_reaches_vote(
    released: libsigner::AuthenticatedSignerEvent,
    network: SignerNetworkHandle,
    proposal: &BlockProposal,
    miner_key: &StacksPrivateKey,
    signer_key: &StacksPrivateKey,
) {
    use std::io::{Read, Write};
    use std::thread;

    use blockstack_lib::net::api::postblock::StacksBlockAcceptedData;
    use clarity::vm::costs::ExecutionCost;
    use stacks_common::types::chainstate::{BurnchainHeaderHash, ConsensusHash};
    use stacks_common::util::hash::Hash160;
    use tempfile::TempDir;

    use crate::chainstate::v1::{SortitionMinerStatus, SortitionState};
    use crate::client::tests::MockServerClient;

    let MockServerClient { server, client, .. } = MockServerClient::new();
    let accepted_body = serde_json::to_string(&StacksBlockAcceptedData {
        stacks_block_id: proposal.block.block_id(),
        accepted: true,
    })
    .expect("signed-block response JSON");
    let accepted_response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        accepted_body.len(),
        accepted_body
    );
    let rpc_thread = thread::spawn(move || {
        let responses = [
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
            accepted_response.into_bytes(),
        ];
        for response in responses {
            let (mut stream, _) = server.accept().expect("mock companion request");
            let mut request = [0_u8; 4096];
            let read = stream
                .read(&mut request)
                .expect("mock companion request body");
            assert!(read > 0, "mock companion received an empty request");
            stream
                .write_all(&response)
                .expect("mock companion response");
        }
    });

    let signer_address = StacksAddress::p2pkh(false, &StacksPublicKey::from_private(signer_key));
    let signer_weights = HashMap::from([(signer_address.clone(), 1)]);
    let proposal_config = ProposalEvalConfig {
        first_proposal_burn_block_timing: Duration::from_secs(30),
        block_proposal_timeout: Duration::from_secs(30),
        tenure_last_block_proposal_timeout: Duration::from_secs(30),
        tenure_idle_timeout: Duration::from_secs(300),
        read_count_idle_timeout: Duration::from_secs(12_000),
        tenure_idle_timeout_buffer: Duration::from_secs(2),
        reorg_attempts_activity_timeout: Duration::from_secs(3),
        proposal_wait_for_parent_time: Duration::ZERO,
        reset_replay_set_after_fork_blocks: 0,
    };
    let db_dir = TempDir::new().expect("signer test database directory");
    let signer_db =
        SignerDb::new(db_dir.path().join("signer.sqlite")).expect("signer test database");
    let mut signer = Signer {
        private_key: signer_key.clone(),
        stacks_address: signer_address.clone(),
        signer_network: Some(network.clone()),
        mainnet: false,
        mode: SignerMode::Normal { signer_id: 0 },
        signer_slot_ids: vec![SignerSlotID(0)],
        signer_addresses: vec![signer_address.clone()],
        reward_cycle: proposal.reward_cycle,
        signer_weights: signer_weights.clone(),
        signer_db,
        proposal_config: proposal_config.clone(),
        block_proposal_validation_timeout: Duration::from_secs(1),
        submitted_block_proposal: None,
        block_proposal_max_age_secs: 300,
        local_state_machine: LocalStateMachine::Uninitialized,
        recently_processed: RecentlyProcessedBlocks::new(),
        global_state_evaluator: GlobalStateEvaluator::new(HashMap::new(), signer_weights),
        state_update_heartbeat: StateUpdateHeartbeat::default(),
        validate_with_replay_tx: false,
        tx_replay_scope: None,
        reset_replay_set_after_fork_blocks: 0,
        capitulate_miner_view_timeout: Duration::from_secs(30),
        last_capitulate_miner_view: SystemTime::now(),
        supported_signer_protocol_version: 1,
    };
    signer
        .recently_processed
        .add_block(proposal.block.header.parent_block_id.clone());

    let consensus_hash = proposal.block.header.consensus_hash.clone();
    let miner_public_key = StacksPublicKey::from_private(miner_key);
    let mut sortition_state = Some(SortitionsView {
        cur_sortition: SortitionState {
            data: SortitionData {
                miner_pkh: Hash160::from_data(&miner_public_key.to_bytes_compressed()),
                miner_pubkey: Some(miner_public_key),
                prior_sortition: ConsensusHash([2; 20]),
                parent_tenure_id: ConsensusHash([2; 20]),
                consensus_hash,
                burn_header_timestamp: get_epoch_time_secs(),
                burn_block_hash: BurnchainHeaderHash([3; 32]),
            },
            miner_status: SortitionMinerStatus::Valid,
        },
        last_sortition: None,
        config: proposal_config,
    });

    let event = crate::runloop::authenticated_native_event::<SignerMessage>(released)
        .expect("released native proposal must cross the production runloop boundary");
    let SignerEvent::MinerMessages(messages) = &event else {
        panic!("released proposal did not translate to a miner event");
    };
    assert_eq!(
        messages,
        &vec![SignerMessage::BlockProposal(proposal.clone())]
    );

    signer.handle_event_match(&client, &mut sortition_state, &event);
    let signer_signature_hash = proposal.block.header.signer_signature_hash();
    assert_eq!(
        signer
            .submitted_block_proposal
            .as_ref()
            .map(|(hash, _)| hash),
        Some(&signer_signature_hash),
        "the exact released proposal must be submitted to the companion"
    );

    signer.handle_event_match(
        &client,
        &mut sortition_state,
        &SignerEvent::BlockValidationResponse(BlockValidateResponse::Ok(BlockValidateOk {
            signer_signature_hash: signer_signature_hash.clone(),
            cost: ExecutionCost::ZERO,
            size: proposal.block.serialize_to_vec().len() as u64,
            validation_time_ms: 1,
            replay_tx_hash: None,
            replay_tx_exhausted: false,
        })),
    );
    rpc_thread.join().expect("mock companion thread");

    let block_info = signer
        .block_lookup_by_reward_cycle(&signer_signature_hash)
        .expect("released proposal remains tracked after voting");
    assert_eq!(block_info.valid, Some(true));
    assert!(
        block_info.signed_self.is_some(),
        "normal signer voting must record this signer's accepted vote"
    );

    let local_messages = network
        .local_test_messages()
        .into_iter()
        .filter_map(|message| {
            let mut payload = message.payload.as_slice();
            SignerMessage::consensus_deserialize(&mut payload)
                .ok()
                .filter(|_| payload.is_empty())
        })
        .collect::<Vec<_>>();
    assert!(local_messages.iter().any(|message| {
        matches!(message, SignerMessage::BlockPreCommit(hash) if hash == &signer_signature_hash)
    }));
    assert!(local_messages.iter().any(|message| {
        matches!(
            message,
            SignerMessage::BlockResponse(BlockResponse::Accepted(accepted))
                if accepted.signer_signature_hash == signer_signature_hash
        )
    }));
}

#[cfg(test)]
mod state_update_heartbeat_tests {
    use super::*;

    #[test]
    fn state_update_heartbeat_is_immediate_then_bounded() {
        let now = Instant::now();
        let mut heartbeat = StateUpdateHeartbeat::default();
        assert!(heartbeat.due(now));

        heartbeat.record_attempt(now);
        assert!(!heartbeat.due(now));
        assert!(!heartbeat.due(now + STATE_UPDATE_HEARTBEAT_INTERVAL - Duration::from_millis(1)));
        assert!(heartbeat.due(now + STATE_UPDATE_HEARTBEAT_INTERVAL));
    }
}
