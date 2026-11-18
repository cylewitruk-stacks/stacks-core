// Copyright (C) 2024-2026 Stacks Open Internet Foundation
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
use std::ops::Bound::Included;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use libsigner::v0::messages::{MinerSlotID, SignerMessage as SignerMessageV0};
use libsigner::v0::signer_state::SignerStateMachine;
use libsigner::{BlockProposal, BlockProposalData, SignerSession, StackerDBSession};
use prost::Message as ProstMessage;
use stacks::burnchains::Burnchain;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::{BlockSnapshot, ConsensusHash};
use stacks::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader, NakamotoChainState};
use stacks::chainstate::stacks::boot::{RewardSet, MINERS_NAME};
use stacks::chainstate::stacks::db::{StacksBlockHeaderTypes, StacksChainState};
use stacks::chainstate::stacks::Error as ChainstateError;
use stacks::codec::StacksMessageCodec;
use stacks::libstackerdb::StackerDBChunkData;
use stacks::net::stackerdb::StackerDBs;
use stacks::types::chainstate::{StacksPrivateKey, StacksPublicKey};
use stacks::types::{MinerDiagnosticData, PrivateKey};
use stacks::util::hash::Hash160;
use stacks::util::secp256k1::MessageSignature;
use stacks::util_lib::boot::boot_code_id;
use stacks_network::{
    signed_role_directory_record, NetworkHandle, SignerAdmission, SignerNetworkEvent,
};
use stacks_network_types::wire::v1::{
    ProposalManifest, ProposalUnavailable, Role, SignerEnvelope, SignerEnvelopeBody, SignerLane,
};
use stacks_network_types::{
    proposal_content_id, signer_envelope_digest, signer_envelope_id, ContentId, NetworkObject,
    NetworkScope, ObjectKind, PROPOSAL_MANIFEST_VERSION, SIGNER_ENVELOPE_VERSION,
};
use stacks_signer_bridge::{
    BridgeJournal, LegacyLocator, LegacyWritePipeline, TemporarySignerBridge,
    TemporarySignerBridgeError,
};

use super::miner_db::MinerDB;
use super::signer_message_processor::{BlockStatus, SignerMessageProcessorComms};
use super::Error as NakamotoNodeError;
use crate::event_dispatcher::StackerDBChannel;
use crate::globals::Libp2pSignerEventRouter;
use crate::nakamoto_node::signer_message_processor::{
    InitialChunksLoader, SignerMessageProcessor, EVENT_RECEIVER_POLL,
};
use crate::neon::Counters;
use crate::Config;

/// The state of the signer database listener, used by the miner thread to
/// interact with the signer listener.
pub struct SignerCoordinator {
    /// The private key used to sign messages from the miner
    message_key: StacksPrivateKey,
    /// Is this mainnet?
    is_mainnet: bool,
    /// Direct legacy `.miners` writer used only by a legacy-only coordinator.
    miners_session: Option<StackerDBSession>,
    /// The total weight of all signers
    total_weight: u32,
    /// The weight threshold for block approval
    weight_threshold: u32,
    /// Interface to the transport-neutral signer response accumulator.
    signer_comms: SignerMessageProcessorComms,
    /// Keep-running flag for the optional legacy signer event source.
    keep_running: Arc<AtomicBool>,
    /// Handle for the optional legacy signer event-source thread.
    legacy_listener_thread: Option<JoinHandle<()>>,
    /// The miner thread's abort flag, set by the relayer to stop the miner thread. While waiting
    /// for signatures, the coordinator gives up as soon as it is set.
    miner_abort_flag: Arc<AtomicBool>,
    /// The current tip when this miner thread was started.
    /// This *should not* be passed into any block building code, as it
    ///  is not necessarily the burn view for the block being constructed.
    /// Rather, this burn block is used to determine whether or not a new
    ///  burn block has arrived since this thread started.
    burn_tip_at_start: ConsensusHash,
    /// The timeout configuration based on the percentage of rejections
    block_rejection_timeout_steps: BTreeMap<u32, Duration>,
    /// Producer side of the native libp2p signer network.
    native_network: Option<NetworkHandle>,
    /// Rollout gate for locally authored native application messages.
    native_publish_enabled: bool,
    /// Stacks application chain/network identifier.
    chain_id: u32,
    /// Whether locally authored miner messages are also written to `.miners`.
    compatibility_stackerdb: bool,
    /// Restart-safe native miner envelope sequence cursors.
    native_sequence_db: MinerDB,
    /// Durable origin-only `.miners` compatibility translator.
    miner_bridge: Option<TemporarySignerBridge>,
    /// Complete bounded lifecycle of the legacy HTTP writer.
    miner_bridge_pipeline: LegacyWritePipeline,
    /// Continuously drains native signer events into the transport-neutral
    /// accumulator, including between proposal wait loops.
    native_listener_thread: Option<JoinHandle<()>>,
    /// Process-wide native event router and this coordinator's generation.
    native_signer_router: Libp2pSignerEventRouter,
    native_signer_registration: Option<u64>,
    /// Rejection timeout to apply while any signer has rejected the block
    /// for a transient reason
    transient_rejection_retry_timeout: Duration,
}

/// Helper function to build block_rejection_timeout_steps BTreeMap from config.
///
/// When multiple percentages truncate to the same rejections_amount
/// (common with small total_weight), keeps the longest timeout.
fn build_block_rejection_timeout_steps(
    total_weight: u32,
    config_steps: &HashMap<u32, Duration>,
) -> BTreeMap<u32, Duration> {
    let mut block_rejection_timeout_steps = BTreeMap::<u32, Duration>::new();
    for (percentage, duration) in config_steps.iter() {
        let rejections_amount = ((f64::from(total_weight) / 100.0) * f64::from(*percentage)) as u32;
        // If multiple percentages collapse to the same weight, keep the longest timeout.
        if let Some(existing) = block_rejection_timeout_steps.get_mut(&rejections_amount) {
            warn!(
                "block_rejection_timeout_steps collision: percentages map to same rejection weight";
                "rejections_amount" => rejections_amount,
                "existing_timeout_secs" => existing.as_secs(),
                "new_timeout_secs" => duration.as_secs(),
            );
            *existing = (*existing).max(*duration);
        } else {
            block_rejection_timeout_steps.insert(rejections_amount, *duration);
        }
    }

    block_rejection_timeout_steps
}

/// Convert authenticated weighted rejection state into the coordinator's
/// terminal result without requiring chainstate construction in tests.
pub(crate) fn signer_rejection_error(
    block_status: &BlockStatus,
    total_weight: u32,
    weight_threshold: u32,
) -> Option<NakamotoNodeError> {
    if block_status
        .total_weight_rejected
        .saturating_add(weight_threshold)
        <= total_weight
    {
        return None;
    }
    let blocking_minority = total_weight.saturating_sub(weight_threshold);
    let mut temporarily_excluded_txids = HashSet::new();
    let mut permanently_excluded_txids = HashSet::new();
    for (txid, info) in &block_status.failed_txids {
        if info.total_weight > blocking_minority {
            if info.problematic_weight > blocking_minority {
                permanently_excluded_txids.insert(txid.clone());
            } else {
                temporarily_excluded_txids.insert(txid.clone());
            }
        }
    }
    Some(NakamotoNodeError::SignersRejected {
        temporarily_excluded_txids,
        permanently_excluded_txids,
    })
}

fn process_native_signer_event(
    signer_comms: &SignerMessageProcessorComms,
    event: SignerNetworkEvent,
) {
    let envelope = event.envelope;
    if matches!(
        event.admission,
        SignerAdmission::Duplicate | SignerAdmission::Equivocation
    ) {
        return;
    }
    let Ok(lane) = SignerLane::try_from(envelope.body.lane) else {
        warn!("Authenticated native signer response has an unknown lane");
        return;
    };
    let Ok(signer_pubkey) = StacksPublicKey::from_slice(&envelope.body.signer_public_key) else {
        warn!("Authenticated native response has an invalid signer public key");
        return;
    };
    if lane == SignerLane::ProposalUnavailable {
        let Ok(unavailable) = ProposalUnavailable::decode(envelope.body.payload.as_slice()) else {
            warn!("Failed to decode authenticated proposal-unavailable outcome");
            return;
        };
        if stacks_network_types::validate_proposal_unavailable(
            &unavailable,
            envelope.body.reward_cycle,
        )
        .is_err()
        {
            warn!("Rejected malformed authenticated proposal-unavailable outcome");
            return;
        }
        signer_comms.process_authenticated_unavailable(
            &signer_pubkey,
            &unavailable,
            envelope.body.reward_cycle,
        );
        return;
    }
    let mut payload = envelope.body.payload.as_slice();
    let Ok(message) = SignerMessageV0::consensus_deserialize(&mut payload) else {
        warn!("Failed to decode authenticated native signer response");
        return;
    };
    if !payload.is_empty() {
        warn!("Rejected authenticated native signer response with trailing bytes");
        return;
    }
    let expected_lane = match &message {
        SignerMessageV0::BlockResponse(_) => SignerLane::BlockResponse,
        SignerMessageV0::StateMachineUpdate(_) => SignerLane::StateMachineUpdate,
        _ => {
            warn!("Rejected native signer message not consumed by the miner");
            return;
        }
    };
    if lane != expected_lane {
        warn!("Rejected native signer envelope with mismatched lane and payload";
            "lane" => ?lane,
            "expected_lane" => ?expected_lane,
        );
        return;
    }
    signer_comms.process_authenticated_message(&signer_pubkey, message);
}

fn run_native_signer_adapter(
    receiver: Receiver<SignerNetworkEvent>,
    signer_comms: SignerMessageProcessorComms,
    keep_running: Arc<AtomicBool>,
) {
    info!("Native signer event adapter: starting up");
    while keep_running.load(std::sync::atomic::Ordering::Relaxed) {
        match receiver.recv_timeout(EVENT_RECEIVER_POLL) {
            Ok(event) => process_native_signer_event(&signer_comms, event),
            Err(error) => match error {
                std::sync::mpsc::RecvTimeoutError::Timeout => {}
                std::sync::mpsc::RecvTimeoutError::Disconnected => break,
            },
        }
    }
    debug!("Native signer event adapter: shut down");
}

/// Select the timeout to apply while waiting for signer responses, given the
/// total rejection weight received so far and the portion of it that is
/// transient (see [`libsigner::v0::messages::RejectReason::is_transient`]).
///
/// Returns the matching step (the rejection weight key) and its timeout. While
/// any transient rejections are outstanding, the timeout is
/// `transient_retry_timeout` regardless of the step: those signers re-evaluate
/// the block once it is proposed again, so a longer step only delays the block,
/// while a shorter one (e.g. 0) re-sends before they have caught up and only
/// collects the same rejections again.
fn select_rejection_timeout(
    block_rejection_timeout_steps: &BTreeMap<u32, Duration>,
    total_weight_rejected: u32,
    total_weight_rejected_transient: u32,
    transient_retry_timeout: Duration,
) -> Option<(u32, Duration)> {
    let (step, timeout) = block_rejection_timeout_steps
        .range((Included(0), Included(total_weight_rejected)))
        .last()?;
    if total_weight_rejected_transient > 0 {
        Some((*step, transient_retry_timeout))
    } else {
        Some((*step, *timeout))
    }
}

/// Should a block whose rejections exceed the `blocking_minority` be re-sent
/// rather than abandoned? It should if the rejections that are not transient
/// (see [`libsigner::v0::messages::RejectReason::is_transient`]) do not exceed
/// the `blocking_minority` on their own: the transient rejecters re-evaluate the
/// block when it is proposed again, and may then accept it.
fn should_resend_on_transient_rejection(
    total_weight_rejected: u32,
    total_weight_rejected_transient: u32,
    blocking_minority: u32,
) -> bool {
    let substantive = total_weight_rejected.saturating_sub(total_weight_rejected_transient);
    substantive <= blocking_minority
}

impl SignerCoordinator {
    pub(super) fn miner_bridge_enabled(&self) -> bool {
        self.miner_bridge.is_some()
    }

    /// Create a new `SignerCoordinator` instance.
    /// This will spawn a new thread to listen for messages from the signer DB.
    pub(crate) fn new(
        stackerdb_channel: Arc<Mutex<StackerDBChannel>>,
        node_keep_running: Arc<AtomicBool>,
        miner_abort_flag: Arc<AtomicBool>,
        reward_set: &RewardSet,
        initial_chunks_loader: InitialChunksLoader,
        election_block: &BlockSnapshot,
        burnchain: &Burnchain,
        message_key: StacksPrivateKey,
        config: &Config,
        burn_tip_at_start: &ConsensusHash,
        native_network: Option<NetworkHandle>,
        native_signer_router: Libp2pSignerEventRouter,
    ) -> Result<Self, ChainstateError> {
        info!("SignerCoordinator: starting up");
        let keep_running = Arc::new(AtomicBool::new(true));

        // Create the transport-neutral signer response processor. Its legacy
        // event source is absent when compatibility ingress is disabled.
        let mut processor = SignerMessageProcessor::new(
            stackerdb_channel,
            node_keep_running.clone(),
            keep_running.clone(),
            reward_set,
            initial_chunks_loader,
            election_block,
            burnchain,
            config,
        )?;
        let is_mainnet = config.is_mainnet();
        let rpc_socket = config
            .node
            .get_rpc_loopback()
            .ok_or_else(|| ChainstateError::MinerAborted)?;
        let miners_session =
            if native_network.is_none() && config.node.libp2p.signer_bridge.mode.writes_legacy() {
                Some(StackerDBSession::new(
                    &rpc_socket.to_string(),
                    boot_code_id(MINERS_NAME, is_mainnet),
                    config.miner.stackerdb_timeout,
                ))
            } else {
                None
            };
        let native_sequence_db = MinerDB::open_with_config(config).map_err(|error| {
            error!("Failed to open native miner sequence journal: {error}");
            ChainstateError::DBError(error)
        })?;
        let reward_cycle = burnchain
            .block_height_to_reward_cycle(election_block.block_height)
            .expect("signer coordinator starts after the first reward cycle");
        let mut miner_bridge =
            if native_network.is_some() && config.node.libp2p.signer_bridge.mode.writes_legacy() {
                Some(
                    TemporarySignerBridge::new(
                        config.node.libp2p.signer_bridge.clone(),
                        BridgeJournal::open(MinerDB::miner_db_path(config)).map_err(|error| {
                            ChainstateError::InvalidStacksBlock(format!(
                                "failed to open miner bridge journal: {error}"
                            ))
                        })?,
                    )
                    .map_err(|error| {
                        ChainstateError::InvalidStacksBlock(format!(
                            "failed to initialize miner bridge: {error}"
                        ))
                    })?,
                )
            } else {
                None
            };
        if let Some(bridge) = miner_bridge.as_mut() {
            bridge
                .update_cycles(reward_cycle, Some(reward_cycle.saturating_add(1)))
                .map_err(|error| {
                    ChainstateError::InvalidStacksBlock(format!(
                        "failed to initialize miner bridge cycle: {error}"
                    ))
                })?;
        }
        let miner_bridge_pipeline = if miner_bridge.is_some() {
            LegacyWritePipeline::spawn(
                "miner-legacy-bridge",
                rpc_socket.to_string(),
                config.miner.stackerdb_timeout,
                256,
            )
            .map_err(|error| {
                error!("Failed to spawn miner legacy bridge: {error}");
                ChainstateError::MinerAborted
            })?
        } else {
            LegacyWritePipeline::disabled()
        };

        // build a BTreeMap of the various timeout steps
        let block_rejection_timeout_steps = build_block_rejection_timeout_steps(
            processor.total_weight,
            &config.miner.block_rejection_timeout_steps,
        );
        if let Some(network) = native_network.as_ref() {
            network
                .update_chain_view(election_block.block_height, reward_cycle)
                .map_err(|error| {
                    ChainstateError::InvalidStacksBlock(format!(
                        "failed to update libp2p chain view: {error}"
                    ))
                })?;
            network
                .retain_signer_cycles(reward_cycle, Some(reward_cycle.saturating_add(1)))
                .map_err(|error| {
                    ChainstateError::InvalidStacksBlock(format!(
                        "failed to retain libp2p signer cycles: {error}"
                    ))
                })?;
            let public_keys = reward_set
                .signers()
                .map(|signers| signers.iter().map(|entry| entry.signing_key).collect())
                .unwrap_or_default();
            network
                .update_authorized_signers(reward_cycle, public_keys)
                .map_err(|error| {
                    ChainstateError::InvalidStacksBlock(format!(
                        "failed to update libp2p signer authorization: {error}"
                    ))
                })?;
            let miner_public_key =
                StacksPublicKey::from_private(&message_key).to_bytes_compressed();
            let miner_public_key_hash = Hash160::from_data(&miner_public_key);
            network
                .update_authorized_miners(
                    reward_cycle,
                    vec![(
                        election_block.consensus_hash.as_bytes().to_vec(),
                        miner_public_key_hash.0,
                    )],
                )
                .map_err(|error| {
                    ChainstateError::InvalidStacksBlock(format!(
                        "failed to update libp2p miner authorization: {error}"
                    ))
                })?;
            let local_peer_id = network.local_peer_id().map_err(|error| {
                ChainstateError::InvalidStacksBlock(format!(
                    "failed to resolve local libp2p PeerId: {error}"
                ))
            })?;
            let advertised_addresses = config
                .node
                .libp2p
                .advertise
                .iter()
                .map(|address| address.parse())
                .collect::<Result<Vec<libp2p::Multiaddr>, _>>()
                .map_err(|error| {
                    ChainstateError::InvalidStacksBlock(format!(
                        "invalid libp2p miner advertised address: {error}"
                    ))
                })?;
            let role_record = signed_role_directory_record(
                NetworkScope::new(config.burnchain.chain_id, config.burnchain.chain_id),
                local_peer_id,
                Role::Miner,
                reward_cycle,
                election_block.consensus_hash.as_bytes().to_vec(),
                election_block.block_height,
                election_block
                    .block_height
                    .saturating_add(u64::from(burnchain.pox_constants.reward_cycle_length)),
                advertised_addresses,
                &message_key,
            )
            .map_err(|error| {
                ChainstateError::InvalidStacksBlock(format!(
                    "failed to construct libp2p miner role proof: {error}"
                ))
            })?;
            network
                .set_local_role_record(Some(role_record))
                .map_err(|error| {
                    ChainstateError::InvalidStacksBlock(format!(
                        "failed to install libp2p miner role proof: {error}"
                    ))
                })?;
        }

        let mut sc = Self {
            message_key,
            is_mainnet,
            miners_session,
            total_weight: processor.total_weight,
            weight_threshold: processor.weight_threshold,
            signer_comms: processor.get_comms(),
            keep_running,
            legacy_listener_thread: None,
            burn_tip_at_start: burn_tip_at_start.clone(),
            block_rejection_timeout_steps,
            native_network,
            native_publish_enabled: config.node.libp2p.rollout_mode.publishes_application_data(),
            chain_id: config.burnchain.chain_id,
            compatibility_stackerdb: config.node.libp2p.signer_bridge.mode.writes_legacy(),
            native_sequence_db,
            miner_bridge,
            miner_bridge_pipeline,
            native_listener_thread: None,
            native_signer_router,
            native_signer_registration: None,
            miner_abort_flag,
            transient_rejection_retry_timeout: config.miner.transient_rejection_retry_timeout,
        };

        if sc.native_network.is_some() {
            let native_signer_comms = processor.get_comms();
            let native_keep_running = sc.keep_running.clone();
            let (registration, receiver) = sc.native_signer_router.register();
            let listener_thread = std::thread::Builder::new()
                .name(format!(
                    "native_signer_adapter_{}",
                    election_block.block_height
                ))
                .spawn(move || {
                    run_native_signer_adapter(receiver, native_signer_comms, native_keep_running);
                })
                .map_err(|error| {
                    error!("Failed to spawn native signer event adapter: {error:?}");
                    ChainstateError::MinerAborted
                })?;
            sc.native_signer_registration = Some(registration);
            sc.native_listener_thread = Some(listener_thread);
        }

        if processor.has_legacy_event_source() {
            let listener_thread = std::thread::Builder::new()
                .name(format!(
                    "legacy_signer_adapter_{}",
                    election_block.block_height
                ))
                .spawn(move || {
                    if let Err(e) = processor.run() {
                        error!("Legacy signer event adapter exited with error: {e:?}");
                    }
                })
                .map_err(|e| {
                    error!("Failed to spawn legacy signer event adapter: {e:?}");
                    ChainstateError::MinerAborted
                })?;
            sc.legacy_listener_thread = Some(listener_thread);
        }

        Ok(sc)
    }

    pub(super) fn publish_native_message(
        &mut self,
        message: &SignerMessageV0,
        reward_cycle: u64,
        burn_view: &ConsensusHash,
        lane: SignerLane,
    ) -> Result<Option<ContentId>, NakamotoNodeError> {
        if !self.native_publish_enabled {
            return Ok(None);
        }
        let Some(network) = self.native_network.as_ref() else {
            return Ok(None);
        };
        let author = StacksPublicKey::from_private(&self.message_key).to_bytes_compressed();
        let (sequence, previous) = self
            .native_sequence_db
            .get_native_signer_sequence(&author, reward_cycle, lane as i32)
            .map_err(|error| {
                NakamotoNodeError::SigningCoordinatorFailure(format!(
                    "failed to load native miner sequence: {error}"
                ))
            })?;
        let local_peer_id = network.local_peer_id().map_err(|error| {
            NakamotoNodeError::SigningCoordinatorFailure(format!(
                "failed to resolve local libp2p PeerId for miner message: {error}"
            ))
        })?;
        let encoded_message = message.serialize_to_vec();
        let proposal = if lane == SignerLane::BlockProposal {
            let SignerMessageV0::BlockProposal(proposal) = message else {
                return Err(NakamotoNodeError::SigningCoordinatorFailure(
                    "block-proposal lane carried a different signer message".into(),
                ));
            };
            let content_id = proposal_content_id(&encoded_message);
            let encoded_len = u64::try_from(encoded_message.len()).map_err(|_| {
                NakamotoNodeError::SigningCoordinatorFailure(
                    "proposal length does not fit its manifest".into(),
                )
            })?;
            Some((
                NetworkObject {
                    kind: ObjectKind::BlockProposal,
                    content_id,
                    bytes: encoded_message.clone(),
                },
                ProposalManifest {
                    version: PROPOSAL_MANIFEST_VERSION,
                    content_id: content_id.as_bytes().to_vec(),
                    encoded_len,
                    signer_signature_hash: proposal.block.header.signer_signature_hash().0.to_vec(),
                    burn_height: proposal.burn_height,
                    reward_cycle: proposal.reward_cycle,
                },
            ))
        } else {
            None
        };
        let body = SignerEnvelopeBody {
            version: SIGNER_ENVELOPE_VERSION,
            chain_id: self.chain_id,
            network_id: self.chain_id,
            reward_cycle,
            lane: lane as i32,
            sequence,
            previous_envelope_id: previous
                .map(|id| id.as_bytes().to_vec())
                .unwrap_or_default(),
            signer_public_key: author.clone(),
            transport_peer_id: local_peer_id.to_bytes(),
            payload: proposal.as_ref().map_or(encoded_message, |_| Vec::new()),
            burn_view_consensus_hash: burn_view.as_bytes().to_vec(),
            proposal_manifest: proposal.as_ref().map(|(_, manifest)| manifest.clone()),
        };
        let signature = self
            .message_key
            .sign(&signer_envelope_digest(&body))
            .map_err(|error| {
                NakamotoNodeError::SigningCoordinatorFailure(format!(
                    "failed to sign native miner envelope: {error}"
                ))
            })?;
        let envelope = SignerEnvelope {
            body: Some(body),
            signature: signature.as_bytes().to_vec(),
        };
        let envelope_id = signer_envelope_id(&envelope).map_err(|error| {
            NakamotoNodeError::SigningCoordinatorFailure(format!(
                "failed to identify native miner envelope: {error}"
            ))
        })?;
        self.native_sequence_db
            .advance_native_signer_sequence(
                &author,
                reward_cycle,
                lane as i32,
                sequence.saturating_add(1),
                &envelope_id,
            )
            .map_err(|error| {
                NakamotoNodeError::SigningCoordinatorFailure(format!(
                    "failed to persist native miner sequence: {error}"
                ))
            })?;
        let publish_result = if let Some((object, _)) = proposal {
            network.publish_proposal(object, envelope)
        } else {
            network.publish_signer(envelope)
        };
        publish_result.map_err(|error| {
            NakamotoNodeError::SigningCoordinatorFailure(format!(
                "failed to queue miner message on native libp2p transport: {error}"
            ))
        })?;
        info!(
            "Queued miner message on native libp2p transport";
            "reward_cycle" => reward_cycle,
            "lane" => ?lane,
            "sequence" => sequence,
            "envelope_id" => ?envelope_id,
        );
        Ok(Some(envelope_id))
    }

    /// Send a message over the miners contract using a `StacksPrivateKey`
    #[allow(clippy::too_many_arguments)]
    pub fn send_miners_message<M: StacksMessageCodec>(
        miner_sk: &StacksPrivateKey,
        sortdb: &SortitionDB,
        tip: &BlockSnapshot,
        stackerdbs: &StackerDBs,
        message: M,
        miner_slot_id: MinerSlotID,
        is_mainnet: bool,
        miners_session: &mut StackerDBSession,
        election_sortition: &ConsensusHash,
        miner_db: &MinerDB,
    ) -> Result<(), NakamotoNodeError> {
        let Some(slot_range) = NakamotoChainState::get_miner_slot(sortdb, tip, election_sortition)
            .map_err(|e| {
                NakamotoNodeError::SigningCoordinatorFailure(format!(
                    "Failed to read miner slot information: {e:?}"
                ))
            })?
        else {
            return Err(NakamotoNodeError::SigningCoordinatorFailure(
                "No slot for miner".into(),
            ));
        };

        let slot_id = slot_range
            .start
            .saturating_add(miner_slot_id.to_u8().into());
        if !slot_range.contains(&slot_id) {
            return Err(NakamotoNodeError::SigningCoordinatorFailure(
                "Not enough slots for miner messages".into(),
            ));
        }
        // Get the LAST slot version number written to the DB. If not found, use 0.
        // Add 1 to get the NEXT version number
        // Note: we already check above for the slot's existence
        let miners_contract_id = boot_code_id(MINERS_NAME, is_mainnet);
        let mut slot_version = stackerdbs
            .get_slot_version(&miners_contract_id, slot_id)
            .map_err(|e| {
                NakamotoNodeError::SigningCoordinatorFailure(format!(
                    "Failed to read slot version: {e:?}"
                ))
            })?
            .unwrap_or(0)
            .saturating_add(1);
        let miner_pk = StacksPublicKey::from_private(miner_sk);
        if let Some(prior_version) = miner_db.get_legacy_adapter_version(&miner_pk, slot_id)? {
            if slot_version <= prior_version {
                slot_version = prior_version.saturating_add(1);
            }
        }

        let mut chunk = StackerDBChunkData::new(slot_id, slot_version, message.serialize_to_vec());
        chunk.sign(miner_sk).map_err(|e| {
            NakamotoNodeError::SigningCoordinatorFailure(format!(
                "Failed to sign StackerDB chunk: {e:?}"
            ))
        })?;

        match miners_session.put_chunk(&chunk) {
            Ok(ack) => {
                if ack.accepted {
                    miner_db.set_legacy_adapter_version(&miner_pk, slot_id, slot_version)?;
                    debug!("Wrote message to stackerdb: {ack:?}");
                    Ok(())
                } else {
                    Err(NakamotoNodeError::StackerDBUploadError(ack.into()))
                }
            }
            Err(e) => Err(NakamotoNodeError::SigningCoordinatorFailure(format!(
                "{e:?}"
            ))),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn enqueue_miner_bridge_message(
        &mut self,
        message: &SignerMessageV0,
        native_envelope_id: Option<ContentId>,
        reward_cycle: u64,
        lane: SignerLane,
        miner_slot_id: MinerSlotID,
        sortdb: &SortitionDB,
        tip: &BlockSnapshot,
        election_sortition: &ConsensusHash,
        burn_view: &ConsensusHash,
    ) -> Result<bool, NakamotoNodeError> {
        self.pump_miner_bridge();
        let Some(bridge) = self.miner_bridge.as_mut() else {
            return Ok(false);
        };
        let Some(slot_range) = NakamotoChainState::get_miner_slot(sortdb, tip, election_sortition)
            .map_err(|error| {
                NakamotoNodeError::SigningCoordinatorFailure(format!(
                    "failed to read miner slot information: {error:?}"
                ))
            })?
        else {
            return Err(NakamotoNodeError::SigningCoordinatorFailure(
                "no slot for miner compatibility message".to_owned(),
            ));
        };
        let slot_id = slot_range
            .start
            .saturating_add(u32::from(miner_slot_id.to_u8()));
        if !slot_range.contains(&slot_id) {
            return Err(NakamotoNodeError::SigningCoordinatorFailure(
                "not enough slots for miner compatibility message".to_owned(),
            ));
        }
        let locator = LegacyLocator {
            contract: boot_code_id(MINERS_NAME, self.is_mainnet).to_string(),
            reward_cycle,
            lane,
            slot_id,
            author: stacks_signer_bridge::LegacyAuthor::PublicKey(
                StacksPublicKey::from_private(&self.message_key)
                    .to_bytes_compressed()
                    .try_into()
                    .expect("compressed Stacks public keys are 33 bytes"),
            ),
            allow_epoch25: false,
        };
        let semantic = libsigner::SignerNetworkMessage {
            reward_cycle,
            lane,
            burn_view_consensus_hash: burn_view.as_bytes().to_vec(),
            payload: message.serialize_to_vec(),
        };
        match bridge.enqueue_origin_egress(
            &semantic,
            native_envelope_id,
            locator,
            &self.message_key,
            stacks::util::get_epoch_time_secs(),
        ) {
            Ok(_) => {
                self.pump_miner_bridge();
                Ok(true)
            }
            Err(TemporarySignerBridgeError::QueueFull) => {
                warn!("Miner compatibility bridge is full; native delivery remains queued");
                Ok(false)
            }
            Err(error) => Err(NakamotoNodeError::SigningCoordinatorFailure(format!(
                "failed to queue miner compatibility bridge message: {error}"
            ))),
        }
    }

    fn pump_miner_bridge(&mut self) {
        let Some(bridge) = self.miner_bridge.as_mut() else {
            return;
        };
        for warning in self
            .miner_bridge_pipeline
            .pump(
                bridge,
                &self.message_key,
                stacks::util::get_epoch_time_secs(),
            )
            .warnings
        {
            warn!("Miner compatibility bridge pipeline: {warning}");
        }
    }

    /// Propose a Nakamoto block and gather signatures for it.
    /// This function begins by sending a `BlockProposal` message to the
    /// signers, and then it waits for the signers to respond with their
    /// signatures. It does so in two ways, concurrently:
    /// * It waits for the signer DB listener to collect enough signatures to
    ///   accept or reject the block
    /// * It waits for the chainstate to contain the relayed block. If so, then its signatures are
    ///   loaded and returned. This can happen if the node receives the block via a signer who
    ///   fetched all signatures and assembled the signature vector, all before we could.
    // Mutants skip here: this function is covered via integration tests,
    //  which the mutation testing does not see.
    #[cfg_attr(test, mutants::skip)]
    #[allow(clippy::too_many_arguments)]
    pub fn propose_block(
        &mut self,
        block: &NakamotoBlock,
        burnchain: &Burnchain,
        sortdb: &SortitionDB,
        chain_state: &mut StacksChainState,
        stackerdbs: &StackerDBs,
        counters: &Counters,
        election_sortition: &BlockSnapshot,
        miner_db: &MinerDB,
        miner_diagnostic_data: MinerDiagnosticData,
    ) -> Result<Vec<MessageSignature>, NakamotoNodeError> {
        // Add this block to the block status map.
        self.signer_comms.insert_block(&block.header);

        let reward_cycle_id = burnchain
            .block_height_to_reward_cycle(election_sortition.block_height)
            .expect("FATAL: tried to initialize coordinator before first burn block height");

        let block_proposal = BlockProposal {
            block: block.clone(),
            burn_height: election_sortition.block_height,
            reward_cycle: reward_cycle_id,
            block_proposal_data: BlockProposalData::from_current_version(miner_diagnostic_data),
        };

        let block_proposal_message = SignerMessageV0::BlockProposal(block_proposal);
        let proposal_id = block.header.signer_signature_hash().to_string();
        stacks::monitoring::begin_libp2p_signer_round(
            proposal_id.clone(),
            block.header.chain_length,
            self.weight_threshold,
            self.total_weight,
        );

        loop {
            debug!("Sending block proposal message to signers";
                "signer_signature_hash" => %block.header.signer_signature_hash(),
            );
            let native_envelope_id = self.publish_native_message(
                &block_proposal_message,
                reward_cycle_id,
                &election_sortition.consensus_hash,
                SignerLane::BlockProposal,
            )?;
            if self.miner_bridge.is_some() {
                self.enqueue_miner_bridge_message(
                    &block_proposal_message,
                    native_envelope_id,
                    reward_cycle_id,
                    SignerLane::BlockProposal,
                    MinerSlotID::BlockProposal,
                    sortdb,
                    election_sortition,
                    &election_sortition.consensus_hash,
                    &election_sortition.consensus_hash,
                )?;
            } else if self.compatibility_stackerdb {
                let miners_session = self.miners_session.as_mut().ok_or_else(|| {
                    NakamotoNodeError::SigningCoordinatorFailure(
                        "legacy signer publication has no compatibility session".into(),
                    )
                })?;
                Self::send_miners_message::<SignerMessageV0>(
                    &self.message_key,
                    sortdb,
                    election_sortition,
                    stackerdbs,
                    block_proposal_message.clone(),
                    MinerSlotID::BlockProposal,
                    self.is_mainnet,
                    miners_session,
                    &election_sortition.consensus_hash,
                    miner_db,
                )?;
            } else if native_envelope_id.is_none() {
                return Err(NakamotoNodeError::SigningCoordinatorFailure(
                    "native signer transport is required when StackerDB compatibility is off"
                        .into(),
                ));
            }
            counters.bump_naka_proposed_blocks();

            #[cfg(test)]
            {
                info!(
                    "SignerCoordinator: sent block proposal to .miners, waiting for test signing channel"
                );
                // In test mode, short-circuit waiting for the signers if the TEST_SIGNING
                //  channel has been created. This allows integration tests for the stacks-node
                //  independent of the stacks-signer.
                if let Some(signatures) =
                    crate::tests::nakamoto_integrations::TestSigningChannel::get_signature()
                {
                    debug!("Short-circuiting waiting for signers, using test signature");
                    stacks::monitoring::set_libp2p_signer_round_status(&proposal_id, "approved");
                    return Ok(signatures);
                }
            }

            let res = self.get_block_status(&block.header, chain_state, sortdb, counters);

            match res {
                Err(NakamotoNodeError::SignatureTimeout) => {
                    stacks::monitoring::set_libp2p_signer_round_status(&proposal_id, "collecting");
                    #[cfg(test)]
                    if crate::nakamoto_node::miner::TEST_MINER_FORCE_REMINE.get() {
                        crate::nakamoto_node::miner::TEST_MINER_FORCE_REMINE.set(false);
                        info!("Abandoning the block proposal and re-mining due to testing directive";
                            "signer_signature_hash" => %block.header.signer_signature_hash(),
                        );
                        return Err(NakamotoNodeError::SignersRejected {
                            temporarily_excluded_txids: HashSet::new(),
                            permanently_excluded_txids: HashSet::new(),
                        });
                    }
                    info!("Block proposal signing process timed out, resending the same proposal");
                    continue;
                }
                Ok(signatures) => {
                    stacks::monitoring::set_libp2p_signer_round_status(&proposal_id, "approved");
                    return Ok(signatures);
                }
                Err(error @ NakamotoNodeError::SignersRejected { .. }) => {
                    stacks::monitoring::set_libp2p_signer_round_status(&proposal_id, "rejected");
                    return Err(error);
                }
                Err(error) => {
                    stacks::monitoring::set_libp2p_signer_round_status(&proposal_id, "timed-out");
                    return Err(error);
                }
            }
        }
    }

    /// Get the block status for a given block hash.
    /// If we have not yet received enough signatures for this block, this
    /// method will block until we do. If this block shows up in the staging DB
    /// before we have enough signatures, we will return the signatures from
    /// there. If a new burnchain tip is detected, we will return an error.
    fn get_block_status(
        &self,
        block_header: &NakamotoBlockHeader,
        chain_state: &mut StacksChainState,
        sortdb: &SortitionDB,
        counters: &Counters,
    ) -> Result<Vec<MessageSignature>, NakamotoNodeError> {
        let block_signer_sighash = &block_header.signer_signature_hash();
        let block_id = &block_header.block_id();
        let parent_block_id = &block_header.parent_block_id;
        let block_consensus_hash = &block_header.consensus_hash;
        // the amount of current rejections (used to eventually modify the timeout)
        let mut rejections: u32 = 0;
        // Unavailability is temporary and never contributes to consensus
        // rejection weight. Track changes only so the miner can retry the
        // same proposal as soon as approval quorum is known to be unavailable.
        let mut unavailable: u32 = 0;
        // default timeout (the 0 entry must be always present)
        let mut rejections_timeout = *self
            .block_rejection_timeout_steps
            .get(&rejections)
            .ok_or_else(|| {
                NakamotoNodeError::SigningCoordinatorFailure(
                    "Invalid rejection timeout step function definition".into(),
                )
            })?;

        let parent_tenure_header =
            NakamotoChainState::get_block_header(chain_state.db(), parent_block_id)?
                .ok_or(NakamotoNodeError::UnexpectedChainState)?;

        // this is used to track the start of the waiting cycle
        let rejections_timer = Instant::now();
        loop {
            if self.miner_abort_flag.load(Ordering::SeqCst) {
                info!("SignCoordinator: Exiting due to miner abort";
                    "signer_signature_hash" => %block_signer_sighash,
                );
                return Err(ChainstateError::MinerAborted.into());
            }
            // At every iteration wait for the block_status.
            // Exit when the amount of confirmations/rejections reaches the threshold (or until timeout)
            // Based on the amount of rejections, eventually modify the timeout.
            let block_status = match self.signer_comms.wait_for_block_status(
                block_signer_sighash,
                EVENT_RECEIVER_POLL,
                |status| {
                    // rejections-based timeout expired?
                    if rejections_timer.elapsed() > rejections_timeout {
                        return false;
                    }
                    // number of rejections changed?
                    if status.total_weight_rejected != rejections {
                        return false;
                    }
                    // availability changed?
                    if status.total_weight_unavailable != unavailable {
                        return false;
                    }
                    // enough signatures?
                    status.total_weight_approved < self.weight_threshold
                },
            )? {
                Some(status) => status,
                None => {
                    // If we just received a timeout, we should check if the burnchain
                    // tip has changed or if we received this signed block already in
                    // the staging db.
                    debug!("SignerCoordinator: Intermediate timeout waiting for block status");

                    // Look in the nakamoto staging db -- a block can only get stored there
                    // if it has enough signing weight to clear the threshold.
                    if let Ok(Some((stored_block, _sz))) = chain_state
                        .nakamoto_blocks_db()
                        .get_nakamoto_block(block_id)
                        .map_err(|e| {
                            warn!(
                                "Failed to query chainstate for block: {e:?}";
                                "block_id" => %block_id,
                                "signer_signature_hash" => %block_signer_sighash,
                            );
                            e
                        })
                    {
                        debug!("SignCoordinator: Found signatures in relayed block");
                        counters.bump_naka_signer_pushed_blocks();
                        return Ok(stored_block.header.signer_signature);
                    }

                    if self.check_burn_tip_changed(sortdb) {
                        debug!("SignCoordinator: Exiting due to new burnchain tip");
                        return Err(NakamotoNodeError::BurnchainTipChanged);
                    }

                    if rejections_timer.elapsed() > rejections_timeout {
                        warn!("Timed out while waiting for responses from signers, resending proposal";
                            "elapsed" => rejections_timer.elapsed().as_secs(),
                            "rejections_timeout" => rejections_timeout.as_secs(),
                            "rejections" => rejections,
                            "rejections_threshold" => self.total_weight.saturating_sub(self.weight_threshold)
                        );

                        if unavailable.saturating_add(self.weight_threshold) > self.total_weight {
                            // A retry may let temporarily unavailable signers
                            // rejoin. Preserve validity judgments for this
                            // exact proposal; only liveness state is retryable.
                            self.signer_comms.reset_unavailable(block_signer_sighash);
                        } else {
                            self.signer_comms.reset_rejections(block_signer_sighash);
                        }

                        return Err(NakamotoNodeError::SignatureTimeout);
                    }

                    // Check if a new Stacks block has arrived in the parent tenure
                    let highest_in_tenure =
                        NakamotoChainState::find_highest_known_block_header_in_tenure(
                            chain_state,
                            sortdb,
                            &parent_tenure_header.consensus_hash,
                        )?
                        .ok_or(NakamotoNodeError::UnexpectedChainState)?;
                    let highest_stacks_block_id = highest_in_tenure.index_block_hash();
                    if &highest_stacks_block_id == block_id {
                        // the block was included in the chainstate since we last checked!
                        let StacksBlockHeaderTypes::Nakamoto(stored_block) =
                            highest_in_tenure.anchored_header
                        else {
                            error!("Nakamoto miner produced a non-nakamoto block");
                            return Err(NakamotoNodeError::UnexpectedChainState);
                        };
                        return Ok(stored_block.signer_signature);
                    } else if &highest_stacks_block_id != parent_block_id {
                        info!("SignCoordinator: Exiting due to new stacks tip";
                              "new_block_hash" => %highest_in_tenure.anchored_header.block_hash(),
                              "new_block_height" => %highest_in_tenure.anchored_header.height(),
                        );
                        return Err(NakamotoNodeError::StacksTipChanged);
                    }

                    // A tenure-start block's parent lives in the previous tenure, so the
                    // check above cannot see a *sibling* tenure-start block landing in the
                    // proposal's own tenure. That happens when an earlier proposal for this
                    // tenure (e.g. from the miner thread this one replaced) is signed and
                    // pushed by the signers while we wait on ours. Without this check the
                    // miner keeps re-proposing a block the signers will never sign.
                    if &parent_tenure_header.consensus_hash != block_consensus_hash {
                        if let Some(highest_in_own_tenure) =
                            NakamotoChainState::find_highest_known_block_header_in_tenure(
                                chain_state,
                                sortdb,
                                block_consensus_hash,
                            )?
                        {
                            if &highest_in_own_tenure.index_block_hash() == block_id {
                                let StacksBlockHeaderTypes::Nakamoto(stored_block) =
                                    highest_in_own_tenure.anchored_header
                                else {
                                    error!("Nakamoto miner produced a non-nakamoto block");
                                    return Err(NakamotoNodeError::UnexpectedChainState);
                                };
                                return Ok(stored_block.signer_signature);
                            }
                            info!("SignCoordinator: Exiting due to a different block in the proposed block's tenure";
                                  "new_block_hash" => %highest_in_own_tenure.anchored_header.block_hash(),
                                  "new_block_height" => %highest_in_own_tenure.anchored_header.height(),
                                  "consensus_hash" => %block_consensus_hash,
                            );
                            return Err(NakamotoNodeError::StacksTipChanged);
                        }
                    }

                    continue;
                }
            };

            if rejections != block_status.total_weight_rejected {
                rejections = block_status.total_weight_rejected;
                let (rejections_step, new_rejections_timeout) = select_rejection_timeout(
                    &self.block_rejection_timeout_steps,
                    rejections,
                    block_status.total_weight_rejected_transient,
                    self.transient_rejection_retry_timeout,
                )
                .ok_or_else(|| {
                    NakamotoNodeError::SigningCoordinatorFailure(
                        "Invalid rejection timeout step function definition".into(),
                    )
                })?;
                rejections_timeout = new_rejections_timeout;
                info!("Number of received rejections updated, resetting timeout";
                                    "rejections" => rejections,
                                    "transient_rejections" => block_status.total_weight_rejected_transient,
                                    "rejections_timeout" => rejections_timeout.as_secs(),
                                    "rejections_step" => rejections_step,
                                    "rejections_threshold" => self.total_weight.saturating_sub(self.weight_threshold));

                counters.set_miner_current_rejections_timeout_secs(rejections_timeout.as_secs());
                counters.set_miner_current_rejections(rejections);
            }

            if unavailable != block_status.total_weight_unavailable {
                unavailable = block_status.total_weight_unavailable;
                info!("Unavailable signer weight updated";
                    "signer_signature_hash" => %block_signer_sighash,
                    "unavailable" => unavailable,
                    "total_weight" => self.total_weight,
                    "weight_threshold" => self.weight_threshold,
                );
            }

            let blocking_minority = self.total_weight.saturating_sub(self.weight_threshold);
            let rejected = block_status
                .total_weight_rejected
                .saturating_add(self.weight_threshold)
                > self.total_weight;
            let resend_after_rejection = rejected
                && should_resend_on_transient_rejection(
                    block_status.total_weight_rejected,
                    block_status.total_weight_rejected_transient,
                    blocking_minority,
                );
            if resend_after_rejection {
                // Keep waiting rather than abandon the block: once the
                // rejections timeout (the transient retry timeout) expires, the
                // same proposal is re-sent and re-evaluated by the signers.
                info!("Block rejected only on transient grounds, re-sending the same proposal after the retry timeout";
                    "signer_signature_hash" => %block_signer_sighash,
                    "total_weight_rejected" => block_status.total_weight_rejected,
                    "transient_weight_rejected" => block_status.total_weight_rejected_transient,
                    "blocking_minority" => blocking_minority,
                    "rejections_timeout" => rejections_timeout.as_secs(),
                );
            }

            if let Some(rejection_error) =
                signer_rejection_error(&block_status, self.total_weight, self.weight_threshold)
                    .filter(|_| !resend_after_rejection)
            {
                info!(
                    "{}/{} signer weight votes to reject block",
                    block_status.total_weight_rejected, self.total_weight;
                    "signer_signature_hash" => %block_signer_sighash,
                );
                counters.bump_naka_rejected_blocks();

                return Err(rejection_error);
            } else if block_status.total_weight_approved >= self.weight_threshold {
                info!("Received enough signatures, block accepted";
                    "signer_signature_hash" => %block_signer_sighash,
                );
                return Ok(block_status.gathered_signatures.values().cloned().collect());
            } else if rejections_timer.elapsed() > rejections_timeout {
                warn!("Timed out while waiting for responses from signers";
                    "elapsed" => rejections_timer.elapsed().as_secs(),
                    "rejections_timeout" => rejections_timeout.as_secs(),
                    "rejections" => rejections,
                    "rejections_threshold" => self.total_weight.saturating_sub(self.weight_threshold)
                );

                if block_status
                    .total_weight_unavailable
                    .saturating_add(self.weight_threshold)
                    > self.total_weight
                {
                    // Do not let an unavailable report create a loop-speed
                    // retry or erase an honest validity judgment. This branch
                    // is reached only after the normal escalating deadline.
                    self.signer_comms.reset_unavailable(block_signer_sighash);
                } else {
                    self.signer_comms.reset_rejections(block_signer_sighash);
                }

                return Err(NakamotoNodeError::SignatureTimeout);
            } else {
                continue;
            }
        }
    }

    /// Get the timestamp at which at least 70% of the signing power should be
    /// willing to accept a time-based tenure extension.
    pub fn get_tenure_extend_timestamp(&self) -> u64 {
        self.signer_comms
            .get_tenure_extend_timestamp(self.weight_threshold)
    }

    /// Get the timestamp at which at least 70% of the signing power should be
    /// willing to accept a time-based read-count extension.
    pub fn get_read_count_extend_timestamp(&self) -> u64 {
        self.signer_comms
            .get_read_count_extend_timestamp(self.weight_threshold)
    }

    /// Get the signer global state view if there is one
    pub fn get_signer_global_state(&self) -> Option<SignerStateMachine> {
        self.signer_comms.get_signer_global_state()
    }

    /// Check if the tenure needs to change
    fn check_burn_tip_changed(&self, sortdb: &SortitionDB) -> bool {
        let cur_burn_chain_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
            .expect("FATAL: failed to query sortition DB for canonical burn chain tip");

        if cur_burn_chain_tip.consensus_hash != self.burn_tip_at_start {
            info!("SignCoordinator: Cancel signature aggregation; burnchain tip has changed");
            true
        } else {
            false
        }
    }

    pub fn shutdown(&mut self) {
        if let Some(registration) = self.native_signer_registration.take() {
            self.native_signer_router.unregister(registration);
        }
        if self.legacy_listener_thread.is_some() || self.native_listener_thread.is_some() {
            self.keep_running
                .store(false, std::sync::atomic::Ordering::Relaxed);
        }
        if let Some(listener_thread) = self.native_listener_thread.take() {
            info!("SignerCoordinator: shutting down native signer adapter thread");
            if let Err(error) = listener_thread.join() {
                error!("Failed to join native signer adapter thread: {error:?}");
            }
        }
        if let Some(listener_thread) = self.legacy_listener_thread.take() {
            info!("SignerCoordinator: shutting down legacy signer adapter thread");
            if let Err(e) = listener_thread.join() {
                error!("Failed to join signer listener thread: {e:?}");
            }
            debug!("SignerCoordinator: legacy signer adapter thread has shut down");
        }
        let Self {
            miner_bridge,
            miner_bridge_pipeline,
            message_key,
            ..
        } = self;
        if let Some(bridge) = miner_bridge.as_mut() {
            if let Err(error) = miner_bridge_pipeline.shutdown(|pipeline| {
                for warning in pipeline
                    .pump(bridge, message_key, stacks::util::get_epoch_time_secs())
                    .warnings
                {
                    warn!("Miner compatibility bridge pipeline: {warning}");
                }
            }) {
                error!("Failed to join miner compatibility bridge: {error:?}");
            }
        } else if let Err(error) = miner_bridge_pipeline.shutdown(|_| {}) {
            error!("Failed to join miner compatibility bridge: {error:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use super::{
        build_block_rejection_timeout_steps, select_rejection_timeout,
        should_resend_on_transient_rejection,
    };

    #[test]
    fn timeout_steps_keep_longest_on_collisions() {
        let mut steps = HashMap::new();
        steps.insert(0, Duration::from_secs(180));
        steps.insert(10, Duration::from_secs(90));
        steps.insert(20, Duration::from_secs(45));
        steps.insert(30, Duration::from_secs(0));

        let built = build_block_rejection_timeout_steps(3, &steps);

        assert_eq!(built.len(), 1);
        assert_eq!(built.get(&0), Some(&Duration::from_secs(180)));
    }

    #[test]
    fn timeout_steps_distinct_with_normal_weight() {
        let mut steps = HashMap::new();
        steps.insert(0, Duration::from_secs(180));
        steps.insert(10, Duration::from_secs(90));
        steps.insert(20, Duration::from_secs(45));
        steps.insert(30, Duration::from_secs(0));

        let built = build_block_rejection_timeout_steps(100, &steps);

        assert_eq!(built.get(&0), Some(&Duration::from_secs(180)));
        assert_eq!(built.get(&10), Some(&Duration::from_secs(90)));
        assert_eq!(built.get(&20), Some(&Duration::from_secs(45)));
        assert_eq!(built.get(&30), Some(&Duration::from_secs(0)));
    }

    fn default_steps(total_weight: u32) -> std::collections::BTreeMap<u32, Duration> {
        let mut steps = HashMap::new();
        steps.insert(0, Duration::from_secs(180));
        steps.insert(10, Duration::from_secs(90));
        steps.insert(20, Duration::from_secs(45));
        steps.insert(30, Duration::from_secs(0));
        build_block_rejection_timeout_steps(total_weight, &steps)
    }

    #[test]
    fn rejection_timeout_follows_steps_without_transient_rejections() {
        let steps = default_steps(100);
        let retry = Duration::from_secs(5);

        assert_eq!(
            select_rejection_timeout(&steps, 0, 0, retry),
            Some((0, Duration::from_secs(180)))
        );
        assert_eq!(
            select_rejection_timeout(&steps, 15, 0, retry),
            Some((10, Duration::from_secs(90)))
        );
        assert_eq!(
            select_rejection_timeout(&steps, 25, 0, retry),
            Some((20, Duration::from_secs(45)))
        );
    }

    #[test]
    fn rejection_timeout_set_by_transient_rejections() {
        let steps = default_steps(100);
        let retry = Duration::from_secs(5);

        // All rejections are transient
        assert_eq!(
            select_rejection_timeout(&steps, 15, 15, retry),
            Some((10, retry))
        );
        // Mixed rejections: any transient weight selects the retry timeout
        assert_eq!(
            select_rejection_timeout(&steps, 25, 5, retry),
            Some((20, retry))
        );
        // A shorter step timeout is lengthened, so the miner does not re-send
        // before the transient rejecters have had time to catch up
        assert_eq!(
            select_rejection_timeout(&steps, 30, 10, retry),
            Some((30, retry))
        );
        assert_eq!(
            select_rejection_timeout(&steps, 35, 10, retry),
            Some((30, retry))
        );
        // Without transient rejections, the step applies
        assert_eq!(
            select_rejection_timeout(&steps, 35, 0, retry),
            Some((30, Duration::from_secs(0)))
        );
    }

    #[test]
    fn resend_only_when_substantive_rejections_within_blocking_minority() {
        let blocking_minority = 30;
        // All rejections are transient
        assert!(should_resend_on_transient_rejection(
            35,
            35,
            blocking_minority
        ));
        // Substantive rejections alone do not exceed the blocking minority
        assert!(should_resend_on_transient_rejection(
            50,
            20,
            blocking_minority
        ));
        // Substantive rejections alone exceed the blocking minority
        assert!(!should_resend_on_transient_rejection(
            50,
            19,
            blocking_minority
        ));
        // No transient rejections
        assert!(!should_resend_on_transient_rejection(
            35,
            0,
            blocking_minority
        ));
    }
}
