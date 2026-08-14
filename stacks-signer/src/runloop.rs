// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2024 Stacks Open Internet Foundation
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
use std::fmt::Debug;
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use clarity::codec::StacksMessageCodec;
use hashbrown::HashMap;
use libsigner::v0::messages::SignerMessageTypePrefix;
use libsigner::{AuthenticatedSignerEvent, SignerEntries, SignerEvent, SignerRunLoop};
use stacks_common::types::chainstate::StacksPublicKey;
use stacks_common::{debug, error, info, warn};
use stacks_network_types::wire::v1::SignerLane;
use stacks_network_types::BridgeMode;

use crate::chainstate::v1::SortitionsView;
use crate::client::{retry_with_exponential_backoff, ClientError, SignerSlotID, StacksClient};
use crate::config::{GlobalConfig, SignerConfig, SignerConfigMode};
use crate::signerdb::BlockInfo;
use crate::v0::signer_state::LocalStateMachine;
#[cfg(any(test, feature = "testing"))]
use crate::v0::tests::TEST_SKIP_SIGNER_CLEANUP;
use crate::Signer as SignerTrait;

/// A libp2p-only signer can start before PoX-4 reward-set queries are
/// available.  It cannot wait for the legacy burn-block callback to retry,
/// because that callback is deliberately disabled.  Keep this retry slow and
/// bounded so bootstrap cannot turn an unavailable node into a tight RPC loop.
const COMPANION_REFRESH_RETRY_INTERVAL: Duration = Duration::from_secs(5);

/// Resume the bounded RPC safety-net if the authenticated companion stream goes
/// quiet.  This is deliberately longer than the PoC's steady-state Bitcoin
/// cadence, so a healthy companion remains the authoritative event source while
/// a dropped role record or connection can still heal without a restart.
const COMPANION_STATE_STALE_AFTER: Duration = Duration::from_secs(45);

/// Chain-view refresh is a control-plane liveness probe, not a block-validation
/// obligation. Keep it independently short so a stalled companion cannot hold
/// the synchronous signer runloop for the much longer validation horizon and
/// delay already-authenticated availability observations.
const COMPANION_STATE_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// A companion emits its durable burn-block callback just before the same
/// block becomes queryable from its RPC thread. Do not install a perpetually
/// one-sortition-behind miner snapshot from that short ordering window.
const MINER_AUTHORIZATION_CATCHUP_TIMEOUT: Duration = Duration::from_secs(2);
const MINER_AUTHORIZATION_CATCHUP_POLL: Duration = Duration::from_millis(50);

/// Translate one authenticated native transport event into the existing signer
/// event boundary. Keeping this conversion independent of queue draining lets
/// production-path tests prove that the exact released envelope, rather than a
/// separately reconstructed proposal, reaches signer policy.
pub(crate) fn authenticated_native_event<T>(
    authenticated: AuthenticatedSignerEvent,
) -> Option<SignerEvent<T>>
where
    T: StacksMessageCodec + Clone + Send + Debug,
{
    if authenticated.is_equivocation {
        warn!(
            "Retained native signer equivocation without applying conflicting payload";
            "event_id" => ?authenticated.event_id(),
        );
        return None;
    }
    let lane = authenticated.message.lane;
    if matches!(lane, SignerLane::Control | SignerLane::ProposalUnavailable) {
        return None;
    }
    let Some(prefix) = authenticated
        .message
        .payload
        .first()
        .and_then(|prefix| SignerMessageTypePrefix::from_u8(*prefix))
    else {
        warn!("Authenticated signer event has no recognized payload prefix");
        return None;
    };
    let expected_lane = match prefix {
        SignerMessageTypePrefix::BlockProposal => SignerLane::BlockProposal,
        SignerMessageTypePrefix::BlockResponse | SignerMessageTypePrefix::MockSignature => {
            SignerLane::BlockResponse
        }
        SignerMessageTypePrefix::BlockPushed => SignerLane::BlockPushed,
        SignerMessageTypePrefix::StateMachineUpdate => SignerLane::StateMachineUpdate,
        SignerMessageTypePrefix::BlockPreCommit => SignerLane::BlockPreCommit,
        SignerMessageTypePrefix::MockProposal | SignerMessageTypePrefix::MockBlock => {
            warn!("Epoch-2.5 miner-only payload is not valid on native signer transport");
            return None;
        }
    };
    if lane != expected_lane {
        warn!(
            "Rejected native signer event with mismatched lane and payload";
            "lane" => ?lane,
            "payload_type" => ?prefix,
        );
        return None;
    }
    let Some(author_public_key) = authenticated.author_public_key() else {
        warn!("Authenticated signer event has no author public key evidence");
        return None;
    };
    let Ok(public_key) = StacksPublicKey::from_slice(author_public_key) else {
        warn!("Authenticated signer event has an invalid author public key");
        return None;
    };
    let mut payload = authenticated.message.payload.as_slice();
    let Ok(message) = T::consensus_deserialize(&mut payload) else {
        warn!("Failed to deserialize authenticated native signer payload");
        return None;
    };
    if !payload.is_empty() {
        warn!("Rejected authenticated native signer payload with trailing bytes");
        return None;
    }
    match lane {
        SignerLane::BlockProposal | SignerLane::BlockPushed => {
            Some(SignerEvent::MinerMessages(vec![message]))
        }
        SignerLane::BlockResponse | SignerLane::BlockPreCommit | SignerLane::StateMachineUpdate => {
            Some(SignerEvent::SignerMessages {
                signer_set: (authenticated.message.reward_cycle % 2) as u32,
                messages: vec![(0, public_key, message)],
                received_time: std::time::SystemTime::now(),
            })
        }
        SignerLane::Unspecified | SignerLane::Control | SignerLane::ProposalUnavailable => None,
    }
}

#[derive(thiserror::Error, Debug)]
#[allow(clippy::large_enum_variant)]
/// Configuration error type
pub enum ConfigurationError {
    /// Error occurred while fetching data from the stacks node
    #[error("{0}")]
    ClientError(#[from] ClientError),
    /// The stackerdb signer config is not yet updated
    #[error("The stackerdb config is not yet updated")]
    StackerDBNotUpdated,
    /// The signer binary is configured as dry-run, but is also registered for this cycle
    #[error("The signer binary is configured as dry-run, but is also registered for this cycle")]
    DryRunStackerIsRegistered,
}

/// The internal signer state info
#[derive(PartialEq, Clone, Debug)]
pub struct StateInfo {
    /// the runloop state
    pub runloop_state: State,
    /// the current reward cycle info
    pub reward_cycle_info: Option<RewardCycleInfo>,
    /// The current running signers reward cycles
    pub running_signers: Vec<u64>,
    /// The local state machines for the running signers
    ///  as a pair of (reward-cycle, state-machine)
    pub signer_state_machines: Vec<(u64, Option<LocalStateMachine>)>,
    /// The number of pending block proposals for this signer
    pub pending_proposals_count: u64,
    /// The canonical tip block info according to the running signers
    /// as a pair of (reward-cycle, block-info)
    pub signer_canonical_tips: Vec<(u64, Option<BlockInfo>)>,
}

/// The signer result that can be sent across threads
pub enum SignerResult {
    /// The signer has received a status check
    StatusCheck(StateInfo),
}

impl From<StateInfo> for SignerResult {
    fn from(state_info: StateInfo) -> Self {
        SignerResult::StatusCheck(state_info)
    }
}

/// The runloop state
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum State {
    /// The runloop is uninitialized
    Uninitialized,
    /// The runloop has no registered signers
    NoRegisteredSigners,
    /// The runloop has registered signers
    RegisteredSigners,
}

/// The current reward cycle info
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct RewardCycleInfo {
    /// The current reward cycle
    pub reward_cycle: u64,
    /// The total reward cycle length
    pub reward_cycle_length: u64,
    /// The prepare phase length
    pub prepare_phase_block_length: u64,
    /// The first burn block height
    pub first_burnchain_block_height: u64,
    /// The burnchain block height of the last query
    pub last_burnchain_block_height: u64,
}

impl RewardCycleInfo {
    /// Check if the provided burnchain block height is part of the reward cycle
    pub const fn is_in_reward_cycle(&self, burnchain_block_height: u64) -> bool {
        let blocks_mined = burnchain_block_height.saturating_sub(self.first_burnchain_block_height);
        let reward_cycle = blocks_mined / self.reward_cycle_length;
        self.reward_cycle == reward_cycle
    }

    /// Get the reward cycle for a specific burnchain block height
    pub const fn get_reward_cycle(&self, burnchain_block_height: u64) -> u64 {
        let blocks_mined = burnchain_block_height.saturating_sub(self.first_burnchain_block_height);
        blocks_mined / self.reward_cycle_length
    }

    /// The modulo-0 boundary is signed by the new cycle, but a late
    /// `BlockFound` for the preceding sortition can still require the previous
    /// signer instance before the burnchain advances again.
    pub const fn is_nakamoto_signing_cycle_start(&self, burnchain_block_height: u64) -> bool {
        burnchain_block_height >= self.first_burnchain_block_height
            && self.reward_cycle_length != 0
            && (burnchain_block_height - self.first_burnchain_block_height)
                .is_multiple_of(self.reward_cycle_length)
    }

    /// Check if the provided burnchain block height is in the prepare phase of the next cycle
    pub fn is_in_next_prepare_phase(&self, burnchain_block_height: u64) -> bool {
        let effective_height = burnchain_block_height - self.first_burnchain_block_height;
        let reward_index = effective_height % self.reward_cycle_length;

        reward_index >= (self.reward_cycle_length - self.prepare_phase_block_length)
            && self.get_reward_cycle(burnchain_block_height) == self.reward_cycle
    }
}

/// The configuration state for a reward cycle.
/// Allows us to track if we've registered a signer for a cycle or not
///  and to differentiate between being unregistered and simply not configured
pub enum ConfiguredSigner<Signer, T>
where
    Signer: SignerTrait<T>,
    T: StacksMessageCodec + Clone + Send + Debug,
{
    /// Signer is registered for the cycle and ready to process messages
    RegisteredSigner(Signer),
    /// The signer runloop isn't registered for this cycle (i.e., we've checked the
    ///   the signer set and we're not in it)
    NotRegistered {
        /// the cycle number we're not registered for
        cycle: u64,
        /// Phantom data for the message codec
        _phantom_state: std::marker::PhantomData<T>,
    },
}

impl<Signer: SignerTrait<T>, T: StacksMessageCodec + Clone + Send + Debug> std::fmt::Display
    for ConfiguredSigner<Signer, T>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RegisteredSigner(s) => write!(f, "{s}"),
            Self::NotRegistered { cycle, .. } => write!(f, "NotRegistered in Cycle #{cycle}"),
        }
    }
}

impl<Signer: SignerTrait<T>, T: StacksMessageCodec + Clone + Send + Debug>
    ConfiguredSigner<Signer, T>
{
    /// Create a `NotRegistered` instance of the enum (so that callers do not need
    ///  to supply phantom_state data).
    pub fn not_registered(cycle: u64) -> Self {
        Self::NotRegistered {
            cycle,
            _phantom_state: std::marker::PhantomData,
        }
    }

    /// The reward cycle this signer is configured for
    pub fn reward_cycle(&self) -> u64 {
        match self {
            ConfiguredSigner::RegisteredSigner(s) => s.reward_cycle(),
            ConfiguredSigner::NotRegistered { cycle, .. } => *cycle,
        }
    }
}

/// The runloop for the stacks signer
pub struct RunLoop<Signer, T>
where
    Signer: SignerTrait<T>,
    T: StacksMessageCodec + Clone + Send + Debug,
{
    /// Configuration info
    pub config: GlobalConfig,
    /// The stacks node client
    pub stacks_client: StacksClient,
    companion_state_client: StacksClient,
    /// The internal signer for an odd or even reward cycle
    /// Keyed by reward cycle % 2
    pub stacks_signers: HashMap<u64, ConfiguredSigner<Signer, T>>,
    /// The state of the runloop
    pub state: State,
    /// The current reward cycle info. Only None if the runloop is uninitialized
    pub current_reward_cycle_info: Option<RewardCycleInfo>,
    /// Cache sortitin data from `stacks-node`
    pub sortition_state: Option<SortitionsView>,
    /// Process-wide native signer network shared by current/next cycle signers.
    signer_network: Option<crate::network::SignerNetworkHandle>,
    /// Locally authorized signer ID for each configured reward cycle.
    local_signer_ids: HashMap<u64, u32>,
    /// Earliest time a signer may retry companion state refresh after its
    /// authenticated observer stream goes stale.
    next_companion_state_refresh: Instant,
    /// Last authenticated burn-block callback from this signer's companion.
    last_companion_burn_event: Option<Instant>,
}

impl<Signer: SignerTrait<T>, T: StacksMessageCodec + Clone + Send + Debug> RunLoop<Signer, T> {
    /// Create a new signer runloop from the provided configuration
    pub fn new(config: GlobalConfig) -> Self {
        Self::with_signer_network(config, None)
    }

    /// Create a signer runloop with an optional native signer network.
    pub fn with_signer_network(
        config: GlobalConfig,
        signer_network: Option<crate::network::SignerNetworkHandle>,
    ) -> Self {
        // Proposal validation and chain-view liveness have different timeout
        // budgets. Sharing the validation horizon with control-plane probes
        // lets a paused companion block the signer runloop long after a local
        // availability observation is ready.
        let stacks_client = StacksClient::from(&config)
            .with_request_timeout(config.block_proposal_validation_timeout)
            .expect("failed to construct bounded Stacks node HTTP client");
        let companion_state_client = StacksClient::from(&config)
            .with_request_timeout(COMPANION_STATE_REQUEST_TIMEOUT)
            .expect("failed to construct bounded companion state HTTP client");
        Self {
            config,
            stacks_client,
            companion_state_client,
            stacks_signers: HashMap::with_capacity(2),
            state: State::Uninitialized,
            current_reward_cycle_info: None,
            sortition_state: None,
            signer_network,
            local_signer_ids: HashMap::with_capacity(2),
            next_companion_state_refresh: Instant::now(),
            last_companion_burn_event: None,
        }
    }
    /// Get the registered signers for a specific reward cycle
    /// Returns None if no signers are registered or its not Nakamoto cycle
    pub fn get_parsed_reward_set(
        &self,
        reward_cycle: u64,
    ) -> Result<Option<SignerEntries>, ClientError> {
        debug!("Getting registered signers for reward cycle {reward_cycle}...");
        let Some(signers) = self.stacks_client.get_reward_set_signers(reward_cycle)? else {
            warn!("No reward set signers found for reward cycle {reward_cycle}.");
            return Ok(None);
        };
        if signers.is_empty() {
            warn!("No registered signers found for reward cycle {reward_cycle}.");
            return Ok(None);
        }
        let entries = SignerEntries::parse(self.config.network.is_mainnet(), &signers).unwrap();
        Ok(Some(entries))
    }

    /// Get a signer configuration for a specific reward cycle from the stacks node
    fn get_signer_config(
        &mut self,
        reward_cycle: u64,
    ) -> Result<Option<SignerConfig>, ConfigurationError> {
        // We can only register for a reward cycle if a reward set exists.
        let signer_entries = match self.get_parsed_reward_set(reward_cycle) {
            Ok(Some(x)) => x,
            Ok(None) => return Ok(None),
            Err(e) => {
                warn!("Error while fetching reward set {reward_cycle}: {e:?}");
                return Err(e.into());
            }
        };

        if let Some(network) = self.signer_network.as_ref() {
            let public_keys = signer_entries
                .signer_pks
                .iter()
                .map(|public_key| {
                    public_key
                        .to_bytes_compressed()
                        .try_into()
                        .expect("compressed Stacks public keys are exactly 33 bytes")
                })
                .collect();
            if let Err(error) = network.update_authorized_signers(reward_cycle, public_keys) {
                warn!(
                    "Failed to update native signer-network reward-set authorization";
                    "reward_cycle" => reward_cycle,
                    "error" => %error,
                );
            }
        }

        let requires_legacy_slots =
            !self.config.libp2p.enabled || self.config.libp2p.signer_bridge.mode != BridgeMode::Off;
        let signer_slot_ids = if requires_legacy_slots {
            // The quarantined compatibility boundary still needs the legacy
            // contract's exact slot assignment while mixed-version signers
            // exist. Native-only operation never reads this state.
            let last_calculated_reward_cycle =
                self.stacks_client.get_last_set_cycle().map_err(|e| {
                    warn!(
                        "Failed to fetch last calculated StackerDB cycle for compatibility mode";
                        "reward_cycle" => reward_cycle,
                        "err" => ?e
                    );
                    ConfigurationError::StackerDBNotUpdated
                })?;
            if last_calculated_reward_cycle < reward_cycle as u128 {
                warn!(
                    "Compatibility StackerDB has not been updated for reward cycle {reward_cycle}. Last calculated reward cycle is {last_calculated_reward_cycle}."
                );
                return Err(ConfigurationError::StackerDBNotUpdated);
            }
            self.stacks_client
                .get_parsed_signer_slots(reward_cycle)
                .map_err(|e| {
                    warn!(
                        "Error while fetching compatibility StackerDB slots {reward_cycle}: {e:?}"
                    );
                    e
                })?
        } else {
            signer_entries
                .signer_addr_to_id
                .iter()
                .map(|(address, signer_id)| (address.clone(), SignerSlotID(*signer_id)))
                .collect()
        };

        let dry_run = self.config.dry_run;
        let current_addr = self.stacks_client.get_signer_address();

        let signer_config_mode = if !dry_run {
            let Some(signer_slot_id) = signer_slot_ids.get(current_addr) else {
                warn!(
                    "Signer {current_addr} was not found in the active signer membership. Must not be registered for reward cycle {reward_cycle}."
                );
                return Ok(None);
            };
            let Some(signer_id) = signer_entries.signer_addr_to_id.get(current_addr) else {
                warn!(
                    "Signer {current_addr} has a transport slot but is not in the reward set for reward cycle {reward_cycle}."
                );
                return Ok(None);
            };
            info!(
                "Signer #{signer_id} ({current_addr}) is registered for reward cycle {reward_cycle}."
            );
            SignerConfigMode::Normal {
                signer_slot_id: *signer_slot_id,
                signer_id: *signer_id,
            }
        } else {
            if signer_slot_ids.contains_key(current_addr) {
                error!(
                    "Signer is configured for dry-run, but {current_addr} is in the active signer membership."
                );
                return Err(ConfigurationError::DryRunStackerIsRegistered);
            };
            if signer_entries.signer_addr_to_id.contains_key(current_addr) {
                warn!(
                    "Signer {current_addr} has a transport slot but is not in the reward set for reward cycle {reward_cycle}."
                );
                return Ok(None);
            };
            SignerConfigMode::DryRun
        };
        Ok(Some(SignerConfig {
            reward_cycle,
            signer_mode: signer_config_mode,
            signer_entries,
            signer_slot_ids: signer_slot_ids.into_values().collect(),
            first_proposal_burn_block_timing: self.config.first_proposal_burn_block_timing,
            stacks_private_key: self.config.stacks_private_key.clone(),
            node_host: self.config.node_host.to_string(),
            mainnet: self.config.network.is_mainnet(),
            db_path: self.config.db_path.clone(),
            block_proposal_timeout: self.config.block_proposal_timeout,
            tenure_last_block_proposal_timeout: self.config.tenure_last_block_proposal_timeout,
            block_proposal_validation_timeout: self.config.block_proposal_validation_timeout,
            tenure_idle_timeout: self.config.tenure_idle_timeout,
            tenure_idle_timeout_buffer: self.config.tenure_idle_timeout_buffer,
            read_count_idle_timeout: self.config.read_count_idle_timeout,
            block_proposal_max_age_secs: self.config.block_proposal_max_age_secs,
            reorg_attempts_activity_timeout: self.config.reorg_attempts_activity_timeout,
            proposal_wait_for_parent_time: self.config.proposal_wait_for_parent_time,
            validate_with_replay_tx: self.config.validate_with_replay_tx,
            reset_replay_set_after_fork_blocks: self.config.reset_replay_set_after_fork_blocks,
            capitulate_miner_view_timeout: self.config.capitulate_miner_view_timeout,
            #[cfg(any(test, feature = "testing"))]
            legacy_test_adapter_timeout: self.config.stackerdb_timeout,
            #[cfg(any(test, feature = "testing"))]
            supported_signer_protocol_version: self.config.supported_signer_protocol_version,
        }))
    }

    /// Refresh signer configuration for a specific reward cycle
    fn refresh_signer_config(&mut self, reward_cycle: u64) {
        let reward_index = reward_cycle % 2;
        let new_signer_config = match self.get_signer_config(reward_cycle) {
            Ok(Some(new_signer_config)) => {
                let signer_mode = new_signer_config.signer_mode.clone();
                match &signer_mode {
                    SignerConfigMode::Normal { signer_id, .. } => {
                        self.local_signer_ids.insert(reward_cycle, *signer_id);
                    }
                    SignerConfigMode::DryRun => {
                        self.local_signer_ids.remove(&reward_cycle);
                    }
                }
                if self.config.libp2p.signer_bridge.mode != BridgeMode::Off {
                    if let (Some(network), SignerConfigMode::Normal { signer_slot_id, .. }) =
                        (self.signer_network.as_ref(), &signer_mode)
                    {
                        if let Err(error) = network.configure_legacy_cycle(
                            reward_cycle,
                            signer_slot_id.0,
                            new_signer_config.mainnet,
                        ) {
                            warn!(
                                "Failed to configure temporary signer compatibility bridge";
                                "reward_cycle" => reward_cycle,
                                "signer_slot_id" => signer_slot_id.0,
                                "error" => %error,
                            );
                        }
                    }
                }
                let mut new_signer = Signer::new(&self.stacks_client, new_signer_config);
                new_signer.set_signer_network(self.signer_network.clone());
                info!(
                    "{new_signer} Signer is registered for reward cycle {reward_cycle} as {signer_mode}. Initialized signer state."
                );
                ConfiguredSigner::RegisteredSigner(new_signer)
            }
            Ok(None) => {
                self.local_signer_ids.remove(&reward_cycle);
                warn!("Signer is not registered for reward cycle {reward_cycle}");
                ConfiguredSigner::not_registered(reward_cycle)
            }
            Err(e) => {
                warn!("Failed to get the reward set info: {e}. Will try again later.");
                return;
            }
        };

        self.stacks_signers.insert(reward_index, new_signer_config);
    }

    fn initialize_runloop(&mut self) -> Result<(), ClientError> {
        debug!("Initializing signer runloop...");
        let reward_cycle_info = retry_with_exponential_backoff(|| {
            self.stacks_client
                .get_current_reward_cycle_info()
                .map_err(backoff::Error::transient)
        })?;
        let current_reward_cycle = reward_cycle_info.reward_cycle;
        self.current_reward_cycle_info = Some(reward_cycle_info);
        if current_reward_cycle > 0
            && reward_cycle_info
                .is_nakamoto_signing_cycle_start(reward_cycle_info.last_burnchain_block_height)
        {
            // A restart at modulo 0 must still be able to finish the late
            // BlockFound for the preceding sortition.
            self.refresh_signer_config(current_reward_cycle - 1);
        }
        self.refresh_signer_config(current_reward_cycle);
        // We should only attempt to initialize the next reward cycle signer if we are in the prepare phase of the next reward cycle
        if reward_cycle_info.is_in_next_prepare_phase(reward_cycle_info.last_burnchain_block_height)
        {
            self.refresh_signer_config(current_reward_cycle.saturating_add(1));
        }
        self.update_network_cycles(current_reward_cycle);
        self.refresh_miner_authorizations(
            current_reward_cycle,
            reward_cycle_info.last_burnchain_block_height,
        );
        if self.stacks_signers.is_empty() {
            self.state = State::NoRegisteredSigners;
        } else {
            self.state = State::RegisteredSigners;
        }
        Ok(())
    }

    fn refresh_runloop(&mut self, ev_burn_block_height: u64) -> Result<(), ClientError> {
        let current_burn_block_height = std::cmp::max(
            self.companion_state_client
                .get_peer_info()?
                .burn_block_height,
            ev_burn_block_height,
        );
        let reward_cycle_info = self
            .current_reward_cycle_info
            .as_mut()
            .expect("FATAL: cannot be an initialized signer with no reward cycle info.");
        let current_reward_cycle = reward_cycle_info.reward_cycle;
        let block_reward_cycle = reward_cycle_info.get_reward_cycle(current_burn_block_height);

        // First ensure we refresh our view of the current reward cycle information
        if block_reward_cycle != current_reward_cycle {
            let new_reward_cycle_info = RewardCycleInfo {
                reward_cycle: block_reward_cycle,
                reward_cycle_length: reward_cycle_info.reward_cycle_length,
                prepare_phase_block_length: reward_cycle_info.prepare_phase_block_length,
                first_burnchain_block_height: reward_cycle_info.first_burnchain_block_height,
                last_burnchain_block_height: current_burn_block_height,
            };
            *reward_cycle_info = new_reward_cycle_info;
        }
        let reward_cycle_before_refresh = current_reward_cycle;
        let current_reward_cycle = reward_cycle_info.reward_cycle;
        let is_in_next_prepare_phase =
            reward_cycle_info.is_in_next_prepare_phase(current_burn_block_height);
        let is_nakamoto_signing_cycle_start =
            reward_cycle_info.is_nakamoto_signing_cycle_start(current_burn_block_height);
        let next_reward_cycle = current_reward_cycle.saturating_add(1);

        info!(
            "Refreshing runloop with new burn block event";
            "latest_node_burn_ht" => current_burn_block_height,
            "event_ht" =>  ev_burn_block_height,
            "reward_cycle_before_refresh" => reward_cycle_before_refresh,
            "current_reward_cycle" => current_reward_cycle,
            "configured_for_current" => Self::is_configured_for_cycle(&self.stacks_signers, current_reward_cycle),
            "registered_for_current" => Self::is_registered_for_cycle(&self.stacks_signers, current_reward_cycle),
            "configured_for_next" => Self::is_configured_for_cycle(&self.stacks_signers, next_reward_cycle),
            "registered_for_next" => Self::is_registered_for_cycle(&self.stacks_signers, next_reward_cycle),
            "is_in_next_prepare_phase" => is_in_next_prepare_phase,
        );

        // Check if we need to refresh the signers:
        //   need to refresh the current signer if we are not configured for the current reward cycle
        //   need to refresh the next signer if we're not configured for the next reward cycle, and we're in the prepare phase
        if !Self::is_configured_for_cycle(&self.stacks_signers, current_reward_cycle) {
            self.refresh_signer_config(current_reward_cycle);
        }
        if is_in_next_prepare_phase
            && !Self::is_configured_for_cycle(&self.stacks_signers, next_reward_cycle)
        {
            self.refresh_signer_config(next_reward_cycle);
        }

        self.cleanup_stale_signers(current_reward_cycle, is_nakamoto_signing_cycle_start);
        self.update_network_cycles(current_reward_cycle);
        self.refresh_miner_authorizations(current_reward_cycle, current_burn_block_height);
        if self.stacks_signers.is_empty() {
            self.state = State::NoRegisteredSigners;
        } else {
            self.state = State::RegisteredSigners;
        }
        Ok(())
    }

    fn update_network_cycles(&self, current_reward_cycle: u64) {
        let mut active_cycles = self
            .stacks_signers
            .values()
            .map(ConfiguredSigner::reward_cycle)
            .filter(|cycle| {
                *cycle >= current_reward_cycle.saturating_sub(1)
                    && *cycle <= current_reward_cycle.saturating_add(1)
            })
            .collect::<Vec<_>>();
        active_cycles.sort_unstable();
        active_cycles.dedup();
        let retained_current = active_cycles
            .first()
            .copied()
            .unwrap_or(current_reward_cycle);
        let retained_next = active_cycles.get(1).copied();
        if let Some(network) = self.signer_network.as_ref() {
            if let Err(error) = network.update_cycles(retained_current, retained_next) {
                warn!(
                    "Failed to update native signer-network reward cycles";
                    "current_reward_cycle" => current_reward_cycle,
                    "retained_current" => retained_current,
                    "retained_next" => ?retained_next,
                    "error" => %error,
                );
                return;
            }
            if let Some(info) = self.current_reward_cycle_info.as_ref() {
                for cycle in active_cycles {
                    let Some(signer_id) = self.local_signer_ids.get(&cycle).copied() else {
                        continue;
                    };
                    let cycle_start = info
                        .first_burnchain_block_height
                        .saturating_add(cycle.saturating_mul(info.reward_cycle_length));
                    let valid_from = cycle_start.saturating_sub(info.prepare_phase_block_length);
                    let valid_until = cycle_start
                        .saturating_add(info.reward_cycle_length)
                        .saturating_sub(1)
                        .max(info.last_burnchain_block_height);
                    if let Err(error) = network.install_role_record(
                        cycle,
                        signer_id,
                        info.last_burnchain_block_height,
                        valid_from,
                        valid_until,
                    ) {
                        warn!(
                            "Failed to install private signer role-directory record";
                            "reward_cycle" => cycle,
                            "signer_id" => signer_id,
                            "error" => %error,
                        );
                    }
                }
            }
        }
    }

    fn refresh_miner_authorizations(&self, reward_cycle: u64, minimum_burn_height: u64) {
        let Some(network) = self.signer_network.as_ref() else {
            return;
        };
        let deadline = Instant::now() + MINER_AUTHORIZATION_CATCHUP_TIMEOUT;
        let sortitions = loop {
            match self.companion_state_client.get_current_and_last_sortition() {
                Ok(sortitions)
                    if sortitions.current_sortition.burn_block_height >= minimum_burn_height =>
                {
                    break sortitions;
                }
                Ok(sortitions) => {
                    if Instant::now() >= deadline {
                        warn!(
                            "Companion sortition RPC did not catch up to its burn-block event";
                            "event_burn_height" => minimum_burn_height,
                            "rpc_burn_height" => sortitions.current_sortition.burn_block_height,
                        );
                        return;
                    }
                }
                Err(error) => {
                    if Instant::now() >= deadline {
                        warn!(
                            "Failed to refresh canonical miner authorization: {error}";
                            "event_burn_height" => minimum_burn_height,
                        );
                        return;
                    }
                }
            }
            std::thread::sleep(MINER_AUTHORIZATION_CATCHUP_POLL);
        };
        let mut native_by_cycle =
            std::collections::BTreeMap::<u64, Vec<(Vec<u8>, [u8; 20])>>::new();
        for sortition in
            std::iter::once(&sortitions.current_sortition).chain(sortitions.last_sortition.as_ref())
        {
            let Some(hash) = sortition.miner_pk_hash160.as_ref() else {
                continue;
            };
            let cycle = self
                .current_reward_cycle_info
                .as_ref()
                .map(|info| info.get_reward_cycle(sortition.burn_block_height))
                .unwrap_or(reward_cycle);
            native_by_cycle
                .entry(cycle)
                .or_default()
                .push((sortition.consensus_hash.as_bytes().to_vec(), hash.0));
        }
        for (cycle, miners) in native_by_cycle {
            if let Err(error) = network.update_authorized_miners(cycle, miners) {
                warn!(
                    "Failed to install canonical native miner authorization";
                    "reward_cycle" => cycle,
                    "error" => %error,
                );
            }
        }
        if !self.config.libp2p.signer_bridge.mode.accepts_ingress() {
            return;
        }
        // Zero is the serde-compatible value returned by an old node that does
        // not expose the count. Fail closed and retain the incumbent parser.
        if sortitions.current_sortition.num_sortitions == 0 {
            warn!("Node does not expose sortition count; exact .miners bridge remains disabled");
            return;
        }
        let authorizations = legacy_miner_authorizations(
            sortitions.current_sortition.num_sortitions,
            sortitions
                .current_sortition
                .miner_pk_hash160
                .map(|hash| hash.0),
            sortitions
                .last_sortition
                .and_then(|sortition| sortition.miner_pk_hash160.map(|hash| hash.0)),
        );
        if let Err(error) = network.update_authorized_legacy_miners(reward_cycle, authorizations) {
            warn!("Failed to install exact legacy miner authorization: {error}");
        }
    }

    fn drain_native_signer_events(&self) -> Vec<SignerEvent<T>> {
        const MAX_EVENTS_PER_PASS: usize = 256;
        let Some(network) = self.signer_network.as_ref() else {
            return Vec::new();
        };
        let mut events = Vec::new();
        for _ in 0..MAX_EVENTS_PER_PASS {
            let authenticated = match network.try_next_event() {
                Ok(Some(event)) => event,
                Ok(None) => break,
                Err(error) => {
                    warn!("Failed to poll native signer network: {error}");
                    break;
                }
            };
            if let Some(event) = authenticated_native_event(authenticated) {
                events.push(event);
            }
        }
        events
    }

    fn is_configured_for_cycle(
        stacks_signers: &HashMap<u64, ConfiguredSigner<Signer, T>>,
        reward_cycle: u64,
    ) -> bool {
        let Some(signer) = stacks_signers.get(&(reward_cycle % 2)) else {
            return false;
        };
        signer.reward_cycle() == reward_cycle
    }

    fn is_registered_for_cycle(
        stacks_signers: &HashMap<u64, ConfiguredSigner<Signer, T>>,
        reward_cycle: u64,
    ) -> bool {
        let Some(signer) = stacks_signers.get(&(reward_cycle % 2)) else {
            return false;
        };
        signer.reward_cycle() == reward_cycle
            && matches!(signer, ConfiguredSigner::RegisteredSigner(_))
    }

    fn cleanup_stale_signers(
        &mut self,
        current_reward_cycle: u64,
        preserve_previous_at_signing_boundary: bool,
    ) {
        #[cfg(any(test, feature = "testing"))]
        if TEST_SKIP_SIGNER_CLEANUP.get() {
            warn!("Skipping signer cleanup due to testing directive.");
            return;
        }
        let mut to_delete = Vec::new();
        for (idx, signer) in &mut self.stacks_signers {
            let reward_cycle = signer.reward_cycle();
            if reward_cycle >= current_reward_cycle {
                // We are either the current or a future reward cycle, so we are not stale.
                continue;
            }
            if preserve_previous_at_signing_boundary
                && reward_cycle == current_reward_cycle.saturating_sub(1)
            {
                // The current burn block cannot advance until the late
                // previous-cycle BlockFound has either completed or failed.
                continue;
            }
            match signer {
                ConfiguredSigner::RegisteredSigner(signer) => {
                    if !signer.has_unprocessed_blocks() {
                        debug!("{signer}: Signer's tenure has completed.");
                        to_delete.push(*idx);
                    }
                }
                ConfiguredSigner::NotRegistered { .. } => {
                    debug!("{signer}: Unregistered signer's tenure has completed.");
                    to_delete.push(*idx);
                }
            }
        }
        for idx in to_delete {
            self.stacks_signers.remove(&idx);
        }
    }
}

impl<Signer: SignerTrait<T>, T: StacksMessageCodec + Clone + Send + Debug>
    SignerRunLoop<SignerResult, T> for RunLoop<Signer, T>
{
    fn set_event_timeout(&mut self, timeout: Duration) {
        self.config.event_timeout = timeout;
    }

    fn get_event_timeout(&self) -> Duration {
        self.config.event_timeout
    }

    fn run_one_pass(
        &mut self,
        event: Option<SignerEvent<T>>,
        res: &Sender<SignerResult>,
    ) -> Option<SignerResult> {
        debug!(
            "Running one pass for the signer. state={:?}, event={event:?}",
            self.state
        );
        // This is the only event that we respond to from the outer signer runloop
        if let Some(SignerEvent::StatusCheck) = event {
            let state_info = StateInfo {
                runloop_state: self.state,
                reward_cycle_info: self.current_reward_cycle_info,
                running_signers: self
                    .stacks_signers
                    .values()
                    .map(|s| s.reward_cycle())
                    .collect(),
                signer_state_machines: self
                    .stacks_signers
                    .iter()
                    .map(|(reward_cycle, signer)| {
                        let ConfiguredSigner::RegisteredSigner(ref signer) = signer else {
                            return (*reward_cycle, None);
                        };
                        (
                            *reward_cycle,
                            Some(signer.get_local_state_machine().clone()),
                        )
                    })
                    .collect(),
                pending_proposals_count: self
                    .stacks_signers
                    .values()
                    .find_map(|signer| {
                        if let ConfiguredSigner::RegisteredSigner(signer) = signer {
                            Some(signer.get_pending_proposals_count())
                        } else {
                            None
                        }
                    })
                    .unwrap_or(0),
                signer_canonical_tips: self
                    .stacks_signers
                    .iter()
                    .map(|(reward_cycle, signer)| {
                        let ConfiguredSigner::RegisteredSigner(ref signer) = signer else {
                            return (*reward_cycle, None);
                        };
                        (*reward_cycle, signer.get_canonical_tip())
                    })
                    .collect(),
            };
            info!("Signer status check requested: {state_info:?}");

            if let Err(e) = res.send(state_info.into()) {
                error!("Failed to send status check result: {e}.");
            }
        }

        if self.state == State::Uninitialized {
            if let Err(e) = self.initialize_runloop() {
                error!("Failed to initialize signer runloop: {e}.");
                if let Some(event) = event {
                    warn!("Ignoring event: {event:?}");
                }
                return None;
            }
        } else if let Some(SignerEvent::NewBurnBlock { burn_height, .. }) = event.as_ref() {
            self.last_companion_burn_event = Some(Instant::now());
            if let Err(e) = self.refresh_runloop(*burn_height) {
                error!("Failed to refresh signer runloop: {e}.");
                warn!("Signer may have an outdated view of the network.");
            }
        }
        // Authenticated companion callbacks are the authoritative chain-view
        // trigger. A bounded RPC refresh is only a liveness safety net when
        // that observer stream is stale.
        let now = Instant::now();
        let companion_stale = self
            .last_companion_burn_event
            .is_none_or(|last_event| now.duration_since(last_event) >= COMPANION_STATE_STALE_AFTER);
        if companion_stale && now >= self.next_companion_state_refresh {
            self.next_companion_state_refresh = now + COMPANION_REFRESH_RETRY_INTERVAL;
            if let Err(error) = self.refresh_runloop(0) {
                warn!("Failed to refresh companion signer state: {error}");
            }
        }

        let current_reward_cycle = self
            .current_reward_cycle_info
            .as_ref()
            .expect("FATAL: cannot be an initialized signer with no reward cycle info.")
            .reward_cycle;
        let native_events = self.drain_native_signer_events();
        let miner_bridge_ready = self
            .signer_network
            .as_ref()
            .is_some_and(|network| network.bridges_legacy_miner_ingress());
        let compatibility_event = event.as_ref().filter(|event| match event {
            SignerEvent::SignerMessages { .. } => {
                !self.config.libp2p.signer_bridge.mode.emits_events()
            }
            SignerEvent::MinerMessages(_) => !miner_bridge_ready,
            _ => true,
        });
        for configured_signer in self.stacks_signers.values_mut() {
            let ConfiguredSigner::RegisteredSigner(ref mut signer) = configured_signer else {
                debug!("{configured_signer}: Not configured for cycle, ignoring events for cycle");
                continue;
            };

            signer.process_event(
                &self.stacks_client,
                &mut self.sortition_state,
                compatibility_event,
                res,
                current_reward_cycle,
            );
        }
        for native_event in &native_events {
            for configured_signer in self.stacks_signers.values_mut() {
                let ConfiguredSigner::RegisteredSigner(ref mut signer) = configured_signer else {
                    continue;
                };
                signer.process_event(
                    &self.stacks_client,
                    &mut self.sortition_state,
                    Some(native_event),
                    res,
                    current_reward_cycle,
                );
            }
        }

        if let Some(network) = self.signer_network.as_ref() {
            network.record_observability_metrics();
        }

        if self.state == State::NoRegisteredSigners && event.is_some() {
            let next_reward_cycle = current_reward_cycle.saturating_add(1);
            info!(
                "Signer is not registered for the current reward cycle ({current_reward_cycle}). Reward set is not yet determined or signer is not registered for the upcoming reward cycle ({next_reward_cycle})."
            );
        }
        None
    }
}

fn legacy_miner_authorizations(
    num_sortitions: u64,
    current_hash: Option<[u8; 20]>,
    previous_hash: Option<[u8; 20]>,
) -> Vec<(u32, SignerLane, [u8; 20])> {
    let current_index = u32::from(!num_sortitions.is_multiple_of(2));
    let mut authorizations = Vec::with_capacity(4);
    for (index, hash) in [
        (current_index, current_hash),
        (current_index ^ 1, previous_hash),
    ] {
        let Some(hash) = hash else { continue };
        let slot_base = index * 2;
        authorizations.push((slot_base, SignerLane::BlockProposal, hash));
        authorizations.push((slot_base + 1, SignerLane::BlockPushed, hash));
    }
    authorizations
}

#[cfg(test)]
mod tests {
    use blockstack_lib::chainstate::stacks::boot::NakamotoSignerEntry;
    use libsigner::SignerEntries;
    use rand::{thread_rng, Rng, RngCore};
    use stacks_common::types::chainstate::StacksPublicKey;
    use stacks_network_types::wire::v1::SignerLane;

    use super::RewardCycleInfo;

    #[test]
    fn legacy_miner_slots_follow_incumbent_sortition_parity() {
        let current = [1; 20];
        let previous = [2; 20];
        assert_eq!(
            super::legacy_miner_authorizations(7, Some(current), Some(previous)),
            vec![
                (2, SignerLane::BlockProposal, current),
                (3, SignerLane::BlockPushed, current),
                (0, SignerLane::BlockProposal, previous),
                (1, SignerLane::BlockPushed, previous),
            ]
        );
        assert_eq!(
            super::legacy_miner_authorizations(8, Some(current), None),
            vec![
                (0, SignerLane::BlockProposal, current),
                (1, SignerLane::BlockPushed, current),
            ]
        );
    }

    #[test]
    fn parse_nakamoto_signer_entries_test() {
        let nmb_signers = 10;
        let weight = 10;
        let mut signer_entries = Vec::with_capacity(nmb_signers);
        for _ in 0..nmb_signers {
            let key = StacksPublicKey::new().to_bytes_compressed();
            let mut signing_key = [0u8; 33];
            signing_key.copy_from_slice(&key);
            signer_entries.push(NakamotoSignerEntry {
                signing_key,
                stacked_amt: 0,
                weight,
            });
        }

        let parsed_entries = SignerEntries::parse(false, &signer_entries).unwrap();
        assert_eq!(parsed_entries.signer_id_to_pk.len(), nmb_signers);
        let mut signer_ids = parsed_entries
            .signer_id_to_pk
            .into_keys()
            .collect::<Vec<_>>();
        signer_ids.sort();
        assert_eq!(
            signer_ids,
            (0..nmb_signers).map(|id| id as u32).collect::<Vec<_>>()
        );
    }

    #[test]
    fn is_in_reward_cycle_info() {
        let rand_byte: u8 = std::cmp::max(1, thread_rng().r#gen());
        let prepare_phase_block_length = rand_byte as u64;
        // Ensure the reward cycle is not close to u64 Max to prevent overflow when adding prepare phase len
        let reward_cycle_length = (std::cmp::max(
            prepare_phase_block_length.wrapping_add(1),
            thread_rng().next_u32() as u64,
        ))
        .wrapping_add(prepare_phase_block_length);
        let reward_cycle_phase_block_length =
            reward_cycle_length.wrapping_sub(prepare_phase_block_length);
        let first_burnchain_block_height = std::cmp::max(1u8, thread_rng().r#gen()) as u64;
        let last_burnchain_block_height = thread_rng().gen_range(
            first_burnchain_block_height
                ..first_burnchain_block_height
                    .wrapping_add(reward_cycle_length)
                    .wrapping_sub(prepare_phase_block_length),
        );
        let blocks_mined = last_burnchain_block_height.wrapping_sub(first_burnchain_block_height);
        let reward_cycle = blocks_mined / reward_cycle_length;

        let reward_cycle_info = RewardCycleInfo {
            reward_cycle,
            reward_cycle_length,
            prepare_phase_block_length,
            first_burnchain_block_height,
            last_burnchain_block_height,
        };
        assert!(reward_cycle_info.is_in_reward_cycle(first_burnchain_block_height));
        assert!(reward_cycle_info.is_in_reward_cycle(last_burnchain_block_height));
        assert!(!reward_cycle_info
            .is_in_reward_cycle(first_burnchain_block_height.wrapping_add(reward_cycle_length)));

        assert!(reward_cycle_info.is_in_reward_cycle(
            first_burnchain_block_height
                .wrapping_add(reward_cycle_length)
                .wrapping_sub(1)
        ));

        assert!(reward_cycle_info.is_in_reward_cycle(
            first_burnchain_block_height.wrapping_add(reward_cycle_phase_block_length)
        ));
        assert!(reward_cycle_info.is_in_reward_cycle(first_burnchain_block_height.wrapping_add(1)));

        assert!(reward_cycle_info.is_in_reward_cycle(
            first_burnchain_block_height
                .wrapping_add(reward_cycle_phase_block_length)
                .wrapping_add(1)
        ));
    }

    #[test]
    fn is_in_next_prepare_phase() {
        let reward_cycle_info = RewardCycleInfo {
            reward_cycle: 5,
            reward_cycle_length: 10,
            prepare_phase_block_length: 5,
            first_burnchain_block_height: 0,
            last_burnchain_block_height: 50,
        };

        assert!(!reward_cycle_info.is_in_next_prepare_phase(49));
        assert!(!reward_cycle_info.is_in_next_prepare_phase(50));
        assert!(!reward_cycle_info.is_in_next_prepare_phase(51));
        assert!(!reward_cycle_info.is_in_next_prepare_phase(52));
        assert!(!reward_cycle_info.is_in_next_prepare_phase(53));
        assert!(!reward_cycle_info.is_in_next_prepare_phase(54));
        assert!(reward_cycle_info.is_in_next_prepare_phase(55));
        assert!(reward_cycle_info.is_in_next_prepare_phase(56));
        assert!(reward_cycle_info.is_in_next_prepare_phase(57));
        assert!(reward_cycle_info.is_in_next_prepare_phase(58));
        assert!(reward_cycle_info.is_in_next_prepare_phase(59));
        assert!(!reward_cycle_info.is_in_next_prepare_phase(60));
        assert!(!reward_cycle_info.is_in_next_prepare_phase(61));

        let rand_byte: u8 = std::cmp::max(1, thread_rng().r#gen());
        let prepare_phase_block_length = rand_byte as u64;
        // Ensure the reward cycle is not close to u64 Max to prevent overflow when adding prepare phase len
        let reward_cycle_length = (std::cmp::max(
            prepare_phase_block_length.wrapping_add(1),
            thread_rng().next_u32() as u64,
        ))
        .wrapping_add(prepare_phase_block_length);
        let reward_cycle_phase_block_length =
            reward_cycle_length.wrapping_sub(prepare_phase_block_length);
        let first_burnchain_block_height = std::cmp::max(1u8, thread_rng().r#gen()) as u64;
        let last_burnchain_block_height = thread_rng().gen_range(
            first_burnchain_block_height
                ..first_burnchain_block_height
                    .wrapping_add(reward_cycle_length)
                    .wrapping_sub(prepare_phase_block_length),
        );
        let blocks_mined = last_burnchain_block_height.wrapping_sub(first_burnchain_block_height);
        let reward_cycle = blocks_mined / reward_cycle_length;

        let reward_cycle_info = RewardCycleInfo {
            reward_cycle,
            reward_cycle_length,
            prepare_phase_block_length,
            first_burnchain_block_height,
            last_burnchain_block_height,
        };

        for i in 0..reward_cycle_length {
            if i < reward_cycle_phase_block_length {
                assert!(!reward_cycle_info
                    .is_in_next_prepare_phase(first_burnchain_block_height.wrapping_add(i)));
            } else {
                assert!(reward_cycle_info
                    .is_in_next_prepare_phase(first_burnchain_block_height.wrapping_add(i)));
            }
        }
    }

    #[test]
    fn modulo_zero_preserves_the_previous_signer_for_late_block_found() {
        let reward_cycle_info = RewardCycleInfo {
            reward_cycle: 13,
            reward_cycle_length: 20,
            prepare_phase_block_length: 5,
            first_burnchain_block_height: 0,
            last_burnchain_block_height: 260,
        };

        assert!(!reward_cycle_info.is_nakamoto_signing_cycle_start(259));
        assert!(reward_cycle_info.is_nakamoto_signing_cycle_start(260));
        assert!(!reward_cycle_info.is_nakamoto_signing_cycle_start(261));
    }
}
