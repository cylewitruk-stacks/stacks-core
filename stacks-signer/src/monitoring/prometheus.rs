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

use std::collections::BTreeSet;
use std::sync::Mutex;

use lazy_static::lazy_static;
use libsigner::VERSION_STRING;
use prometheus::{
    gather, histogram_opts, opts, register_histogram_vec, register_int_counter,
    register_int_counter_vec, register_int_gauge, register_int_gauge_vec, Encoder, HistogramVec,
    IntCounter, IntCounterVec, IntGauge, IntGaugeVec, TextEncoder,
};
use stacks_common::monitoring::build_info_labels;

use crate::v0::signer_state::LocalStateMachine;
use stacks_network::DeferredMinerAuthorizationSnapshot;

lazy_static! {
    pub static ref BUILD_INFO: IntGauge = register_int_gauge!(opts!(
        "stacks_build_info",
        "Build information for the Stacks process."
    )
    .const_labels(build_info_labels(VERSION_STRING.to_string())))
    .unwrap();

    pub static ref STACKS_TIP_HEIGHT_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_signer_stacks_node_height",
        "The current height of the Stacks node"
    ))
    .unwrap();
    pub static ref STACKS_TIP_LAST_CHANGED_TIMESTAMP_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_signer_stacks_node_height_last_changed_timestamp_seconds",
        "Unix timestamp when the signer's observed Stacks node height last changed"
    )).unwrap();
    pub static ref STACKS_TIP_LAST_OBSERVED_TIMESTAMP_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_signer_stacks_node_height_last_observed_timestamp_seconds",
        "Unix timestamp when the signer last successfully read its configured Stacks node height"
    )).unwrap();
    pub static ref BLOCK_VALIDATION_RESPONSES: IntCounterVec = register_int_counter_vec!(
        "stacks_signer_block_validation_responses",
        "Signer-side companion validation observations by outcome: accepted, rejected, or abstained",
        &["response_type"]
    )
    .unwrap();
    pub static ref BLOCK_RESPONSES_SENT: IntCounterVec = register_int_counter_vec!(
        "stacks_signer_block_responses_sent",
        "The number of block responses sent. `response_type` is either 'accepted' or 'rejected'",
        &["response_type"]
    )
    .unwrap();
    pub static ref BLOCK_PROPOSALS_RECEIVED: IntCounter = register_int_counter!(opts!(
        "stacks_signer_block_proposals_received",
        "The number of block proposals received by the signer"
    ))
    .unwrap();
    pub static ref BLOCK_PRE_COMMITS_SENT: IntCounter = register_int_counter!(opts!(
        "stacks_signer_block_pre_commits_sent",
        "The number of block pre-commits sent by the signer"
    ))
    .unwrap();
    pub static ref POLICY_REJECTIONS: IntCounterVec = register_int_counter_vec!(
        "stacks_signer_block_policy_rejections",
        "Block proposals rejected before companion validation, by bounded wire reason",
        &["reject_code"]
    )
    .unwrap();
    pub static ref DEFERRED_MINER_AUTHORIZATIONS_ADMITTED: IntCounter = register_int_counter!(opts!(
        "stacks_signer_deferred_miner_authorizations_admitted",
        "Canonically-pending miner envelopes admitted to bounded signer-owned deferral"
    ))
    .unwrap();
    pub static ref DEFERRED_MINER_AUTHORIZATIONS_PENDING: IntGauge = register_int_gauge!(opts!(
        "stacks_signer_deferred_miner_authorizations_pending",
        "Current canonically-pending miner envelopes owned by the signer transport"
    ))
    .unwrap();
    pub static ref DEFERRED_MINER_AUTHORIZATION_OBSERVATIONS: IntCounterVec = register_int_counter_vec!(
        "stacks_signer_deferred_miner_authorization_observations",
        "Availability-observation delivery and retry lifecycle for deferred miner envelopes",
        &["observation"]
    )
    .unwrap();
    pub static ref DEFERRED_MINER_AUTHORIZATIONS_RESOLVED: IntCounterVec = register_int_counter_vec!(
        "stacks_signer_deferred_miner_authorizations_resolved",
        "Terminal outcomes for signer-owned canonically-pending miner envelopes",
        &["resolution"]
    )
    .unwrap();
    pub static ref NATIVE_NETWORK_GENERATION_START_TIMESTAMP: IntGauge = register_int_gauge!(opts!(
        "stacks_signer_native_network_generation_start_timestamp_seconds",
        "Unix timestamp identifying the process-owned native signer-network counter generation"
    ))
    .unwrap();
    pub static ref PREVIOUS_DEFERRED_MINER_AUTHORIZATIONS: Mutex<DeferredMinerAuthorizationSnapshot> =
        Mutex::new(DeferredMinerAuthorizationSnapshot::default());
    pub static ref CURRENT_REWARD_CYCLE: IntGauge = register_int_gauge!(opts!(
        "stacks_signer_current_reward_cycle",
        "The current reward cycle"
    )).unwrap();
    pub static ref LOCAL_STATE: IntGaugeVec = register_int_gauge_vec!(
        "stacks_signer_local_state",
        "One-hot bounded lifecycle state of the local signer state machine",
        &["state"]
    ).unwrap();
    pub static ref MINER_STATE: IntGaugeVec = register_int_gauge_vec!(
        "stacks_signer_miner_state",
        "One-hot bounded current-miner view held by the local signer state machine",
        &["state"]
    ).unwrap();
    pub static ref STATE_BURN_BLOCK_HEIGHT: IntGauge = register_int_gauge!(opts!(
        "stacks_signer_state_burn_block_height",
        "Burn block height represented by the local signer state machine"
    )).unwrap();
    pub static ref ACTIVE_PROTOCOL_VERSION: IntGauge = register_int_gauge!(opts!(
        "stacks_signer_active_protocol_version",
        "Active signer agreement protocol version in the local state machine"
    )).unwrap();
    pub static ref STATE_LAST_CHANGED_TIMESTAMP: IntGauge = register_int_gauge!(opts!(
        "stacks_signer_state_last_changed_timestamp_seconds",
        "Unix timestamp when the local signer state machine last changed"
    )).unwrap();
    pub static ref NATIVE_CONNECTIONS: IntGauge = register_int_gauge!(opts!(
        "stacks_p2p_connections",
        "Current number of native libp2p connections"
    )).unwrap();
    pub static ref NATIVE_RENDEZVOUS_CONNECTIONS: IntGauge = register_int_gauge!(opts!(
        "stacks_p2p_rendezvous_connections",
        "Current number of connected private native signer rendezvous peers"
    )).unwrap();
    pub static ref AUTHENTICATED_SIGNER_LINKS: IntGaugeVec = register_int_gauge_vec!(
        "stacks_p2p_authenticated_signer_link",
        "Current endpoint-free link evidence to a chain-authorized signer public key",
        &["signer_public_key"]
    ).unwrap();
    pub static ref CONNECTED_PEERS: IntGaugeVec = register_int_gauge_vec!(
        "stacks_p2p_connected_peer",
        "Current native connection to a transport PeerId; the authenticated observer joins only enrolled identities",
        &["peer_id"]
    ).unwrap();
    pub static ref PREVIOUS_AUTHENTICATED_SIGNER_LINKS: Mutex<BTreeSet<String>> =
        Mutex::new(BTreeSet::new());
    pub static ref PREVIOUS_CONNECTED_PEERS: Mutex<BTreeSet<String>> =
        Mutex::new(BTreeSet::new());
    pub static ref SIGNER_BLOCKED_ON: IntGaugeVec = register_int_gauge_vec!(
        "stacks_observability_blocked_on",
        "One-hot bounded current blocking reason for a local subsystem",
        &["subsystem", "reason"]
    ).unwrap();
    pub static ref SIGNER_STX_BALANCE: IntGauge = register_int_gauge!(opts!(
        "stacks_signer_stx_balance",
        "The current STX balance of the signer"
    )).unwrap();
    pub static ref SIGNER_NONCE: IntGauge = register_int_gauge!(opts!(
        "stacks_signer_nonce",
        "The current nonce of the signer"
    )).unwrap();

    pub static ref SIGNER_RPC_CALL_LATENCIES_HISTOGRAM: HistogramVec = register_histogram_vec!(histogram_opts!(
        "stacks_signer_node_rpc_call_latencies_histogram",
        "Time (seconds) measuring round-trip RPC call latency to the Stacks node"
        // Will use DEFAULT_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0] by default
    ), &["path"]).unwrap();

    pub static ref SIGNER_BLOCK_VALIDATION_LATENCIES_HISTOGRAM: HistogramVec = register_histogram_vec!(histogram_opts!(
        "stacks_signer_block_validation_latencies_histogram",
        "One signer observation per independent companion validation execution, using companion-reported seconds",
        vec![0.005, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 20.0]
    ), &[]).unwrap();

    pub static ref SIGNER_BLOCK_RESPONSE_LATENCIES_HISTOGRAM: HistogramVec = register_histogram_vec!(histogram_opts!(
        "stacks_signer_block_response_latencies_histogram",
        "Time (seconds) measuring end-to-end time to respond to a block",
        vec![0.005, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 20.0, 30.0, 60.0, 120.0]
    ), &[]).unwrap();

    pub static ref SIGNER_AGREEMENT_STATE_CHANGE_REASONS: IntCounterVec = register_int_counter_vec!(
        "stacks_signer_agreement_state_change_reasons",
        "The number of state machine changes in signer agreement protocol. `reason` can be one of: 'burn_block_arrival', 'stacks_block_arrival', 'inactive_miner', 'protocol_upgrade', 'miner_view_update', 'miner_parent_tenure_update'",
        &["reason"]
    ).unwrap();

    pub static ref SIGNER_AGREEMENT_STATE_CONFLICTS: IntCounterVec = register_int_counter_vec!(
        "stacks_signer_agreement_state_conflicts",
        "The number of state machine conflicts in signer agreement protocol. `conflict` can be one of: 'burn_block_delay', 'stacks_block_delay', 'miner_view'",
        &["conflict"]
    ).unwrap();

    pub static ref SIGNER_AGREEMENT_CAPITULATION_LATENCIES_HISTOGRAM: HistogramVec = register_histogram_vec!(histogram_opts!(
        "stacks_signer_agreement_capitulation_latencies_histogram",
        "Measuring the time (in seconds) for the signer to agree (capitulate) with the signer set",
        vec![0.0, 1.0, 3.0, 5.0, 10.0, 20.0, 30.0, 60.0, 120.0]
    ), &[]).unwrap();

    pub static ref SIGNER_LOCAL_STATE_MACHINE: Mutex<Option<LocalStateMachine>> = Mutex::new(None);
}

pub fn gather_metrics_string() -> String {
    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
    let metrics_families = gather();
    encoder.encode(&metrics_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}
