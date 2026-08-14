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

use stacks_common::define_named_enum;

#[cfg(feature = "monitoring_prom")]
mod prometheus;

#[cfg(feature = "monitoring_prom")]
mod server;

define_named_enum!(
/// Represent different state change reason on signer agreement protocol
SignerAgreementStateChangeReason {
    /// A new burn block has arrived
    BurnBlockArrival("burn_block_arrival"),
    /// A new stacks block has arrived
    StacksBlockArrival("stacks_block_arrival"),
    /// A miner is inactive when it should be starting its tenure
    InactiveMiner("inactive_miner"),
    /// Signer agreement protocol version has been upgraded
    ProtocolUpgrade("protocol_upgrade"),
    /// An update related to the Miner view
    MinerViewUpdate("miner_view_update"),
    /// A specific Miner View update related to the parent tenure
    MinerParentTenureUpdate("miner_parent_tenure_update"),
});

define_named_enum!(
/// Represent different conflict types on signer agreement protocol
SignerAgreementStateConflict {
    /// Waiting for burn block propagation to be aligned with the signer set
    BurnBlockDelay("burn_block_delay"),
    /// Waiting for stacks block propagation to be aligned with the signer set
    StacksBlockDelay("stacks_block_delay"),
    /// No agreement on miner view with the signer set
    MinerView("miner_view"),
});

/// Actions for updating metrics
#[cfg(feature = "monitoring_prom")]
pub mod actions {
    use ::prometheus::HistogramTimer;
    use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
    use stacks_common::error;

    use crate::config::GlobalConfig;
    use crate::monitoring::prometheus::*;
    use crate::monitoring::{SignerAgreementStateChangeReason, SignerAgreementStateConflict};
    use crate::v0::signer_state::LocalStateMachine;
    use libsigner::v0::signer_state::MinerState;
    use stacks_network::DeferredMinerAuthorizationSnapshot;

    /// Update stacks tip height gauge
    pub fn update_stacks_tip_height(height: i64) {
        let observed_at = i64::try_from(clarity::util::get_epoch_time_secs()).unwrap_or(i64::MAX);
        if STACKS_TIP_HEIGHT_GAUGE.get() != height {
            STACKS_TIP_LAST_CHANGED_TIMESTAMP_GAUGE.set(observed_at);
        }
        STACKS_TIP_HEIGHT_GAUGE.set(height);
        STACKS_TIP_LAST_OBSERVED_TIMESTAMP_GAUGE.set(observed_at);
    }

    /// Update the current reward cycle
    pub fn update_reward_cycle(reward_cycle: i64) {
        CURRENT_REWARD_CYCLE.set(reward_cycle);
    }

    /// Increment the block validation responses counter
    pub fn increment_block_validation_responses(accepted: bool) {
        let label_value = if accepted { "accepted" } else { "rejected" };
        BLOCK_VALIDATION_RESPONSES
            .with_label_values(&[label_value])
            .inc();
    }

    /// Record a companion timeout as abstention, never as a rejection.
    pub fn increment_block_validation_abstentions() {
        BLOCK_VALIDATION_RESPONSES
            .with_label_values(&["abstained"])
            .inc();
    }

    /// Increment the block responses sent counter
    pub fn increment_block_responses_sent(accepted: bool) {
        let label_value = if accepted { "accepted" } else { "rejected" };
        BLOCK_RESPONSES_SENT.with_label_values(&[label_value]).inc();
    }

    /// Increment the number of block proposals received
    pub fn increment_block_proposals_received() {
        BLOCK_PROPOSALS_RECEIVED.inc();
    }

    /// Increment the block pre-commit sent counter
    pub fn increment_block_pre_commits_sent() {
        BLOCK_PRE_COMMITS_SENT.inc();
    }

    /// Record a bounded signer-policy rejection reason before companion validation.
    pub fn increment_block_policy_rejection(reason: &str) {
        POLICY_REJECTIONS.with_label_values(&[reason]).inc();
    }

    /// Update the stx balance of the signer
    pub fn update_signer_stx_balance(balance: i64) {
        SIGNER_STX_BALANCE.set(balance);
    }

    /// Update the signer nonce metric
    pub fn update_signer_nonce(nonce: u64) {
        SIGNER_NONCE.set(nonce as i64);
    }

    /// Start a new RPC call timer.
    /// The `origin` parameter is the base path of the RPC call, e.g. `http://node.com`.
    /// The `origin` parameter is removed from `full_path` when storing in prometheus.
    pub fn new_rpc_call_timer(full_path: &str, origin: &str) -> HistogramTimer {
        let path = super::remove_origin_from_path(full_path, origin);
        let histogram = SIGNER_RPC_CALL_LATENCIES_HISTOGRAM.with_label_values(&[&path]);
        histogram.start_timer()
    }

    /// Record the time taken to issue a block response for
    /// a given block. The block's timestamp is used to calculate the latency.
    ///
    /// Call this right after broadcasting a BlockResponse
    pub fn record_block_response_latency(block: &NakamotoBlock) {
        use clarity::util::get_epoch_time_ms;

        let diff =
            get_epoch_time_ms().saturating_sub(block.header.timestamp.saturating_mul(1000).into());
        SIGNER_BLOCK_RESPONSE_LATENCIES_HISTOGRAM
            .with_label_values(&[])
            .observe(diff as f64 / 1000.0);
    }

    /// Record the time taken to validate a block, as reported by the Stacks node.
    pub fn record_block_validation_latency(latency_ms: u64) {
        SIGNER_BLOCK_VALIDATION_LATENCIES_HISTOGRAM
            .with_label_values(&[])
            .observe(latency_ms as f64 / 1000.0);
    }

    /// Record the current local state machine
    pub fn record_local_state(state: LocalStateMachine) {
        let blocked_on = match &state {
            LocalStateMachine::Uninitialized => "local_node_rpc",
            LocalStateMachine::Pending { .. } => "canonical_view",
            LocalStateMachine::Initialized(_) => "none",
        };
        for reason in ["none", "canonical_view", "local_node_rpc", "other"] {
            SIGNER_BLOCKED_ON
                .with_label_values(&["signer_state", reason])
                .set(i64::from(reason == blocked_on));
        }
        let lifecycle = match &state {
            LocalStateMachine::Uninitialized => "uninitialized",
            LocalStateMachine::Pending { .. } => "pending",
            LocalStateMachine::Initialized(_) => "initialized",
        };
        for value in ["uninitialized", "pending", "initialized"] {
            LOCAL_STATE
                .with_label_values(&[value])
                .set(i64::from(value == lifecycle));
        }
        let state_view = match &state {
            LocalStateMachine::Initialized(view) => Some(view),
            LocalStateMachine::Pending { prior, .. } => Some(prior),
            LocalStateMachine::Uninitialized => None,
        };
        let miner_state = match state_view.map(|view| &view.current_miner) {
            Some(MinerState::ActiveMiner { .. }) => "active_miner",
            Some(MinerState::NoValidMiner) => "no_valid_miner",
            None => "unknown",
        };
        for value in ["unknown", "no_valid_miner", "active_miner"] {
            MINER_STATE
                .with_label_values(&[value])
                .set(i64::from(value == miner_state));
        }
        STATE_BURN_BLOCK_HEIGHT.set(
            state_view
                .and_then(|view| i64::try_from(view.burn_block_height).ok())
                .unwrap_or(0),
        );
        ACTIVE_PROTOCOL_VERSION.set(
            state_view
                .and_then(|view| i64::try_from(view.active_signer_protocol_version).ok())
                .unwrap_or(0),
        );
        let mut recorded = SIGNER_LOCAL_STATE_MACHINE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if recorded.as_ref() != Some(&state) {
            STATE_LAST_CHANGED_TIMESTAMP
                .set(i64::try_from(clarity::util::get_epoch_time_secs()).unwrap_or(i64::MAX));
        }
        recorded.replace(state);
    }

    /// Publish a bounded native-network snapshot. Transport PeerIds are
    /// public-key-derived identities rather than endpoints; the central
    /// observer joins only uniquely enrolled identities.
    pub fn record_native_network(
        connected_peer_ids: &[String],
        connected_rendezvous: usize,
        signer_public_keys: &[String],
        deferred: &DeferredMinerAuthorizationSnapshot,
    ) {
        NATIVE_CONNECTIONS.set(i64::try_from(connected_peer_ids.len()).unwrap_or(i64::MAX));
        NATIVE_RENDEZVOUS_CONNECTIONS.set(i64::try_from(connected_rendezvous).unwrap_or(i64::MAX));
        let current_peers = connected_peer_ids
            .iter()
            .filter(|peer_id| valid_transport_peer_id(peer_id))
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        let mut previous_peers = PREVIOUS_CONNECTED_PEERS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for peer_id in previous_peers.difference(&current_peers) {
            let _ = CONNECTED_PEERS.remove_label_values(&[peer_id]);
        }
        for peer_id in &current_peers {
            CONNECTED_PEERS.with_label_values(&[peer_id]).set(1);
        }
        *previous_peers = current_peers;
        let current = signer_public_keys
            .iter()
            .filter_map(|key| {
                let parsed =
                    stacks_common::util::secp256k1::Secp256k1PublicKey::from_hex(key).ok()?;
                parsed.compressed().then(|| parsed.to_hex())
            })
            .collect::<std::collections::BTreeSet<_>>();
        let mut previous = PREVIOUS_AUTHENTICATED_SIGNER_LINKS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for key in previous.iter() {
            AUTHENTICATED_SIGNER_LINKS.with_label_values(&[key]).set(0);
        }
        for key in &current {
            AUTHENTICATED_SIGNER_LINKS.with_label_values(&[key]).set(1);
        }
        *previous = current;

        let generation_started =
            i64::try_from(clarity::util::get_epoch_time_secs()).unwrap_or(i64::MAX);
        if NATIVE_NETWORK_GENERATION_START_TIMESTAMP.get() == 0 {
            NATIVE_NETWORK_GENERATION_START_TIMESTAMP.set(generation_started);
        }
        let mut prior = PREVIOUS_DEFERRED_MINER_AUTHORIZATIONS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let delta = |current: u64, previous: u64| {
            let value = if current >= previous {
                current - previous
            } else {
                current
            };
            i64::try_from(value).unwrap_or(i64::MAX)
        };
        let admitted_delta = delta(deferred.admitted, prior.admitted);
        DEFERRED_MINER_AUTHORIZATIONS_ADMITTED.inc_by(admitted_delta);
        // Admission is the unique, authenticated observe-on-defer boundary.
        // Count the local abstention here so a companion RPC stall cannot
        // delay or suppress it by blocking the consensus runloop's queue.
        BLOCK_VALIDATION_RESPONSES
            .with_label_values(&["abstained"])
            .inc_by(admitted_delta);
        DEFERRED_MINER_AUTHORIZATION_OBSERVATIONS
            .with_label_values(&["delivered"])
            .inc_by(delta(
                deferred.observation_delivered,
                prior.observation_delivered,
            ));
        DEFERRED_MINER_AUTHORIZATION_OBSERVATIONS
            .with_label_values(&["retry"])
            .inc_by(delta(
                deferred.observation_retries,
                prior.observation_retries,
            ));
        for (outcome, current, previous) in [
            ("released", deferred.released, prior.released),
            ("expired", deferred.expired, prior.expired),
            ("unauthorized", deferred.unauthorized, prior.unauthorized),
            ("redundant", deferred.redundant, prior.redundant),
            (
                "binding_failed",
                deferred.binding_failed,
                prior.binding_failed,
            ),
            ("malformed", deferred.malformed, prior.malformed),
        ] {
            DEFERRED_MINER_AUTHORIZATIONS_RESOLVED
                .with_label_values(&[outcome])
                .inc_by(delta(current, previous));
        }
        DEFERRED_MINER_AUTHORIZATIONS_PENDING
            .set(i64::try_from(deferred.pending).unwrap_or(i64::MAX));
        *prior = *deferred;
    }

    #[cfg(test)]
    pub(crate) fn deferred_miner_authorizations_admitted_for_test() -> i64 {
        DEFERRED_MINER_AUTHORIZATIONS_ADMITTED.get()
    }

    fn valid_transport_peer_id(peer_id: &str) -> bool {
        (32..=128).contains(&peer_id.len())
            && peer_id
                .bytes()
                .all(|byte| matches!(byte, b'1'..=b'9' | b'A'..=b'H' | b'J'..=b'N' | b'P'..=b'Z' | b'a'..=b'k' | b'm'..=b'z'))
    }

    /// Increment signer agreement state change reason counter
    pub fn increment_signer_agreement_state_change_reason(
        reason: SignerAgreementStateChangeReason,
    ) {
        let label_value = reason.get_name();
        SIGNER_AGREEMENT_STATE_CHANGE_REASONS
            .with_label_values(&[&label_value])
            .inc();
    }

    /// Increment signer agreement state conflict counter
    pub fn increment_signer_agreement_state_conflict(conflict: SignerAgreementStateConflict) {
        let label_value = conflict.get_name();
        SIGNER_AGREEMENT_STATE_CONFLICTS
            .with_label_values(&[&label_value])
            .inc();
    }

    /// Record the time (seconds) taken for a signer to agree with the signer set
    pub fn record_signer_agreement_capitulation_latency(latency_s: u64) {
        SIGNER_AGREEMENT_CAPITULATION_LATENCIES_HISTOGRAM
            .with_label_values(&[])
            .observe(latency_s as f64);
    }

    /// Start serving monitoring metrics.
    /// This will only serve the metrics if the `monitoring_prom` feature is enabled.
    pub fn start_serving_monitoring_metrics(config: GlobalConfig) -> Result<(), String> {
        if config.metrics_endpoint.is_none() {
            return Ok(());
        }
        let _ = std::thread::Builder::new()
            .name("signer_metrics".to_string())
            .spawn(move || {
                if let Err(monitoring_err) = super::server::MonitoringServer::start(&config) {
                    error!("Monitoring: Error in metrics server: {:?}", monitoring_err);
                }
            });
        Ok(())
    }
}

/// No-op actions for updating metrics
#[cfg(not(feature = "monitoring_prom"))]
pub mod actions {
    use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
    use stacks_common::info;

    use crate::monitoring::{SignerAgreementStateChangeReason, SignerAgreementStateConflict};
    use crate::v0::signer_state::LocalStateMachine;
    use crate::GlobalConfig;
    use stacks_network::DeferredMinerAuthorizationSnapshot;

    /// Update stacks tip height gauge
    pub fn update_stacks_tip_height(_height: i64) {}

    /// Update the current reward cycle
    pub fn update_reward_cycle(_reward_cycle: i64) {}

    /// Increment the block validation responses counter
    pub fn increment_block_validation_responses(_accepted: bool) {}

    /// Record a companion timeout as abstention.
    pub fn increment_block_validation_abstentions() {}

    /// Increment the block responses sent counter
    pub fn increment_block_responses_sent(_accepted: bool) {}

    /// Increment the number of block proposals received
    pub fn increment_block_proposals_received() {}

    /// Increment the block pre-commits sent counter
    pub fn increment_block_pre_commits_sent() {}

    /// Record a bounded signer-policy rejection reason.
    pub fn increment_block_policy_rejection(_reason: &str) {}

    /// Update the stx balance of the signer
    pub fn update_signer_stx_balance(_balance: i64) {}

    /// Update the signer nonce metric
    pub fn update_signer_nonce(_nonce: u64) {}

    /// NoOp timer uses for monitoring when the monitoring feature is not enabled.
    pub struct NoOpTimer;
    impl NoOpTimer {
        /// NoOp method to stop recording when the monitoring feature is not enabled.
        pub fn stop_and_record(&self) {}
    }

    /// Stop and record the no-op timer.
    pub fn new_rpc_call_timer(_full_path: &str, _origin: &str) -> NoOpTimer {
        NoOpTimer
    }

    /// Record the time taken to issue a block response for
    /// a given block. The block's timestamp is used to calculate the latency.
    ///
    /// Call this right after broadcasting a BlockResponse
    pub fn record_block_response_latency(_block: &NakamotoBlock) {}

    /// Record the time taken to validate a block, as reported by the Stacks node.
    pub fn record_block_validation_latency(_latency_ms: u64) {}

    /// Record the current local state machine
    pub fn record_local_state(_state: LocalStateMachine) {}

    /// Record a sanitized native-network snapshot.
    pub fn record_native_network(
        _connected_peer_ids: &[String],
        _connected_rendezvous: usize,
        _signer_public_keys: &[String],
        _deferred: &DeferredMinerAuthorizationSnapshot,
    ) {
    }

    /// Increment signer agreement state change reason counter
    pub fn increment_signer_agreement_state_change_reason(
        _reason: SignerAgreementStateChangeReason,
    ) {
    }

    /// Increment signer agreement state conflict counter
    pub fn increment_signer_agreement_state_conflict(_conflict: SignerAgreementStateConflict) {}

    /// Record the time (seconds) taken for a signer to agree with the signer set
    pub fn record_signer_agreement_capitulation_latency(_latency_s: u64) {}

    /// Start serving monitoring metrics.
    /// This will only serve the metrics if the `monitoring_prom` feature is enabled.
    pub fn start_serving_monitoring_metrics(config: GlobalConfig) -> Result<(), String> {
        if config.metrics_endpoint.is_some() {
            info!("`metrics_endpoint` is configured for the signer, but the monitoring_prom feature is not enabled. Not starting monitoring metrics server.");
        }
        Ok(())
    }
}

// Allow dead code because this is only used in the `monitoring_prom` feature
// but we want to run it in a test
#[allow(dead_code)]
/// Remove the origin from the full path to avoid duplicate metrics for different origins
fn remove_origin_from_path(full_path: &str, origin: &str) -> String {
    full_path.replace(origin, "")
}

#[cfg(all(test, feature = "monitoring_prom"))]
use stacks_network::DeferredMinerAuthorizationSnapshot;

#[cfg(all(test, feature = "monitoring_prom"))]
static MONITORING_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn test_remove_origin_from_path() {
    let full_path = "http://localhost:20443/v2/info";
    let origin = "http://localhost:20443";
    let path = remove_origin_from_path(full_path, origin);
    assert_eq!(path, "/v2/info");

    let full_path = "/v2/info";
    let origin = "http://localhost:20443";
    let path = remove_origin_from_path(full_path, origin);
    assert_eq!(path, "/v2/info");
}

#[cfg(feature = "monitoring_prom")]
#[test]
fn native_network_metric_exports_an_exact_valid_signer_set() {
    let _guard = MONITORING_TEST_LOCK.lock().unwrap();
    let key = "02007311430123d4cad97f4f7e86e023b28143130a18099ecf094d36fef0f6135c".to_owned();
    let invalid_curve_point = format!("02{}", "00".repeat(32));
    let peer = "16Uiu2HAmU1MbqEPd87m36aZWn6qKUtPumc2SthnzhF4h2RXz4wTS".to_owned();
    actions::record_native_network(
        std::slice::from_ref(&peer),
        1,
        &[key.clone(), invalid_curve_point.clone()],
        &DeferredMinerAuthorizationSnapshot::default(),
    );
    assert_eq!(prometheus::NATIVE_CONNECTIONS.get(), 1);
    assert_eq!(prometheus::NATIVE_RENDEZVOUS_CONNECTIONS.get(), 1);
    assert_eq!(
        prometheus::AUTHENTICATED_SIGNER_LINKS
            .with_label_values(&[&key])
            .get(),
        1
    );
    assert_eq!(
        prometheus::AUTHENTICATED_SIGNER_LINKS
            .with_label_values(&[&invalid_curve_point])
            .get(),
        0
    );

    assert_eq!(
        prometheus::CONNECTED_PEERS
            .with_label_values(&[&peer])
            .get(),
        1
    );
    actions::record_native_network(&[], 0, &[], &DeferredMinerAuthorizationSnapshot::default());
    assert_eq!(
        prometheus::AUTHENTICATED_SIGNER_LINKS
            .with_label_values(&[&key])
            .get(),
        0
    );
    assert!(prometheus::CONNECTED_PEERS
        .remove_label_values(&[&peer])
        .is_err());
}

#[cfg(feature = "monitoring_prom")]
#[test]
fn unchanged_node_tip_refreshes_observation_without_faking_a_chain_change() {
    prometheus::STACKS_TIP_HEIGHT_GAUGE.set(42);
    prometheus::STACKS_TIP_LAST_CHANGED_TIMESTAMP_GAUGE.set(123);
    prometheus::STACKS_TIP_LAST_OBSERVED_TIMESTAMP_GAUGE.set(0);

    actions::update_stacks_tip_height(42);

    assert_eq!(
        prometheus::STACKS_TIP_LAST_CHANGED_TIMESTAMP_GAUGE.get(),
        123
    );
    assert!(prometheus::STACKS_TIP_LAST_OBSERVED_TIMESTAMP_GAUGE.get() > 0);
}

#[cfg(feature = "monitoring_prom")]
#[test]
fn native_deferral_metrics_mirror_monotonic_conserved_lifecycle() {
    let _guard = MONITORING_TEST_LOCK.lock().unwrap();
    *prometheus::PREVIOUS_DEFERRED_MINER_AUTHORIZATIONS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) =
        DeferredMinerAuthorizationSnapshot::default();
    let admitted_before = prometheus::DEFERRED_MINER_AUTHORIZATIONS_ADMITTED.get();
    let abstained_before = prometheus::BLOCK_VALIDATION_RESPONSES
        .with_label_values(&["abstained"])
        .get();
    let released_before = prometheus::DEFERRED_MINER_AUTHORIZATIONS_RESOLVED
        .with_label_values(&["released"])
        .get();
    let snapshot = DeferredMinerAuthorizationSnapshot {
        admitted: 3,
        observation_delivered: 3,
        observation_retries: 1,
        released: 2,
        expired: 0,
        unauthorized: 0,
        redundant: 0,
        binding_failed: 0,
        malformed: 0,
        pending: 1,
    };
    assert!(snapshot.is_conserved());
    actions::record_native_network(&[], 0, &[], &snapshot);
    assert_eq!(
        prometheus::DEFERRED_MINER_AUTHORIZATIONS_ADMITTED.get() - admitted_before,
        3
    );
    assert_eq!(
        prometheus::BLOCK_VALIDATION_RESPONSES
            .with_label_values(&["abstained"])
            .get()
            - abstained_before,
        3
    );
    assert_eq!(
        prometheus::DEFERRED_MINER_AUTHORIZATIONS_RESOLVED
            .with_label_values(&["released"])
            .get()
            - released_before,
        2
    );
    assert_eq!(prometheus::DEFERRED_MINER_AUTHORIZATIONS_PENDING.get(), 1);
    actions::record_native_network(&[], 0, &[], &snapshot);
    assert_eq!(
        prometheus::DEFERRED_MINER_AUTHORIZATIONS_ADMITTED.get() - admitted_before,
        3,
        "re-recording one service snapshot must not double count"
    );
    assert_eq!(
        prometheus::BLOCK_VALIDATION_RESPONSES
            .with_label_values(&["abstained"])
            .get()
            - abstained_before,
        3,
        "re-recording one service snapshot must not double count abstentions"
    );
}
