// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

use std::error::Error;
use std::path::PathBuf;
#[cfg(feature = "monitoring_prom")]
use std::sync::Mutex;
use std::sync::{OnceLock, RwLock};
use std::{fmt, fs};

use clarity::vm::costs::ExecutionCost;
use rusqlite::{OpenFlags, OptionalExtension};
#[cfg(feature = "network_observer")]
use serde::Serialize;
use stacks_common::types::sqlite::NO_PARAMS;
use stacks_common::util::uint::{Uint256, Uint512};

use crate::burnchains::{BurnchainSigner, Txid};
use crate::net::httpcore::StacksHttpRequest;
use crate::net::rpc::ConversationHttp;
use crate::net::Error as net_error;
use crate::util_lib::db::{sqlite_open, DBConn, Error as DatabaseError};

#[cfg(feature = "monitoring_prom")]
mod prometheus;

#[cfg(feature = "monitoring_prom")]
lazy_static::lazy_static! {
    static ref GLOBAL_BURNCHAIN_SIGNER: std::sync::Mutex<Option<BurnchainSigner>> = std::sync::Mutex::new(None);
}

pub fn increment_rpc_calls_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::RPC_CALL_COUNTER.inc();
}

/// Record one actual companion/node proposal-validation execution. This is
/// deliberately distinct from signer-side observations of callback results.
#[allow(unused_variables)]
pub fn record_block_proposal_validation_execution(outcome: &str, elapsed: std::time::Duration) {
    #[cfg(feature = "monitoring_prom")]
    {
        prometheus::BLOCK_PROPOSAL_VALIDATION_EXECUTIONS
            .with_label_values(&[outcome])
            .inc();
        prometheus::BLOCK_PROPOSAL_VALIDATION_EXECUTION_SECONDS
            .with_label_values(&[outcome])
            .observe(elapsed.as_secs_f64());
    }
}

#[allow(unused_mut)]
pub fn instrument_http_request_handler<F, R>(
    conv_http: &mut ConversationHttp,
    #[allow(unused_mut)] mut req: StacksHttpRequest,
    handler: F,
) -> Result<R, net_error>
where
    F: FnOnce(&mut ConversationHttp, StacksHttpRequest) -> Result<R, net_error>,
{
    #[cfg(feature = "monitoring_prom")]
    increment_rpc_calls_counter();

    #[cfg(feature = "monitoring_prom")]
    let timer = prometheus::new_rpc_call_timer(conv_http.metrics_identifier(&mut req));

    let res = handler(conv_http, req);

    #[cfg(feature = "monitoring_prom")]
    timer.stop_and_record();

    res
}

pub fn increment_stx_blocks_received_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::STX_BLOCKS_RECEIVED_COUNTER.inc();
}

pub fn increment_stx_micro_blocks_received_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::STX_MICRO_BLOCKS_RECEIVED_COUNTER.inc();
}

pub fn increment_stx_blocks_served_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::STX_BLOCKS_SERVED_COUNTER.inc();
}

pub fn increment_stx_micro_blocks_served_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::STX_MICRO_BLOCKS_SERVED_COUNTER.inc();
}

pub fn increment_stx_confirmed_micro_blocks_served_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::STX_CONFIRMED_MICRO_BLOCKS_SERVED_COUNTER.inc();
}

pub fn increment_txs_received_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::TXS_RECEIVED_COUNTER.inc();
}

pub fn increment_btc_blocks_received_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::BTC_BLOCKS_RECEIVED_COUNTER.inc();
}

/// Publish a low-cardinality native-network health snapshot. High-cardinality
/// peer and content detail remains in the bounded diagnostic ring and logs.
#[allow(unused_variables)]
pub fn set_libp2p_network_metrics(
    connected_peers: usize,
    sync_capable_peers: usize,
    swarm_lag_ms: u64,
    command_queue_residence_ms: u64,
    oldest_item_waiting_ms: u64,
    stall_reason: i64,
) {
    #[cfg(feature = "monitoring_prom")]
    {
        prometheus::LIBP2P_CONNECTIONS_GAUGE
            .set(i64::try_from(connected_peers).unwrap_or(i64::MAX));
        prometheus::LIBP2P_SYNC_CAPABLE_PEERS_GAUGE
            .set(i64::try_from(sync_capable_peers).unwrap_or(i64::MAX));
        prometheus::LIBP2P_SWARM_LAG_SECONDS_GAUGE.set(swarm_lag_ms as f64 / 1000.0);
        prometheus::LIBP2P_COMMAND_QUEUE_RESIDENCE_SECONDS_GAUGE
            .set(command_queue_residence_ms as f64 / 1000.0);
        prometheus::LIBP2P_OLDEST_ITEM_WAITING_SECONDS_GAUGE
            .set(oldest_item_waiting_ms as f64 / 1000.0);
        prometheus::LIBP2P_STALL_REASON_GAUGE.set(stall_reason);
        const REASONS: &[&str] = &[
            "none",
            "peer_capability",
            "inventory",
            "queue_capacity",
            "validation",
            "retry_backoff",
            "other",
        ];
        let current = match stall_reason {
            0 => "none",
            1 | 2 => "peer_capability",
            3 => "other",
            4 => "queue_capacity",
            5 => "inventory",
            6 => "validation",
            _ => "other",
        };
        for reason in REASONS {
            prometheus::OBSERVABILITY_BLOCKED_ON_GAUGE
                .with_label_values(&["network_service", reason])
                .set(i64::from(*reason == current));
        }
    }
}

/// Publish the exact set of currently connected signer identities for which
/// this process has observed a valid, chain-authorized signer envelope. The
/// public signer key is deliberately the only identity label: transport
/// PeerIds and endpoints never enter this metric.
#[allow(unused_variables)]
pub fn set_libp2p_authenticated_signer_links(signer_public_keys: &[String]) {
    #[cfg(feature = "monitoring_prom")]
    {
        static PREVIOUS: OnceLock<Mutex<std::collections::BTreeSet<String>>> = OnceLock::new();
        let current = signer_public_keys
            .iter()
            .filter_map(|key| {
                let parsed =
                    stacks_common::util::secp256k1::Secp256k1PublicKey::from_hex(key).ok()?;
                parsed.compressed().then(|| parsed.to_hex())
            })
            .collect::<std::collections::BTreeSet<_>>();
        let mut previous = PREVIOUS
            .get_or_init(|| Mutex::new(std::collections::BTreeSet::new()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for key in previous.iter() {
            prometheus::LIBP2P_AUTHENTICATED_SIGNER_LINK_GAUGE
                .with_label_values(&[key])
                .set(0);
        }
        for key in &current {
            prometheus::LIBP2P_AUTHENTICATED_SIGNER_LINK_GAUGE
                .with_label_values(&[key])
                .set(1);
        }
        *previous = current;
    }
}

/// Publish the bounded set of current native transport peers. PeerIds are
/// public-key-derived identities, not endpoints; the observer qualifies an
/// edge only when the remote identity is uniquely bound in its server-owned
/// enrollment registry. Removed labels are deleted to bound lifetime series
/// cardinality by the live connection limit rather than peer churn.
#[allow(unused_variables)]
pub fn set_libp2p_connected_peer_links(peer_ids: &[String]) {
    #[cfg(feature = "monitoring_prom")]
    {
        static PREVIOUS: OnceLock<Mutex<std::collections::BTreeSet<String>>> = OnceLock::new();
        let current = peer_ids
            .iter()
            .filter(|peer_id| valid_transport_peer_id(peer_id))
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        let mut previous = PREVIOUS
            .get_or_init(|| Mutex::new(std::collections::BTreeSet::new()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for peer_id in previous.difference(&current) {
            let _ = prometheus::LIBP2P_CONNECTED_PEER_GAUGE.remove_label_values(&[peer_id]);
        }
        for peer_id in &current {
            prometheus::LIBP2P_CONNECTED_PEER_GAUGE
                .with_label_values(&[peer_id])
                .set(1);
        }
        *previous = current;
    }
}

#[cfg(feature = "monitoring_prom")]
fn valid_transport_peer_id(peer_id: &str) -> bool {
    (32..=128).contains(&peer_id.len())
        && peer_id
            .bytes()
            .all(|byte| matches!(byte, b'1'..=b'9' | b'A'..=b'H' | b'J'..=b'N' | b'P'..=b'Z' | b'a'..=b'k' | b'm'..=b'z'))
}

static LIBP2P_NETWORK_DIAGNOSTICS: OnceLock<RwLock<serde_json::Value>> = OnceLock::new();
static LIBP2P_NETWORK_CONTEXT: OnceLock<RwLock<serde_json::Value>> = OnceLock::new();
#[cfg(feature = "network_observer")]
static LIBP2P_SIGNER_ROUND: OnceLock<RwLock<Option<Libp2pSignerRound>>> = OnceLock::new();
#[cfg(feature = "monitoring_prom")]
static LIBP2P_LAST_TOTALS: OnceLock<Mutex<std::collections::HashMap<&'static str, u64>>> =
    OnceLock::new();

#[cfg(feature = "network_observer")]
#[derive(Clone, Debug, Serialize)]
struct Libp2pSignerVote {
    signer_public_key: String,
    weight: u32,
    decision: &'static str,
    latency_ms: u64,
}

#[cfg(feature = "network_observer")]
#[derive(Clone, Debug, Serialize)]
struct Libp2pSignerRound {
    proposal_id: String,
    block_height: u64,
    started_unix_ms: u128,
    threshold: u32,
    total_weight: u32,
    approved_weight: u32,
    rejected_weight: u32,
    unavailable_weight: u32,
    status: &'static str,
    votes: Vec<Libp2pSignerVote>,
}

/// Start the single bounded signer round exposed through protected network
/// diagnostics. Re-publishing the same proposal preserves its first-seen time
/// and accumulated votes across a retry. This is a no-op unless the explicit
/// `network_observer` feature enables identity-bearing local diagnostics.
#[allow(unused_variables)]
pub fn begin_libp2p_signer_round(
    proposal_id: String,
    block_height: u64,
    threshold: u32,
    total_weight: u32,
) {
    #[cfg(feature = "network_observer")]
    {
        let rounds = LIBP2P_SIGNER_ROUND.get_or_init(|| RwLock::new(None));
        let Ok(mut current) = rounds.write() else {
            return;
        };
        if current
            .as_ref()
            .is_some_and(|round| round.proposal_id == proposal_id)
        {
            if let Some(round) = current.as_mut() {
                round.status = "collecting";
                let round = round.clone();
                drop(current);
                publish_signer_round_metrics(&round);
            }
            return;
        }
        let round = Libp2pSignerRound {
            proposal_id,
            block_height,
            started_unix_ms: unix_time_millis(),
            threshold,
            total_weight,
            approved_weight: 0,
            rejected_weight: 0,
            unavailable_weight: 0,
            status: "collecting",
            votes: Vec::new(),
        };
        *current = Some(round.clone());
        drop(current);
        publish_signer_round_metrics(&round);
    }
}

/// Record an authenticated, reward-set-weighted response for the active
/// proposal. The protected RPC retains the raw signer key only so the local
/// edge reporter can pseudonymize it before federation egress. This is a no-op
/// unless the explicit `network_observer` feature is enabled.
#[allow(unused_variables)]
pub fn record_libp2p_signer_vote(
    proposal_id: &str,
    signer_public_key: String,
    weight: u32,
    approved: bool,
    approved_weight: u32,
    rejected_weight: u32,
    unavailable_weight: u32,
) {
    record_libp2p_signer_outcome(
        proposal_id,
        signer_public_key,
        weight,
        if approved { "approved" } else { "rejected" },
        Some(approved_weight),
        Some(rejected_weight),
        unavailable_weight,
    );
}

/// Record an authenticated temporary liveness outcome for the active proposal.
/// It is deliberately separate from consensus approval/rejection accounting.
#[allow(unused_variables)]
pub fn record_libp2p_signer_unavailable(
    proposal_id: &str,
    signer_public_key: String,
    weight: u32,
    unavailable_weight: u32,
) {
    record_libp2p_signer_outcome(
        proposal_id,
        signer_public_key,
        weight,
        "unavailable",
        None,
        None,
        unavailable_weight,
    );
}

/// Clear temporary unavailability observations when the coordinator retries
/// the same proposal. Validity votes remain intact.
#[allow(unused_variables)]
pub fn reset_libp2p_signer_unavailable(proposal_id: &str) {
    reset_libp2p_signer_outcomes(proposal_id, true);
}

/// Clear retryable rejection and unavailability observations when the
/// coordinator starts a fresh response attempt for the same proposal.
#[allow(unused_variables)]
pub fn reset_libp2p_signer_rejections(proposal_id: &str) {
    reset_libp2p_signer_outcomes(proposal_id, false);
}

#[allow(unused_variables)]
fn reset_libp2p_signer_outcomes(proposal_id: &str, preserve_rejections: bool) {
    #[cfg(feature = "network_observer")]
    {
        let rounds = LIBP2P_SIGNER_ROUND.get_or_init(|| RwLock::new(None));
        let Ok(mut current) = rounds.write() else {
            return;
        };
        let Some(round) = current
            .as_mut()
            .filter(|round| round.proposal_id == proposal_id)
        else {
            return;
        };
        round.unavailable_weight = 0;
        round.votes.retain(|vote| {
            vote.decision != "unavailable" && (preserve_rejections || vote.decision != "rejected")
        });
        if !preserve_rejections {
            round.rejected_weight = 0;
        }
        let round = round.clone();
        drop(current);
        publish_signer_round_metrics(&round);
    }
}

#[allow(unused_variables)]
fn record_libp2p_signer_outcome(
    proposal_id: &str,
    signer_public_key: String,
    weight: u32,
    decision: &'static str,
    approved_weight: Option<u32>,
    rejected_weight: Option<u32>,
    unavailable_weight: u32,
) {
    #[cfg(feature = "network_observer")]
    {
        let rounds = LIBP2P_SIGNER_ROUND.get_or_init(|| RwLock::new(None));
        let Ok(mut current) = rounds.write() else {
            return;
        };
        let Some(round) = current
            .as_mut()
            .filter(|round| round.proposal_id == proposal_id)
        else {
            return;
        };
        if let Some(approved_weight) = approved_weight {
            round.approved_weight = approved_weight;
        }
        if let Some(rejected_weight) = rejected_weight {
            round.rejected_weight = rejected_weight;
        }
        round.unavailable_weight = unavailable_weight;
        let latency_ms = unix_time_millis()
            .saturating_sub(round.started_unix_ms)
            .try_into()
            .unwrap_or(u64::MAX);
        if let Some(vote) = round
            .votes
            .iter_mut()
            .find(|vote| vote.signer_public_key == signer_public_key)
        {
            vote.weight = weight;
            vote.decision = decision;
            vote.latency_ms = latency_ms;
        } else if round.votes.len() < 4_096 {
            round.votes.push(Libp2pSignerVote {
                signer_public_key,
                weight,
                decision,
                latency_ms,
            });
        }
        let round = round.clone();
        drop(current);
        publish_signer_round_metrics(&round);
    }
}

/// Set the bounded active round's lifecycle state. Unknown values fail closed
/// to `timed-out` rather than creating an unbounded status label. This is a
/// no-op unless the explicit `network_observer` feature is enabled.
#[allow(unused_variables)]
pub fn set_libp2p_signer_round_status(proposal_id: &str, status: &'static str) {
    #[cfg(feature = "network_observer")]
    {
        let rounds = LIBP2P_SIGNER_ROUND.get_or_init(|| RwLock::new(None));
        let Ok(mut current) = rounds.write() else {
            return;
        };
        let Some(round) = current
            .as_mut()
            .filter(|round| round.proposal_id == proposal_id)
        else {
            return;
        };
        round.status = match status {
            "collecting" => "collecting",
            "approved" => "approved",
            "rejected" => "rejected",
            _ => "timed-out",
        };
        // The coordinator's terminal approval is authoritative: it returns
        // success only after gathering threshold signature weight. The
        // diagnostic response accumulator is updated on a separate handoff
        // and can legitimately lag that terminal transition. Preserve the
        // exact observed weight when it is higher, but never export the
        // internally contradictory state `approved && approved < threshold`.
        if round.status == "approved" {
            round.approved_weight = round.approved_weight.max(round.threshold);
        }
        let round = round.clone();
        drop(current);
        publish_signer_round_metrics(&round);
    }
}

#[cfg(feature = "network_observer")]
#[allow(unused_variables)]
fn publish_signer_round_metrics(round: &Libp2pSignerRound) {
    #[cfg(feature = "monitoring_prom")]
    {
        const STATUSES: &[&str] = &["collecting", "approved", "rejected", "timed-out"];
        for status in STATUSES {
            prometheus::MINER_SIGNER_ROUND_STATUS_GAUGE
                .with_label_values(&[status])
                .set(i64::from(*status == round.status));
        }
        prometheus::MINER_SIGNER_ROUND_BLOCK_HEIGHT_GAUGE
            .set(i64::try_from(round.block_height).unwrap_or(i64::MAX));
        prometheus::MINER_SIGNER_ROUND_STARTED_TIMESTAMP_GAUGE
            .set(round.started_unix_ms as f64 / 1_000.0);
        prometheus::MINER_SIGNER_ROUND_THRESHOLD_WEIGHT_GAUGE.set(i64::from(round.threshold));
        prometheus::MINER_SIGNER_ROUND_TOTAL_WEIGHT_GAUGE.set(i64::from(round.total_weight));
        prometheus::MINER_SIGNER_ROUND_APPROVED_WEIGHT_GAUGE.set(i64::from(round.approved_weight));
        prometheus::MINER_SIGNER_ROUND_REJECTED_WEIGHT_GAUGE.set(i64::from(round.rejected_weight));
        prometheus::MINER_SIGNER_ROUND_UNAVAILABLE_WEIGHT_GAUGE
            .set(i64::from(round.unavailable_weight));

        type VoteLabel = (String, &'static str);
        static PREVIOUS: OnceLock<Mutex<std::collections::BTreeSet<VoteLabel>>> = OnceLock::new();
        let current = round
            .votes
            .iter()
            .filter_map(|vote| {
                let parsed = stacks_common::util::secp256k1::Secp256k1PublicKey::from_hex(
                    &vote.signer_public_key,
                )
                .ok()?;
                parsed
                    .compressed()
                    .then(|| (parsed.to_hex(), vote.decision))
            })
            .collect::<std::collections::BTreeSet<_>>();
        let mut previous = PREVIOUS
            .get_or_init(|| Mutex::new(std::collections::BTreeSet::new()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for (key, decision) in previous.difference(&current) {
            // Do not delete the series. A downstream Prometheus federation
            // retains a disappeared series until its staleness window closes,
            // which can make an obsolete decision look current. The bounded
            // current/previous signer set is safe to retain at zero and gives
            // every scrape an explicit revocation.
            prometheus::MINER_SIGNER_VOTE_WEIGHT_GAUGE
                .with_label_values(&[key.as_str(), *decision])
                .set(0);
            prometheus::MINER_SIGNER_VOTE_LATENCY_SECONDS_GAUGE
                .with_label_values(&[key.as_str(), *decision])
                .set(0.0);
        }
        for vote in &round.votes {
            let Ok(parsed) = stacks_common::util::secp256k1::Secp256k1PublicKey::from_hex(
                &vote.signer_public_key,
            ) else {
                continue;
            };
            if !parsed.compressed() {
                continue;
            }
            let key = parsed.to_hex();
            prometheus::MINER_SIGNER_VOTE_WEIGHT_GAUGE
                .with_label_values(&[&key, vote.decision])
                .set(i64::from(vote.weight));
            prometheus::MINER_SIGNER_VOTE_LATENCY_SECONDS_GAUGE
                .with_label_values(&[&key, vote.decision])
                .set(vote.latency_ms as f64 / 1_000.0);
        }
        *previous = current;
    }
}

#[cfg(feature = "network_observer")]
fn unix_time_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

/// Replace the protected native-network diagnostic snapshot atomically. The
/// RPC handler reads this copy without reaching into the swarm thread.
pub fn set_libp2p_network_diagnostics(mut snapshot: serde_json::Value) {
    #[cfg(feature = "monitoring_prom")]
    update_libp2p_diagnostic_metrics(&snapshot);
    if let Some(object) = snapshot.as_object_mut() {
        if let Some(context) = LIBP2P_NETWORK_CONTEXT
            .get()
            .and_then(|context| context.read().ok())
        {
            merge_libp2p_network_context(object, &context);
        }
        let generated_at = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        object.insert(
            "snapshot_generated_unix_ms".into(),
            serde_json::Value::String(generated_at.to_string()),
        );
    }
    let diagnostics = LIBP2P_NETWORK_DIAGNOSTICS
        .get_or_init(|| RwLock::new(serde_json::json!({"enabled": false})));
    if let Ok(mut current) = diagnostics.write() {
        *current = snapshot;
    }
}

fn merge_libp2p_network_context(
    snapshot: &mut serde_json::Map<String, serde_json::Value>,
    context: &serde_json::Value,
) {
    if let Some(context) = context.as_object() {
        for (key, value) in context {
            snapshot.insert(key.clone(), value.clone());
        }
    }
}

/// Install bounded, low-cardinality operator context that is merged into each
/// live native-network snapshot. Keeping it separate lets the swarm retain
/// transport-only ownership while the node reports configuration semantics.
pub fn set_libp2p_network_context(context: serde_json::Value) {
    let context_store = LIBP2P_NETWORK_CONTEXT.get_or_init(|| RwLock::new(serde_json::Value::Null));
    if let Ok(mut current) = context_store.write() {
        *current = context;
    }
}

#[cfg(feature = "monitoring_prom")]
fn update_libp2p_diagnostic_metrics(snapshot: &serde_json::Value) {
    const COUNTERS: &[(&str, &str)] = &[
        ("successful_hellos", "hello_accepted"),
        ("rejected_hellos", "hello_rejected"),
        ("outbound_failures", "outbound_failure"),
        ("resource_budget_rejections", "resource_rejected"),
        ("object_announcements_published", "announcement_published"),
        ("object_announcements_received", "announcement_received"),
        ("objects_published", "object_published"),
        ("objects_received", "object_received"),
        ("object_fetches_started", "fetch_started"),
        ("object_fetch_failures", "fetch_failed"),
        ("durable_object_lookups", "durable_lookup"),
        ("durable_object_hits", "durable_hit"),
        ("durable_object_misses", "durable_miss"),
        ("direct_pushes_sent", "direct_push_sent"),
        ("direct_pushes_received", "direct_push_received"),
        ("direct_push_busy", "direct_push_busy"),
        ("direct_push_rejected", "direct_push_rejected"),
        ("direct_push_failures", "direct_push_failed"),
        ("received_signer_messages", "signer_received"),
        ("rejected_signer_messages", "signer_rejected"),
        ("signer_equivocations", "signer_equivocation"),
        ("sync_requests_sent", "sync_request_sent"),
        ("sync_requests_received", "sync_request_received"),
        ("sync_responses_received", "sync_response_received"),
        ("sync_failures", "sync_failed"),
        ("command_queue_full", "command_queue_full"),
        ("event_queue_full", "event_queue_full"),
        ("event_loop_stalls", "event_loop_stall"),
        ("peer_store_writes", "peer_store_write"),
        ("peer_store_write_failures", "peer_store_write_failed"),
        ("peer_store_queue_drops", "peer_store_queue_full"),
        (
            "peer_store_corruptions_recovered",
            "peer_store_corruption_recovered",
        ),
    ];
    let totals = LIBP2P_LAST_TOTALS.get_or_init(|| Mutex::new(std::collections::HashMap::new()));
    if let Ok(mut previous) = totals.lock() {
        for &(field, event) in COUNTERS {
            let Some(current) = snapshot.get(field).and_then(serde_json::Value::as_u64) else {
                continue;
            };
            let old = previous.insert(field, current).unwrap_or(0);
            let delta = if current >= old {
                current - old
            } else {
                current
            };
            if delta > 0 {
                prometheus::LIBP2P_EVENTS_COUNTER
                    .with_label_values(&[event])
                    .inc_by(delta);
            }
        }
        for &(field, reason) in &[
            ("observability_spans_dropped_queue", "queue_full"),
            ("observability_spans_dropped_export", "export_failed"),
        ] {
            let counter =
                prometheus::OBSERVABILITY_SPANS_DROPPED_COUNTER.with_label_values(&[reason]);
            // Materialize both bounded label values even when no spans have
            // been dropped, which makes exporter health assertions reliable.
            counter.inc_by(0);
            let Some(current) = snapshot.get(field).and_then(serde_json::Value::as_u64) else {
                continue;
            };
            let old = previous.insert(field, current).unwrap_or(0);
            let delta = if current >= old {
                current - old
            } else {
                current
            };
            if delta > 0 {
                counter.inc_by(delta);
            }
        }
    }
    if let Some(items) = snapshot
        .get("object_cache_items")
        .and_then(serde_json::Value::as_u64)
    {
        prometheus::LIBP2P_OBJECT_CACHE_ITEMS_GAUGE.set(i64::try_from(items).unwrap_or(i64::MAX));
    }
    if let Some(bytes) = snapshot
        .get("object_cache_bytes")
        .and_then(serde_json::Value::as_u64)
    {
        prometheus::LIBP2P_OBJECT_CACHE_BYTES_GAUGE.set(i64::try_from(bytes).unwrap_or(i64::MAX));
    }
    if let Some(peers) = snapshot
        .get("peer_store_peers")
        .and_then(serde_json::Value::as_u64)
    {
        prometheus::LIBP2P_PEER_STORE_PEERS_GAUGE.set(i64::try_from(peers).unwrap_or(i64::MAX));
    }
    if let Some(addresses) = snapshot
        .get("peer_store_addresses")
        .and_then(serde_json::Value::as_u64)
    {
        prometheus::LIBP2P_PEER_STORE_ADDRESSES_GAUGE
            .set(i64::try_from(addresses).unwrap_or(i64::MAX));
    }
    let rtts = snapshot
        .get("peer_rtt_ms")
        .and_then(serde_json::Value::as_array);
    let (total_ms, count) = rtts.map_or((0_u128, 0_u128), |rtts| {
        rtts.iter().fold((0_u128, 0_u128), |(total, count), row| {
            let rtt = row
                .as_array()
                .and_then(|row| row.get(1))
                .and_then(serde_json::Value::as_u64);
            rtt.map_or((total, count), |rtt| {
                (total.saturating_add(u128::from(rtt)), count + 1)
            })
        })
    });
    prometheus::LIBP2P_PEER_RTT_SECONDS_GAUGE.set(if count == 0 {
        0.0
    } else {
        total_ms as f64 / count as f64 / 1000.0
    });
}

/// Read the latest native-network diagnostic snapshot.
pub fn libp2p_network_diagnostics() -> serde_json::Value {
    #[allow(unused_mut)]
    let mut snapshot = LIBP2P_NETWORK_DIAGNOSTICS
        .get_or_init(|| RwLock::new(serde_json::json!({"enabled": false})))
        .read()
        .map(|snapshot| snapshot.clone())
        .unwrap_or_else(
            |_| serde_json::json!({"enabled": false, "error": "diagnostics lock poisoned"}),
        );
    #[cfg(feature = "network_observer")]
    {
        if let (Some(object), Some(round)) = (
            snapshot.as_object_mut(),
            LIBP2P_SIGNER_ROUND
                .get()
                .and_then(|round| round.read().ok())
                .and_then(|round| round.clone()),
        ) {
            if let Ok(round) = serde_json::to_value(round) {
                object.insert("signer_round".into(), round);
            }
        }
    }
    snapshot
}

/// Log `execution_cost` as a ratio of `block_limit`.
#[allow(unused_variables)]
pub fn set_last_execution_cost_observed(
    execution_cost: &ExecutionCost,
    block_limit: &ExecutionCost,
) {
    #[cfg(feature = "monitoring_prom")]
    {
        prometheus::LAST_BLOCK_READ_COUNT
            .set(execution_cost.read_count as f64 / block_limit.read_count as f64);
        prometheus::LAST_BLOCK_WRITE_COUNT
            .set(execution_cost.write_count as f64 / block_limit.write_count as f64);
        prometheus::LAST_BLOCK_READ_LENGTH
            .set(execution_cost.read_length as f64 / block_limit.read_length as f64);
        prometheus::LAST_BLOCK_WRITE_LENGTH
            .set(execution_cost.write_length as f64 / block_limit.write_length as f64);
        prometheus::LAST_BLOCK_RUNTIME
            .set(execution_cost.runtime as f64 / block_limit.runtime as f64);
    }
}

/// Log the number of transactions in the latest block.
#[allow(unused_variables)]
pub fn set_last_block_transaction_count(transactions_in_block: u64) {
    // Saturating cast from u64 to i64
    #[cfg(feature = "monitoring_prom")]
    prometheus::LAST_BLOCK_TRANSACTION_COUNT
        .set(i64::try_from(transactions_in_block).unwrap_or(i64::MAX));
}

/// Log `execution_cost` as a ratio of `block_limit`.
#[allow(unused_variables)]
pub fn set_last_mined_execution_cost_observed(
    execution_cost: &ExecutionCost,
    block_limit: &ExecutionCost,
) {
    #[cfg(feature = "monitoring_prom")]
    {
        prometheus::LAST_MINED_BLOCK_READ_COUNT
            .set(execution_cost.read_count as f64 / block_limit.read_count as f64);
        prometheus::LAST_MINED_BLOCK_WRITE_COUNT
            .set(execution_cost.write_count as f64 / block_limit.write_count as f64);
        prometheus::LAST_MINED_BLOCK_READ_LENGTH
            .set(execution_cost.read_length as f64 / block_limit.read_length as f64);
        prometheus::LAST_MINED_BLOCK_WRITE_LENGTH
            .set(execution_cost.write_length as f64 / block_limit.write_length as f64);
        prometheus::LAST_MINED_BLOCK_RUNTIME
            .set(execution_cost.runtime as f64 / block_limit.runtime as f64);
    }
}

/// Log the number of transactions in the latest block.
#[allow(unused_variables)]
pub fn set_last_mined_block_transaction_count(transactions_in_block: u64) {
    // Saturating cast from u64 to i64
    #[cfg(feature = "monitoring_prom")]
    prometheus::LAST_MINED_BLOCK_TRANSACTION_COUNT
        .set(i64::try_from(transactions_in_block).unwrap_or(i64::MAX));
}

pub fn increment_btc_ops_sent_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::BTC_OPS_SENT_COUNTER.inc();
}

pub fn increment_stx_blocks_processed_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::STX_BLOCKS_PROCESSED_COUNTER.inc();
}

pub fn increment_stx_blocks_mined_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::STX_BLOCKS_MINED_COUNTER.inc();
}

pub fn increment_warning_emitted_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::WARNING_EMITTED_COUNTER.inc();
}

pub fn increment_errors_emitted_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::ERRORS_EMITTED_COUNTER.inc();
}

pub fn increment_unreachable_errors_counter(_error_type: &str) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::UNREACHABLE_ERRORS_COUNTER
        .with_label_values(&[_error_type])
        .inc();
}

fn txid_tracking_db(chainstate_root_path: &str) -> Result<DBConn, DatabaseError> {
    let mut path = PathBuf::from(chainstate_root_path);

    path.push("tx_tracking.sqlite");
    let db_path = path.to_str().ok_or_else(|| DatabaseError::ParseError)?;

    let mut create_flag = false;
    let open_flags = if fs::metadata(db_path).is_err() {
        // need to create
        create_flag = true;
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
    } else {
        // can just open
        OpenFlags::SQLITE_OPEN_READ_WRITE
    };

    let conn = sqlite_open(db_path, open_flags, false)?;

    if create_flag {
        conn.execute(
            "CREATE TABLE processed_txids (txid TEXT NOT NULL PRIMARY KEY)",
            NO_PARAMS,
        )?;
    }

    Ok(conn)
}

fn txid_tracking_db_contains(conn: &DBConn, txid: &Txid) -> Result<bool, DatabaseError> {
    let contains = conn
        .query_row(
            "SELECT 1 FROM processed_txids WHERE txid = ?",
            [txid],
            |_row| Ok(true),
        )
        .optional()?
        .is_some();
    Ok(contains)
}

#[allow(unused_variables)]
pub fn mempool_accepted(txid: &Txid, chainstate_root_path: &str) -> Result<(), DatabaseError> {
    #[cfg(feature = "monitoring_prom")]
    {
        let tracking_db = txid_tracking_db(chainstate_root_path)?;

        if txid_tracking_db_contains(&tracking_db, txid)? {
            // processed by a previous block, do not track again
            return Ok(());
        }

        prometheus::MEMPOOL_OUTSTANDING_TXS.inc();
    }

    Ok(())
}

#[allow(unused_variables)]
pub fn log_transaction_processed(
    txid: &Txid,
    chainstate_root_path: &str,
) -> Result<(), DatabaseError> {
    #[cfg(feature = "monitoring_prom")]
    {
        let mempool_db_path = crate::core::MemPoolDB::db_path(chainstate_root_path)?;
        let mempool_conn = sqlite_open(&mempool_db_path, OpenFlags::SQLITE_OPEN_READ_ONLY, false)?;
        let tracking_db = txid_tracking_db(chainstate_root_path)?;

        let tx = match crate::core::MemPoolDB::get_tx(&mempool_conn, txid)? {
            Some(tx) => tx,
            None => {
                debug!("Could not log transaction receive to process time, txid not found in mempool"; "txid" => %txid);
                return Ok(());
            }
        };

        if txid_tracking_db_contains(&tracking_db, txid)? {
            // processed by a previous block, do not track again
            return Ok(());
        }

        let mempool_accept_time = tx.metadata.accept_time;
        let time_now = clarity::util::get_epoch_time_secs();

        let time_to_process = time_now - mempool_accept_time;

        prometheus::MEMPOOL_OUTSTANDING_TXS.dec();
        prometheus::MEMPOOL_TX_CONFIRM_TIME.observe(time_to_process as f64);
    }
    Ok(())
}

#[allow(unused_variables)]
pub fn update_active_miners_count_gauge(value: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::ACTIVE_MINERS_COUNT_GAUGE.set(value);
}

#[allow(unused_variables)]
pub fn update_stacks_tip_height(value: i64) {
    #[cfg(feature = "monitoring_prom")]
    {
        if prometheus::STACKS_TIP_HEIGHT_GAUGE.get() != value {
            prometheus::STACKS_TIP_LAST_CHANGED_TIMESTAMP_GAUGE
                .set(i64::try_from(clarity::util::get_epoch_time_secs()).unwrap_or(i64::MAX));
        }
        prometheus::STACKS_TIP_HEIGHT_GAUGE.set(value);
    }
}

#[allow(unused_variables)]
pub fn update_burnchain_height(value: i64) {
    #[cfg(feature = "monitoring_prom")]
    {
        if prometheus::BURNCHAIN_HEIGHT_GAUGE.get() != value {
            prometheus::BURNCHAIN_LAST_CHANGED_TIMESTAMP_GAUGE
                .set(i64::try_from(clarity::util::get_epoch_time_secs()).unwrap_or(i64::MAX));
        }
        prometheus::BURNCHAIN_HEIGHT_GAUGE.set(value);
    }
}

#[allow(unused_variables)]
pub fn update_inbound_neighbors(value: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::INBOUND_NEIGHBORS_GAUGE.set(value);
}

#[allow(unused_variables)]
pub fn update_outbound_neighbors(value: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::OUTBOUND_NEIGHBORS_GAUGE.set(value);
}

#[allow(unused_variables)]
pub fn update_inbound_bandwidth(value: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::INBOUND_BANDWIDTH_GAUGE.add(value);
}

#[allow(unused_variables)]
pub fn update_outbound_bandwidth(value: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::OUTBOUND_BANDWIDTH_GAUGE.add(value);
}

#[allow(unused_variables)]
pub fn update_inbound_rpc_bandwidth(value: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::INBOUND_RPC_BANDWIDTH_GAUGE.add(value);
}

#[allow(unused_variables)]
pub fn update_outbound_rpc_bandwidth(value: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::OUTBOUND_RPC_BANDWIDTH_GAUGE.add(value);
}

#[allow(unused_variables)]
pub fn increment_msg_counter(name: String) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::MSG_COUNTER_VEC
        .with_label_values(&[&name])
        .inc();
}

pub fn increment_stx_mempool_gc() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::STX_MEMPOOL_GC.inc();
}

pub fn increment_contract_calls_processed() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::CONTRACT_CALLS_PROCESSED_COUNT.inc();
}

/// Given a value (type uint256), return value/uint256::max() as an f64 value.
/// The precision of the percentage is determined by the input `precision_points`, which is capped
/// at a max of 15.
fn convert_uint256_to_f64_percentage(value: Uint256, precision_points: u32) -> f64 {
    let precision_points = precision_points.min(15);
    let base = 10;
    let multiplier = Uint512::from_u128(100 * u128::pow(base, precision_points));
    let intermediate_result = ((Uint512::from_uint256(&value) * multiplier)
        / Uint512::from_uint256(&Uint256::max()))
    .low_u64() as i64;
    let divisor = i64::pow(base as i64, precision_points);

    intermediate_result as f64 / divisor as f64
}

#[cfg(test)]
macro_rules! assert_approx_eq {
    ($a: expr, $b: expr) => {{
        let (a, b) = (&$a, &$b);
        assert!(
            (*a - *b).abs() < 1.0e-6,
            "{} is not approximately equal to {}",
            *a,
            *b
        );
    }};
}

#[test]
pub fn test_convert_uint256_to_f64() {
    let original = ((Uint512::from_uint256(&Uint256::max()) * Uint512::from_u64(10))
        / Uint512::from_u64(100))
    .to_uint256();
    assert_approx_eq!(convert_uint256_to_f64_percentage(original, 7), 10_f64);

    let original = ((Uint512::from_uint256(&Uint256::max()) * Uint512::from_u64(122))
        / Uint512::from_u64(1000))
    .to_uint256();
    assert_approx_eq!(convert_uint256_to_f64_percentage(original, 7), 12.2);

    let original = ((Uint512::from_uint256(&Uint256::max()) * Uint512::from_u64(122345))
        / Uint512::from_u64(1000000))
    .to_uint256();
    assert_approx_eq!(convert_uint256_to_f64_percentage(original, 7), 12.2345);

    let original = ((Uint512::from_uint256(&Uint256::max()) * Uint512::from_u64(12234567))
        / Uint512::from_u64(100000000))
    .to_uint256();
    assert_approx_eq!(convert_uint256_to_f64_percentage(original, 7), 12.234567);

    let original = ((Uint512::from_uint256(&Uint256::max()) * Uint512::from_u64(12234567))
        / Uint512::from_u64(100000000))
    .to_uint256();
    assert_approx_eq!(convert_uint256_to_f64_percentage(original, 1000), 12.234567);
}

#[test]
fn libp2p_operator_context_is_merged_without_replacing_live_fields() {
    let mut snapshot = serde_json::json!({
        "connected_peers": ["peer-a"],
        "generic_stackerdb_replication": "stale"
    });
    merge_libp2p_network_context(
        snapshot.as_object_mut().unwrap(),
        &serde_json::json!({
            "peer_transport_mode": "libp2p-only",
            "generic_stackerdb_replication": "not-configured",
            "http_rpc_active": true
        }),
    );
    assert_eq!(snapshot["connected_peers"][0], "peer-a");
    assert_eq!(snapshot["peer_transport_mode"], "libp2p-only");
    assert_eq!(snapshot["generic_stackerdb_replication"], "not-configured");
    assert_eq!(snapshot["http_rpc_active"], true);
}

#[cfg(feature = "monitoring_prom")]
#[test]
fn authenticated_signer_link_metric_is_exact_and_rejects_non_keys() {
    let key = "02007311430123d4cad97f4f7e86e023b28143130a18099ecf094d36fef0f6135c".to_owned();
    let invalid_curve_point = format!("02{}", "00".repeat(32));
    set_libp2p_authenticated_signer_links(&[key.clone(), invalid_curve_point.clone()]);
    assert_eq!(
        prometheus::LIBP2P_AUTHENTICATED_SIGNER_LINK_GAUGE
            .with_label_values(&[&key])
            .get(),
        1
    );
    assert_eq!(
        prometheus::LIBP2P_AUTHENTICATED_SIGNER_LINK_GAUGE
            .with_label_values(&[&invalid_curve_point])
            .get(),
        0
    );

    set_libp2p_authenticated_signer_links(&[]);
    assert_eq!(
        prometheus::LIBP2P_AUTHENTICATED_SIGNER_LINK_GAUGE
            .with_label_values(&[&key])
            .get(),
        0
    );
}

#[cfg(feature = "monitoring_prom")]
#[test]
fn connected_peer_metric_is_exact_bounded_and_removes_stale_series() {
    let peer = "16Uiu2HAmU1MbqEPd87m36aZWn6qKUtPumc2SthnzhF4h2RXz4wTS".to_owned();
    set_libp2p_connected_peer_links(&[peer.clone(), "not-a-peer-id".into()]);
    assert_eq!(
        prometheus::LIBP2P_CONNECTED_PEER_GAUGE
            .with_label_values(&[&peer])
            .get(),
        1
    );
    set_libp2p_connected_peer_links(&[]);
    assert!(prometheus::LIBP2P_CONNECTED_PEER_GAUGE
        .remove_label_values(&[&peer])
        .is_err());
}

#[cfg(feature = "network_observer")]
#[test]
fn protected_diagnostics_include_one_bounded_weighted_signer_round() {
    set_libp2p_network_diagnostics(serde_json::json!({"connected_peers": []}));
    begin_libp2p_signer_round("proposal-a".into(), 61, 21, 30);
    record_libp2p_signer_vote("proposal-a", "signer-a".into(), 15, true, 15, 0, 0);
    record_libp2p_signer_vote("proposal-a", "signer-b".into(), 10, false, 15, 10, 0);
    set_libp2p_signer_round_status("proposal-a", "rejected");

    let snapshot = libp2p_network_diagnostics();
    assert_eq!(snapshot["signer_round"]["proposal_id"], "proposal-a");
    assert_eq!(snapshot["signer_round"]["block_height"], 61);
    assert_eq!(snapshot["signer_round"]["approved_weight"], 15);
    assert_eq!(snapshot["signer_round"]["rejected_weight"], 10);
    assert_eq!(snapshot["signer_round"]["status"], "rejected");
    assert_eq!(
        snapshot["signer_round"]["votes"].as_array().unwrap().len(),
        2
    );
}

#[cfg(feature = "network_observer")]
#[test]
fn signer_round_retry_resets_only_retryable_outcomes() {
    set_libp2p_network_diagnostics(serde_json::json!({"connected_peers": []}));
    begin_libp2p_signer_round("proposal-retry".into(), 61, 21, 30);
    record_libp2p_signer_vote("proposal-retry", "approved".into(), 10, true, 10, 0, 0);
    record_libp2p_signer_vote("proposal-retry", "rejected".into(), 5, false, 10, 5, 0);
    record_libp2p_signer_unavailable("proposal-retry", "unavailable".into(), 15, 15);

    reset_libp2p_signer_unavailable("proposal-retry");
    let snapshot = libp2p_network_diagnostics();
    assert_eq!(snapshot["signer_round"]["approved_weight"], 10);
    assert_eq!(snapshot["signer_round"]["rejected_weight"], 5);
    assert_eq!(snapshot["signer_round"]["unavailable_weight"], 0);
    assert_eq!(
        snapshot["signer_round"]["votes"].as_array().unwrap().len(),
        2
    );

    reset_libp2p_signer_rejections("proposal-retry");
    let snapshot = libp2p_network_diagnostics();
    assert_eq!(snapshot["signer_round"]["approved_weight"], 10);
    assert_eq!(snapshot["signer_round"]["rejected_weight"], 0);
    assert_eq!(
        snapshot["signer_round"]["votes"].as_array().unwrap().len(),
        1
    );
    assert_eq!(snapshot["signer_round"]["votes"][0]["decision"], "approved");
}

#[cfg(all(feature = "network_observer", feature = "monitoring_prom"))]
#[test]
fn signer_round_metrics_publish_one_exact_bounded_round() {
    let key = "02007311430123d4cad97f4f7e86e023b28143130a18099ecf094d36fef0f6135c";
    begin_libp2p_signer_round("metrics-proposal-a".into(), 61, 21, 30);
    record_libp2p_signer_vote("metrics-proposal-a", key.into(), 15, true, 15, 0, 0);
    set_libp2p_signer_round_status("metrics-proposal-a", "approved");

    assert_eq!(prometheus::MINER_SIGNER_ROUND_BLOCK_HEIGHT_GAUGE.get(), 61);
    assert_eq!(
        prometheus::MINER_SIGNER_ROUND_APPROVED_WEIGHT_GAUGE.get(),
        21
    );
    assert_eq!(
        prometheus::MINER_SIGNER_ROUND_STATUS_GAUGE
            .with_label_values(&["approved"])
            .get(),
        1
    );
    assert_eq!(
        prometheus::MINER_SIGNER_VOTE_WEIGHT_GAUGE
            .with_label_values(&[key, "approved"])
            .get(),
        15
    );

    begin_libp2p_signer_round("metrics-proposal-b".into(), 62, 21, 30);
    assert_eq!(
        prometheus::MINER_SIGNER_VOTE_WEIGHT_GAUGE
            .with_label_values(&[key, "approved"])
            .get(),
        0
    );
    assert_eq!(
        prometheus::MINER_SIGNER_VOTE_LATENCY_SECONDS_GAUGE
            .with_label_values(&[key, "approved"])
            .get(),
        0.0
    );
    assert_eq!(
        prometheus::MINER_SIGNER_ROUND_STATUS_GAUGE
            .with_label_values(&["collecting"])
            .get(),
        1
    );
}

#[cfg(not(feature = "network_observer"))]
#[test]
fn default_build_retains_no_identity_bearing_signer_round() {
    set_libp2p_network_diagnostics(serde_json::json!({"connected_peers": []}));
    begin_libp2p_signer_round("proposal-a".into(), 61, 21, 30);
    record_libp2p_signer_vote("proposal-a", "signer-a".into(), 15, true, 15, 0, 0);
    set_libp2p_signer_round_status("proposal-a", "approved");

    assert!(libp2p_network_diagnostics().get("signer_round").is_none());
}

#[allow(unused_variables)]
pub fn update_computed_relative_miner_score(value: Uint256) {
    #[cfg(feature = "monitoring_prom")]
    {
        let percentage = convert_uint256_to_f64_percentage(value, 7);
        prometheus::COMPUTED_RELATIVE_MINER_SCORE.set(percentage);
    }
}

#[allow(unused_variables)]
pub fn update_computed_miner_commitment(value: u128) {
    #[cfg(feature = "monitoring_prom")]
    {
        let high_bits = (value >> 64) as u64;
        let low_bits = value as u64;
        prometheus::COMPUTED_MINER_COMMITMENT_HIGH.set(high_bits as i64);
        prometheus::COMPUTED_MINER_COMMITMENT_LOW.set(low_bits as i64);
    }
}

#[allow(unused_variables)]
pub fn update_miner_current_median_commitment(value: u128) {
    #[cfg(feature = "monitoring_prom")]
    {
        let high_bits = (value >> 64) as u64;
        let low_bits = value as u64;
        prometheus::MINER_CURRENT_MEDIAN_COMMITMENT_HIGH.set(high_bits as i64);
        prometheus::MINER_CURRENT_MEDIAN_COMMITMENT_LOW.set(low_bits as i64);
    }
}

/// Function sets the global variable `GLOBAL_BURNCHAIN_SIGNER`.
/// Fails if there are multiple attempts to set this variable.
#[allow(unused_variables)]
pub fn set_burnchain_signer(signer: BurnchainSigner) -> Result<(), SetGlobalBurnchainSignerError> {
    #[cfg(feature = "monitoring_prom")]
    {
        let mut signer_mutex = GLOBAL_BURNCHAIN_SIGNER.lock().unwrap();
        if signer_mutex.is_some() {
            return Err(SetGlobalBurnchainSignerError);
        }

        *signer_mutex = Some(signer);
    }
    Ok(())
}

#[allow(unreachable_code)]
pub fn get_burnchain_signer() -> Option<BurnchainSigner> {
    #[cfg(feature = "monitoring_prom")]
    {
        return GLOBAL_BURNCHAIN_SIGNER.lock().unwrap().clone();
    }
    None
}

define_named_enum!(MinerStopReason {
    NoTransactions("no_transactions"),
    Preempted("preempted"),
    LimitReached("limit_reached"),
    DeadlineReached("deadline_reached"),
});

// Increment the counter for the given miner stop reason.
#[allow(unused_variables)]
pub fn increment_miner_stop_reason(reason: MinerStopReason) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::MINER_STOP_REASON_TOTAL
        .with_label_values(&[reason.get_name_str()])
        .inc();
}

#[derive(Debug)]
pub struct SetGlobalBurnchainSignerError;

impl fmt::Display for SetGlobalBurnchainSignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("A global default burnchain signer has already been set.")
    }
}

impl Error for SetGlobalBurnchainSignerError {}
