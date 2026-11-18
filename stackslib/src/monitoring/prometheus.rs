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

use lazy_static::lazy_static;
use prometheus::{
    histogram_opts, labels, opts, register_gauge, register_histogram, register_histogram_vec,
    register_int_counter, register_int_counter_vec, register_int_gauge, register_int_gauge_vec,
    Gauge, GaugeVec, Histogram, HistogramTimer, HistogramVec, IntCounter, IntCounterVec, IntGauge,
};

lazy_static! {
    pub static ref RPC_CALL_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_rpc_requests_total",
        "Total number of RPC requests made.",
        labels! {"handler" => "all",}
    )).unwrap();

    pub static ref RPC_CALL_LATENCIES_HISTOGRAM: HistogramVec = register_histogram_vec!(histogram_opts!(
        "stacks_node_rpc_call_latencies_histogram",
        "Time (seconds) measuring RPC calls latency"
        // Will use DEFAULT_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0] by default
    ), &["path"]).unwrap();

    pub static ref BLOCK_PROPOSAL_VALIDATION_EXECUTIONS: IntCounterVec = register_int_counter_vec!(
        "stacks_node_block_proposal_validation_executions_total",
        "Independent block-proposal validation executions performed by this node, by outcome",
        &["outcome"]
    )
    .unwrap();

    pub static ref BLOCK_PROPOSAL_VALIDATION_EXECUTION_SECONDS: HistogramVec = register_histogram_vec!(histogram_opts!(
        "stacks_node_block_proposal_validation_execution_seconds",
        "Wall-clock duration of independent block-proposal validation executions",
        vec![0.005, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 20.0, 30.0, 60.0, 120.0]
    ), &["outcome"]).unwrap();

    pub static ref STX_BLOCKS_RECEIVED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_stx_blocks_received_total",
        "Total number of Stacks blocks received"
    )).unwrap();

    pub static ref STX_MICRO_BLOCKS_RECEIVED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_stx_micro_blocks_received_total",
        "Total number of Stacks micro blocks received"
    )).unwrap();

    pub static ref STX_BLOCKS_SERVED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_stx_blocks_served_total",
        "Total number of Stacks blocks served"
    )).unwrap();

    pub static ref STX_MICRO_BLOCKS_SERVED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_stx_micro_blocks_served_total",
        "Total number of Stacks micro blocks served"
    )).unwrap();

    pub static ref STX_CONFIRMED_MICRO_BLOCKS_SERVED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_stx_confirmed_micro_blocks_served_total",
        "Total number of Stacks blocks served"
    )).unwrap();

    pub static ref TXS_RECEIVED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_transactions_received_total",
        "Total number of transactions received and relayed"
    )).unwrap();

    pub static ref BTC_BLOCKS_RECEIVED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_btc_blocks_received_total",
        "Total number of blocks processed from the burnchain"
    )).unwrap();

    pub static ref BTC_OPS_SENT_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_btc_ops_sent_total",
        "Total number of ops (key registrations, block commits, user burn supports) submitted to the burnchain"
    )).unwrap();

    pub static ref STX_BLOCKS_PROCESSED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_stx_blocks_processed_total",
        "Total number of stacks blocks processed"
    )).unwrap();

    pub static ref STX_BLOCKS_MINED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_stx_blocks_mined_total",
        "Total number of stacks blocks mined by node"
    )).unwrap();

    pub static ref WARNING_EMITTED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_warning_emitted_total",
        "Total number of warning logs emitted by node"
    )).unwrap();

    pub static ref ERRORS_EMITTED_COUNTER: IntCounter = register_int_counter!(opts!(
        "stacks_node_errors_emitted_total",
        "Total number of error logs emitted by node"
    )).unwrap();

    pub static ref LAST_BLOCK_READ_COUNT: Gauge = register_gauge!(opts!(
        "stacks_node_last_block_read_count",
        "`execution_cost_read_count` for the last block observed."
    )).unwrap();

    pub static ref LAST_BLOCK_WRITE_COUNT: Gauge = register_gauge!(opts!(
        "stacks_node_last_block_write_count",
        "`execution_cost_write_count` for the last block observed."
    )).unwrap();

    pub static ref LAST_BLOCK_READ_LENGTH: Gauge = register_gauge!(opts!(
        "stacks_node_last_block_read_length",
        "`execution_cost_read_length` for the last block observed."
    )).unwrap();

    pub static ref LAST_BLOCK_WRITE_LENGTH: Gauge = register_gauge!(opts!(
        "stacks_node_last_block_write_length",
        "`execution_cost_write_length` for the last block observed."
    )).unwrap();

    pub static ref LAST_BLOCK_RUNTIME: Gauge = register_gauge!(opts!(
        "stacks_node_last_block_runtime",
        "`execution_cost_runtime` for the last block observed."
    )).unwrap();

    pub static ref LAST_BLOCK_TRANSACTION_COUNT: IntGauge = register_int_gauge!(opts!(
        "stacks_node_last_block_transaction_count",
        "Number of transactions in the last block."
    )).unwrap();

    pub static ref LAST_MINED_BLOCK_READ_COUNT: Gauge = register_gauge!(opts!(
        "stacks_node_last_mined_block_read_count",
        "`execution_cost_read_count` for the last mined block produced."
    )).unwrap();

    pub static ref LAST_MINED_BLOCK_WRITE_COUNT: Gauge = register_gauge!(opts!(
        "stacks_node_last_mined_block_write_count",
        "`execution_cost_write_count` for the last mined block produced."
    )).unwrap();

    pub static ref LAST_MINED_BLOCK_READ_LENGTH: Gauge = register_gauge!(opts!(
        "stacks_node_last_mined_block_read_length",
        "`execution_cost_read_length` for the last mined block produced."
    )).unwrap();

    pub static ref LAST_MINED_BLOCK_WRITE_LENGTH: Gauge = register_gauge!(opts!(
        "stacks_node_last_mined_block_write_length",
        "`execution_cost_write_length` for the last mined block produced."
    )).unwrap();

    pub static ref LAST_MINED_BLOCK_RUNTIME: Gauge = register_gauge!(opts!(
        "stacks_node_last_mined_block_runtime",
        "`execution_cost_runtime` for the last mined block produced."
    )).unwrap();

    pub static ref LAST_MINED_BLOCK_TRANSACTION_COUNT: IntGauge = register_int_gauge!(opts!(
        "stacks_node_last_mined_block_transaction_count",
        "Number of transactions in the last mined block."
    )).unwrap();


    pub static ref ACTIVE_MINERS_COUNT_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_node_active_miners_total",
        "Total number of active miners"
    )).unwrap();

    pub static ref STACKS_TIP_HEIGHT_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_node_stacks_tip_height",
        "Stacks chain tip height"
    )).unwrap();

    pub static ref STACKS_TIP_LAST_CHANGED_TIMESTAMP_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_node_stacks_tip_last_changed_timestamp_seconds",
        "Unix timestamp when the observed Stacks chain tip height last changed"
    )).unwrap();

    pub static ref BURNCHAIN_HEIGHT_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_node_burn_block_height",
        "Burnchain tip height"
    )).unwrap();

    pub static ref BURNCHAIN_LAST_CHANGED_TIMESTAMP_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_node_burn_block_last_changed_timestamp_seconds",
        "Unix timestamp when the observed burnchain tip height last changed"
    )).unwrap();

    pub static ref INBOUND_NEIGHBORS_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_node_neighbors_inbound",
        "Total count of current known inbound neighbors"
    )).unwrap();

    pub static ref OUTBOUND_NEIGHBORS_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_node_neighbors_outbound",
        "Total count of current known outbound neighbors"
    )).unwrap();

    pub static ref LIBP2P_CONNECTIONS_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_p2p_connections",
        "Current number of native libp2p connections"
    )).unwrap();

    pub static ref LIBP2P_AUTHENTICATED_SIGNER_LINK_GAUGE: prometheus::IntGaugeVec = register_int_gauge_vec!(opts!(
        "stacks_p2p_authenticated_signer_link",
        "Current endpoint-free link evidence to a chain-authorized signer public key"
    ), &["signer_public_key"]).unwrap();

    pub static ref LIBP2P_CONNECTED_PEER_GAUGE: prometheus::IntGaugeVec = register_int_gauge_vec!(opts!(
        "stacks_p2p_connected_peer",
        "Current native connection to a transport PeerId; the authenticated observer joins only enrolled identities"
    ), &["peer_id"]).unwrap();

    pub static ref MINER_SIGNER_ROUND_STATUS_GAUGE: prometheus::IntGaugeVec = register_int_gauge_vec!(opts!(
        "stacks_miner_signer_round_status",
        "One-hot status of the miner's single bounded latest signer round"
    ), &["status"]).unwrap();

    pub static ref MINER_SIGNER_ROUND_BLOCK_HEIGHT_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_miner_signer_round_block_height",
        "Proposed Stacks block height for the miner's single bounded latest signer round"
    )).unwrap();

    pub static ref MINER_SIGNER_ROUND_STARTED_TIMESTAMP_GAUGE: Gauge = register_gauge!(opts!(
        "stacks_miner_signer_round_started_timestamp_seconds",
        "Unix timestamp when the miner's single bounded latest signer round started"
    )).unwrap();

    pub static ref MINER_SIGNER_ROUND_THRESHOLD_WEIGHT_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_miner_signer_round_threshold_weight",
        "Approval weight required by the miner's single bounded latest signer round"
    )).unwrap();

    pub static ref MINER_SIGNER_ROUND_TOTAL_WEIGHT_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_miner_signer_round_total_weight",
        "Total signer weight for the miner's single bounded latest signer round"
    )).unwrap();

    pub static ref MINER_SIGNER_ROUND_APPROVED_WEIGHT_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_miner_signer_round_approved_weight",
        "Approval weight received by the miner's single bounded latest signer round"
    )).unwrap();

    pub static ref MINER_SIGNER_ROUND_REJECTED_WEIGHT_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_miner_signer_round_rejected_weight",
        "Rejection weight received by the miner's single bounded latest signer round"
    )).unwrap();

    pub static ref MINER_SIGNER_ROUND_UNAVAILABLE_WEIGHT_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_miner_signer_round_unavailable_weight",
        "Temporary unavailable weight in the miner's single bounded latest signer round"
    )).unwrap();

    pub static ref MINER_SIGNER_VOTE_WEIGHT_GAUGE: prometheus::IntGaugeVec = register_int_gauge_vec!(opts!(
        "stacks_miner_signer_vote_weight",
        "Weight of an authenticated response in the miner's bounded latest signer round"
    ), &["signer_public_key", "decision"]).unwrap();

    pub static ref MINER_SIGNER_VOTE_LATENCY_SECONDS_GAUGE: GaugeVec = {
        let gauge = GaugeVec::new(opts!(
            "stacks_miner_signer_vote_latency_seconds",
            "Response latency for an authenticated vote in the miner's bounded latest signer round"
        ), &["signer_public_key", "decision"]).unwrap();
        prometheus::register(Box::new(gauge.clone())).unwrap();
        gauge
    };

    pub static ref LIBP2P_SYNC_CAPABLE_PEERS_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_p2p_sync_capable_peers",
        "Current number of Hello-authenticated native sync peers"
    )).unwrap();

    pub static ref LIBP2P_SWARM_LAG_SECONDS_GAUGE: Gauge = register_gauge!(opts!(
        "stacks_p2p_swarm_lag_seconds",
        "Most recently observed native swarm scheduler lag in seconds"
    )).unwrap();

    pub static ref LIBP2P_COMMAND_QUEUE_RESIDENCE_SECONDS_GAUGE: Gauge = register_gauge!(opts!(
        "stacks_p2p_command_queue_residence_seconds",
        "Most recently observed native command queue residence in seconds"
    )).unwrap();

    pub static ref LIBP2P_OLDEST_ITEM_WAITING_SECONDS_GAUGE: Gauge = register_gauge!(opts!(
        "stacks_p2p_oldest_item_waiting_seconds",
        "Age of the oldest item waiting in the bounded native command queue"
    )).unwrap();

    pub static ref OBSERVABILITY_BLOCKED_ON_GAUGE: prometheus::IntGaugeVec = register_int_gauge_vec!(opts!(
        "stacks_observability_blocked_on",
        "One-hot bounded current blocking reason for a local subsystem"
    ), &["subsystem", "reason"]).unwrap();

    pub static ref LIBP2P_STALL_REASON_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_p2p_stall_reason_code",
        "Bounded native stall reason: 0 healthy, 1 no peers, 2 no sync peers, 3 swarm lag, 4 command queue, 5 sync failures, 6 orphaned validation result"
    )).unwrap();

    pub static ref LIBP2P_EVENTS_COUNTER: IntCounterVec = register_int_counter_vec!(opts!(
        "stacks_p2p_events_total",
        "Cumulative native libp2p outcomes by a fixed low-cardinality event class"
    ), &["event"]).unwrap();

    pub static ref OBSERVABILITY_SPANS_DROPPED_COUNTER: IntCounterVec = register_int_counter_vec!(opts!(
        "stacks_observability_spans_dropped_total",
        "Spans discarded by the bounded optional OpenTelemetry path"
    ), &["reason"]).unwrap();

    pub static ref LIBP2P_OBJECT_CACHE_ITEMS_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_p2p_object_cache_items",
        "Current number of contextually accepted objects in the bounded native cache"
    )).unwrap();

    pub static ref LIBP2P_OBJECT_CACHE_BYTES_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_p2p_object_cache_bytes",
        "Current bytes retained in the bounded native object cache"
    )).unwrap();

    pub static ref LIBP2P_PEER_STORE_PEERS_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_p2p_peer_store_peers",
        "Current PeerIds retained in the bounded native restart-discovery cache"
    )).unwrap();

    pub static ref LIBP2P_PEER_STORE_ADDRESSES_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_p2p_peer_store_addresses",
        "Current verified dial endpoints retained in the bounded native restart-discovery cache"
    )).unwrap();

    pub static ref LIBP2P_PEER_RTT_SECONDS_GAUGE: Gauge = register_gauge!(opts!(
        "stacks_p2p_peer_rtt_seconds",
        "Mean RTT across currently connected native peers"
    )).unwrap();

    pub static ref INBOUND_BANDWIDTH_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_node_bandwidth_inbound",
        "Total inbound bandwidth total in bytes"
    )).unwrap();

    pub static ref OUTBOUND_BANDWIDTH_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_node_bandwidth_outbound",
        "Total outbound bandwidth total in bytes"
    )).unwrap();

    pub static ref INBOUND_RPC_BANDWIDTH_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_node_rpc_bandwidth_inbound",
        "Total RPC inbound bandwidth in bytes"
    )).unwrap();

    pub static ref OUTBOUND_RPC_BANDWIDTH_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_node_rpc_bandwidth_outbound",
        "Total RPC outbound bandwidth in bytes"
    )).unwrap();

    pub static ref MSG_COUNTER_VEC: IntCounterVec = register_int_counter_vec!(
        "stacks_node_message_count",
        "Stacks message count by type of message",
        &["name"]
    ).unwrap();


    pub static ref STX_MEMPOOL_GC: IntCounter = register_int_counter!(opts!(
        "stacks_node_mempool_gc_count",
        "Total count of all mempool garbage collections"
    )).unwrap();

    pub static ref CONTRACT_CALLS_PROCESSED_COUNT: IntCounter = register_int_counter!(opts!(
        "stacks_contract_calls_processed",
        "Total count of processed contract calls"
    )).unwrap();

    pub static ref MEMPOOL_OUTSTANDING_TXS: IntGauge = register_int_gauge!(opts!(
        "stacks_node_mempool_outstanding_txs",
        "Number of still-unprocessed transactions received by this node since it started",
        labels! {"handler" => "all",}
    )).unwrap();

    pub static ref MEMPOOL_TX_CONFIRM_TIME: Histogram = register_histogram!(histogram_opts!(
        "stacks_node_mempool_tx_confirm_times",
        "Time (seconds) between when a tx was received by this node's mempool and when a tx was first processed in a block",
        vec![300.0, 600.0, 900.0, 1200.0, 1500.0, 1800.0, 2100.0, 2400.0, 2700.0, 3000.0, 3600.0, 4200.0, 4800.0, 6000.0],
        labels! {"handler".to_string() => "all".to_string(),}
    )).unwrap();

    pub static ref COMPUTED_RELATIVE_MINER_SCORE: Gauge = register_gauge!(opts!(
        "stacks_node_computed_relative_miner_score",
        "Percentage of the u256 range that this miner is assigned in a particular round of sortition"
    )).unwrap();

    pub static ref COMPUTED_MINER_COMMITMENT_HIGH: IntGauge = register_int_gauge!(opts!(
        "stacks_node_computed_miner_commitment_high",
        "High 64 bits of a miner's effective commitment (min of the miner's previous commitment and their median commitment)"
    )).unwrap();

     pub static ref COMPUTED_MINER_COMMITMENT_LOW: IntGauge = register_int_gauge!(opts!(
        "stacks_node_computed_miner_commitment_low",
        "Low 64 bits of a miner's effective commitment (min of the miner's previous commitment and their median commitment)"
    )).unwrap();

    pub static ref MINER_CURRENT_MEDIAN_COMMITMENT_HIGH: IntGauge = register_int_gauge!(opts!(
        "stacks_node_miner_current_median_commitment_high",
        "High 64 bits of a miner's median commitment over the mining commitment window."
    )).unwrap();

    pub static ref MINER_CURRENT_MEDIAN_COMMITMENT_LOW: IntGauge = register_int_gauge!(opts!(
        "stacks_node_miner_current_median_commitment_low",
        "Low 64 bits of a miner's median commitment over the mining commitment window."
    )).unwrap();

    pub static ref MINER_STOP_REASON_TOTAL: IntCounterVec = register_int_counter_vec!(
        "stacks_node_miner_stop_reason_total",
        "Total number of times the miner stopped for each reason",
        &["reason"]
    ).unwrap();

    pub static ref UNREACHABLE_ERRORS_COUNTER: IntCounterVec = register_int_counter_vec!(
        "stacks_unreachable_errors_total",
        "Number of unreachable Clarity VM errors triggered (indicates potential bugs)",
        &["error_type"]
    ).unwrap();
}

pub fn new_rpc_call_timer(path: &str) -> HistogramTimer {
    let histogram = RPC_CALL_LATENCIES_HISTOGRAM.with_label_values(&[path]);
    histogram.start_timer()
}
