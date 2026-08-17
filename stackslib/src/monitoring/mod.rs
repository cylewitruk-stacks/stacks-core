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
use std::{fmt, fs};

use clarity::vm::costs::ExecutionCost;
use rusqlite::{OpenFlags, OptionalExtension};
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
    let open_flags = if fs::metadata(&db_path).is_err() {
        // need to create
        create_flag = true;
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
    } else {
        // can just open
        OpenFlags::SQLITE_OPEN_READ_WRITE
    };

    let conn = sqlite_open(&db_path, open_flags, false)?;

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
            &[txid],
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
    prometheus::STACKS_TIP_HEIGHT_GAUGE.set(value);
}

#[allow(unused_variables)]
pub fn update_burnchain_height(value: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::BURNCHAIN_HEIGHT_GAUGE.set(value);
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

    let result = intermediate_result as f64 / divisor as f64;
    result
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

define_named_enum!(SignerCoordinatorRoundEvent {
    Started("started"),
    Completed("completed"),
});

define_named_enum!(SignerCoordinatorRoundOutcome {
    Pending("pending"),
    Approved("approved"),
    Rejected("rejected"),
    Timeout("timeout"),
    BurnchainTipChanged("burnchain_tip_changed"),
    StacksTipChanged("stacks_tip_changed"),
    Error("error"),
});

define_named_enum!(SignerResponseWeightClassification {
    Approved("approved"),
    RejectedEffective("rejected_effective"),
    UnavailableClassified("unavailable_classified"),
});

define_named_enum!(SignerCoordinatorMilestone {
    ProposalToFirstResponse("proposal_to_first_response"),
    ProposalToThreshold("proposal_to_threshold"),
});

define_named_enum!(SignerCoordinatorMilestoneOutcome {
    Approved("approved"),
    Rejected("rejected"),
});

/// Increment a legacy signer-coordinator round lifecycle event.
#[allow(unused_variables)]
pub fn increment_signer_coordinator_round(
    event: SignerCoordinatorRoundEvent,
    outcome: SignerCoordinatorRoundOutcome,
) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::SIGNER_COORDINATOR_ROUNDS
        .with_label_values(&[event.get_name_str(), outcome.get_name_str()])
        .inc();
}

/// Add unique signer weight to a bounded response classification.
#[allow(unused_variables)]
pub fn add_signer_response_weight(classification: SignerResponseWeightClassification, weight: u32) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::SIGNER_RESPONSE_WEIGHT
        .with_label_values(&[classification.get_name_str()])
        .inc_by(i64::from(weight));
}

/// Observe elapsed seconds from proposal publication to a bounded round milestone.
#[allow(unused_variables)]
pub fn observe_signer_coordinator_milestone(
    milestone: SignerCoordinatorMilestone,
    outcome: SignerCoordinatorMilestoneOutcome,
    elapsed: std::time::Duration,
) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::SIGNER_COORDINATOR_MILESTONE_SECONDS
        .with_label_values(&[milestone.get_name_str(), outcome.get_name_str()])
        .observe(elapsed.as_secs_f64());
}

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

#[cfg(all(test, feature = "monitoring_prom"))]
mod signer_coordinator_metric_tests {
    use std::time::Duration;

    use super::prometheus::{
        SIGNER_COORDINATOR_MILESTONE_SECONDS, SIGNER_COORDINATOR_ROUNDS, SIGNER_RESPONSE_WEIGHT,
    };
    use super::{
        add_signer_response_weight, increment_signer_coordinator_round,
        observe_signer_coordinator_milestone, SignerCoordinatorMilestone,
        SignerCoordinatorMilestoneOutcome, SignerCoordinatorRoundEvent,
        SignerCoordinatorRoundOutcome, SignerResponseWeightClassification,
    };

    #[test]
    fn signer_coordinator_metrics_preserve_overlap_and_bounded_labels() {
        let started = SIGNER_COORDINATOR_ROUNDS.with_label_values(&["started", "pending"]);
        let completed = SIGNER_COORDINATOR_ROUNDS.with_label_values(&["completed", "approved"]);
        let started_before = started.get();
        let completed_before = completed.get();
        increment_signer_coordinator_round(
            SignerCoordinatorRoundEvent::Started,
            SignerCoordinatorRoundOutcome::Pending,
        );
        increment_signer_coordinator_round(
            SignerCoordinatorRoundEvent::Completed,
            SignerCoordinatorRoundOutcome::Approved,
        );
        assert_eq!(started.get(), started_before + 1);
        assert_eq!(completed.get(), completed_before + 1);

        let rejected = SIGNER_RESPONSE_WEIGHT.with_label_values(&["rejected_effective"]);
        let unavailable = SIGNER_RESPONSE_WEIGHT.with_label_values(&["unavailable_classified"]);
        let rejected_before = rejected.get();
        let unavailable_before = unavailable.get();
        add_signer_response_weight(SignerResponseWeightClassification::RejectedEffective, 7);
        add_signer_response_weight(SignerResponseWeightClassification::UnavailableClassified, 7);
        assert_eq!(rejected.get(), rejected_before + 7);
        assert_eq!(unavailable.get(), unavailable_before + 7);

        let first_response = SIGNER_COORDINATOR_MILESTONE_SECONDS
            .with_label_values(&["proposal_to_first_response", "approved"]);
        let threshold = SIGNER_COORDINATOR_MILESTONE_SECONDS
            .with_label_values(&["proposal_to_threshold", "rejected"]);
        let first_response_before = first_response.get_sample_count();
        let count_before = threshold.get_sample_count();
        observe_signer_coordinator_milestone(
            SignerCoordinatorMilestone::ProposalToFirstResponse,
            SignerCoordinatorMilestoneOutcome::Approved,
            Duration::from_millis(25),
        );
        observe_signer_coordinator_milestone(
            SignerCoordinatorMilestone::ProposalToThreshold,
            SignerCoordinatorMilestoneOutcome::Rejected,
            Duration::from_millis(250),
        );
        assert_eq!(first_response.get_sample_count(), first_response_before + 1);
        assert_eq!(threshold.get_sample_count(), count_before + 1);
    }
}
