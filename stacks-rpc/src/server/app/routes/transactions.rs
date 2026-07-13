use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use stacks::chainstate::stacks::{StacksTransaction, TransactionPayload};
use stacks::net::atlas::Attachment;
use stacks::net::rpc_bridge::{status_reply_channel, MempoolQuery};
use stacks::net::rpc_services::TransactionSubmissionStatus;
use stacks_common::codec::StacksMessageCodec;

use super::super::blocking::{map_domain_send_error, recv_reply, run_blocking};
use super::super::extractors::ApiJson;
use super::super::AppState;
use super::common::{parse_hex_bytes, parse_limit, parse_tip, parse_txid, PageQuery, ReadQuery};
use crate::error::{ApiError, ApiErrorCode};
use crate::models::{
    ConfirmedTransactionResponse, FeeEstimateRequest, FeeEstimateResponse,
    MempoolTransactionResponse, MempoolTransactionsPageResponse, TransactionSubmitRequest,
    TransactionSubmitResponse,
};

pub async fn estimate_transaction_fee(
    State(state): State<AppState>,
    ApiJson(request): ApiJson<FeeEstimateRequest>,
) -> Result<Response, ApiError> {
    let payload_bytes = parse_hex_bytes(
        &request.transaction_payload,
        ApiErrorCode::InvalidTransactionPayload,
    )?;
    let mut encoded = payload_bytes.as_slice();
    let payload = TransactionPayload::consensus_deserialize(&mut encoded).map_err(|e| {
        ApiError::bad_request(
            ApiErrorCode::InvalidTransactionPayload,
            format!("Invalid transaction payload: {e}"),
        )
    })?;
    if !encoded.is_empty() {
        return Err(ApiError::bad_request(
            ApiErrorCode::InvalidTransactionPayload,
            "Transaction payload contains trailing bytes",
        ));
    }
    let estimated_len = request
        .estimated_length
        .unwrap_or(payload_bytes.len() as u64)
        .max(payload_bytes.len() as u64);
    let chainstate_reads = state.chainstate_reads.clone();
    let fee_estimation = state.fee_estimation.clone();
    let estimate = run_blocking(move || {
        let epoch = chainstate_reads.get_current_epoch()?;
        fee_estimation.estimate(payload, estimated_len, epoch)
    })
    .await?;
    Ok(Json(FeeEstimateResponse::from(estimate)).into_response())
}

pub async fn get_confirmed_transaction(
    State(state): State<AppState>,
    Path(txid): Path<String>,
    Query(query): Query<ReadQuery>,
) -> Result<Response, ApiError> {
    let txid = parse_txid(&txid)?;
    let tip = parse_tip(query.tip)?;
    let reads = state.chainstate_reads.clone();
    let transaction = run_blocking(move || reads.get_confirmed_transaction(txid, tip)).await?;
    Ok(Json(ConfirmedTransactionResponse::from(transaction)).into_response())
}

pub async fn post_transaction(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<TransactionSubmitRequest>,
) -> Result<Response, ApiError> {
    let transaction_bytes = parse_hex_bytes(&body.transaction, ApiErrorCode::InvalidTransaction)?;
    let mut encoded = transaction_bytes.as_slice();
    let transaction = StacksTransaction::consensus_deserialize(&mut encoded).map_err(|e| {
        ApiError::bad_request(
            ApiErrorCode::InvalidTransaction,
            format!("Failed to deserialize transaction: {e}"),
        )
    })?;
    if !encoded.is_empty() {
        return Err(ApiError::bad_request(
            ApiErrorCode::InvalidTransaction,
            "Transaction contains trailing bytes",
        ));
    }
    let attachment = body
        .attachment
        .map(|attachment| {
            parse_hex_bytes(&attachment, ApiErrorCode::InvalidAttachment).map(Attachment::new)
        })
        .transpose()?;

    let node = state.node.clone();
    let submission = run_blocking(move || {
        let (reply, rx) = status_reply_channel();
        node.mempool
            .try_send(MempoolQuery::SubmitTransaction {
                transaction,
                attachment,
                reply,
            })
            .map_err(map_domain_send_error)?;
        recv_reply(rx)
    })
    .await?;
    let status = match submission.status {
        TransactionSubmissionStatus::Accepted => StatusCode::ACCEPTED,
        TransactionSubmissionStatus::AlreadyKnown => StatusCode::OK,
    };
    Ok((status, Json(TransactionSubmitResponse::from(submission))).into_response())
}

pub async fn get_mempool_transaction(
    State(state): State<AppState>,
    Path(txid): Path<String>,
) -> Result<Response, ApiError> {
    let txid = parse_txid(&txid)?;
    let reads = state.mempool_reads.clone();
    let transaction = run_blocking(move || reads.get_transaction(txid)).await?;
    Ok(Json(MempoolTransactionResponse::from(transaction)).into_response())
}

pub async fn get_mempool_transactions(
    State(state): State<AppState>,
    Query(query): Query<PageQuery>,
) -> Result<Response, ApiError> {
    let cursor = query.cursor.map(|cursor| parse_txid(&cursor)).transpose()?;
    let limit = parse_limit(query.limit.as_deref(), 100, 1_000)? as u64;
    let reads = state.mempool_reads.clone();
    let page = run_blocking(move || reads.get_transactions_page(cursor, limit)).await?;
    Ok(Json(MempoolTransactionsPageResponse::from(page)).into_response())
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use stacks::net::rpc_bridge::rpc_bridge;
    use stacks_common::codec::StacksMessageCodec;
    use stacks_common::util::hash::to_hex;

    use super::super::super::fees::FeeEstimationService;
    use super::super::router;
    use super::super::test_support::*;

    #[test]
    fn serves_confirmed_transaction_from_read_pool() {
        let (node, endpoints) = rpc_bridge();
        spawn_test_node(&node, endpoints);
        let addr = free_addr();
        let _server =
            spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
                .unwrap();
        let client = reqwest::blocking::Client::new();
        let txid = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

        let transaction = wait_get(
            &client,
            &format!("http://{addr}/rpc/v1/transactions/{txid}"),
        );
        assert_eq!(transaction.status().as_u16(), StatusCode::OK.as_u16());
        let transaction: serde_json::Value = transaction.json().unwrap();
        assert_eq!(transaction["block_height"], 42);
        assert_eq!(transaction["canonical"], true);
    }

    #[test]
    fn transaction_lookup_reports_when_indexing_is_disabled() {
        let (node, endpoints) = rpc_bridge();
        spawn_test_node(&node, endpoints);
        let addr = free_addr();
        let _server = spawn_axum_rpc_server(
            addr,
            node,
            mock_chainstate_reads_without_txindex(),
            Some("password".into()),
        )
        .unwrap();
        let client = reqwest::blocking::Client::new();
        let txid = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

        let response = wait_get(
            &client,
            &format!("http://{addr}/rpc/v1/transactions/{txid}"),
        );
        assert_eq!(
            response.status().as_u16(),
            StatusCode::NOT_IMPLEMENTED.as_u16()
        );
        let body: serde_json::Value = response.json().unwrap();
        assert_eq!(body["error"]["code"], "transaction_index_disabled");
    }

    #[test]
    fn submits_transaction_through_bounded_node_bridge() {
        let (node, endpoints) = rpc_bridge();
        spawn_transaction_endpoint(&node, endpoints);
        let addr = free_addr();
        let _server =
            spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
                .unwrap();
        let client = reqwest::blocking::Client::new();
        let transaction = sample_transaction();
        let expected_txid = transaction.txid().to_string();

        let response = client
            .post(format!("http://{addr}/rpc/v1/transactions"))
            .json(&serde_json::json!({
                "transaction": format!("0x{}", to_hex(&transaction.serialize_to_vec())),
            }))
            .send()
            .unwrap();
        assert_eq!(response.status().as_u16(), StatusCode::ACCEPTED.as_u16());
        let response: serde_json::Value = response.json().unwrap();
        assert_eq!(response["txid"], expected_txid);
        assert_eq!(response["status"], "accepted");
    }

    #[test]
    fn estimates_transaction_fees_through_dedicated_service() {
        let (node, _endpoints) = rpc_bridge();
        node.snapshot.publish(sample_snapshot());
        let addr = free_addr();
        let _server = spawn_test_router(
            addr,
            router(
                node,
                mock_chainstate_reads(),
                mock_mempool_reads(),
                FeeEstimationService::test_from_executor(MockFeeEstimator),
                Some("password".into()),
            ),
        )
        .unwrap();
        let client = reqwest::blocking::Client::new();
        let payload = sample_transaction().payload.serialize_to_vec();

        let response = client
            .post(format!("http://{addr}/rpc/v1/fees/transactions"))
            .json(&serde_json::json!({
                "transaction_payload": format!("0x{}", to_hex(&payload)),
                "estimated_length": 512,
            }))
            .send()
            .unwrap();
        assert_eq!(response.status().as_u16(), StatusCode::OK.as_u16());
        let response: serde_json::Value = response.json().unwrap();
        assert_eq!(response["estimated_cost_scalar"], 7);
        assert_eq!(response["estimations"][0]["fee"], 512);
    }

    #[test]
    fn fee_estimation_reports_when_estimators_are_disabled() {
        let (node, endpoints) = rpc_bridge();
        spawn_test_node(&node, endpoints);
        let addr = free_addr();
        let _server =
            spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
                .unwrap();
        let client = reqwest::blocking::Client::new();
        let payload = sample_transaction().payload.serialize_to_vec();

        let response = client
            .post(format!("http://{addr}/rpc/v1/fees/transactions"))
            .json(&serde_json::json!({
                "transaction_payload": format!("0x{}", to_hex(&payload)),
            }))
            .send()
            .unwrap();
        assert_eq!(
            response.status().as_u16(),
            StatusCode::NOT_IMPLEMENTED.as_u16()
        );
        let response: serde_json::Value = response.json().unwrap();
        assert_eq!(response["error"]["code"], "fee_estimation_disabled");
    }

    #[test]
    fn serves_mempool_transactions_through_read_pool() {
        let (node, endpoints) = rpc_bridge();
        spawn_test_node(&node, endpoints);
        let addr = free_addr();
        let _server =
            spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
                .unwrap();
        let client = reqwest::blocking::Client::new();
        let txid = "01".repeat(32);

        let transaction = wait_get(
            &client,
            &format!("http://{addr}/rpc/v1/mempool/transactions/{txid}"),
        );
        assert_eq!(transaction.status().as_u16(), StatusCode::OK.as_u16());
        let transaction: serde_json::Value = transaction.json().unwrap();
        assert_eq!(transaction["txid"], txid);
        assert_eq!(transaction["fee"], 123);
        assert_eq!(transaction["origin_nonce"], 3);

        let page = wait_get(
            &client,
            &format!("http://{addr}/rpc/v1/mempool/transactions?limit=25"),
        );
        assert_eq!(page.status().as_u16(), StatusCode::OK.as_u16());
        let page: serde_json::Value = page.json().unwrap();
        assert_eq!(page["transactions"].as_array().unwrap().len(), 1);
        assert_eq!(page["next_cursor"], "08".repeat(32));
    }

    #[test]
    fn rejects_invalid_transaction_id() {
        let (node, endpoints) = rpc_bridge();
        spawn_test_node(&node, endpoints);
        let addr = free_addr();
        let _server =
            spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
                .unwrap();
        let client = reqwest::blocking::Client::new();

        let response = wait_get(
            &client,
            &format!("http://{addr}/rpc/v1/transactions/not-a-txid"),
        );
        assert_eq!(response.status().as_u16(), StatusCode::BAD_REQUEST.as_u16());
        let response: serde_json::Value = response.json().unwrap();
        assert_eq!(response["error"]["code"], "invalid_transaction_id");
    }
}
