use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use clarity::util::secp256k1::Secp256k1PublicKey;
use serde::Deserialize;
use stacks::net::rpc_services::{SortitionQuery, TenureSelector};
use stacks_common::types::chainstate::BurnchainHeaderHash;

use super::super::blocking::run_blocking;
use super::super::AppState;
use super::common::{
    parse_block_id, parse_consensus_hash, parse_limit, parse_reward_cycle, parse_tip, PageQuery,
    ReadQuery,
};
use crate::error::{ApiError, ApiErrorCode};
use crate::models::{
    HeadersResponse, SignerActivityResponse, SortitionsResponse, StackerSetResponse,
    TenureBlocksPageResponse, TenureForkInfoResponse, TenureTipResponse,
};

pub async fn get_signer_activity(
    State(state): State<AppState>,
    Path((public_key, reward_cycle)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let public_key = Secp256k1PublicKey::from_hex(&public_key).map_err(|_| {
        ApiError::bad_request(
            ApiErrorCode::InvalidSignerPublicKey,
            format!("Failed to parse signer public key: {public_key}"),
        )
    })?;
    let reward_cycle = parse_reward_cycle(&reward_cycle)?;
    let reads = state.chainstate_reads.clone();
    let blocks_signed =
        run_blocking(move || reads.get_signer_block_count(public_key, reward_cycle)).await?;
    Ok(Json(SignerActivityResponse { blocks_signed }).into_response())
}

pub async fn get_tenure_tip(
    State(state): State<AppState>,
    Path(consensus_hash): Path<String>,
) -> Result<Response, ApiError> {
    let consensus_hash = parse_consensus_hash(&consensus_hash)?;
    let reads = state.chainstate_reads.clone();
    let tip = run_blocking(move || reads.get_tenure_tip(consensus_hash)).await?;
    Ok(Json(TenureTipResponse::from(tip)).into_response())
}

pub async fn get_pox_info(
    State(state): State<AppState>,
    Query(query): Query<ReadQuery>,
) -> Result<Response, ApiError> {
    let tip = parse_tip(query.tip)?;
    let reads = state.chainstate_reads.clone();
    let pox = run_blocking(move || reads.get_pox_info(tip)).await?;
    Ok(Json(pox).into_response())
}

pub async fn get_stacker_set(
    State(state): State<AppState>,
    Path(reward_cycle): Path<String>,
    Query(query): Query<ReadQuery>,
) -> Result<Response, ApiError> {
    let reward_cycle = parse_reward_cycle(&reward_cycle)?;
    let tip = parse_tip(query.tip)?;
    let reads = state.chainstate_reads.clone();
    let reward_set = run_blocking(move || reads.get_stacker_set(reward_cycle, tip)).await?;
    Ok(Json(StackerSetResponse {
        reward_cycle,
        reward_set,
    })
    .into_response())
}

pub async fn get_latest_sortition(State(state): State<AppState>) -> Result<Response, ApiError> {
    get_sortitions(state, SortitionQuery::Latest).await
}

pub async fn get_latest_and_last_sortitions(
    State(state): State<AppState>,
) -> Result<Response, ApiError> {
    get_sortitions(state, SortitionQuery::LatestAndLast).await
}

pub async fn get_sortition_by_consensus(
    State(state): State<AppState>,
    Path(consensus_hash): Path<String>,
) -> Result<Response, ApiError> {
    let consensus_hash = parse_consensus_hash(&consensus_hash)?;
    get_sortitions(state, SortitionQuery::ConsensusHash(consensus_hash)).await
}

pub async fn get_sortition_by_burn_block(
    State(state): State<AppState>,
    Path(burn_block_hash): Path<String>,
) -> Result<Response, ApiError> {
    let burn_block_hash = BurnchainHeaderHash::from_hex(&burn_block_hash).map_err(|_| {
        ApiError::bad_request(
            ApiErrorCode::InvalidBurnBlockHash,
            format!("Failed to parse burn block hash: {burn_block_hash}"),
        )
    })?;
    get_sortitions(state, SortitionQuery::BurnBlockHash(burn_block_hash)).await
}

pub async fn get_sortition_by_burn_height(
    State(state): State<AppState>,
    Path(burn_block_height): Path<String>,
) -> Result<Response, ApiError> {
    let burn_block_height = burn_block_height.parse::<u64>().map_err(|_| {
        ApiError::bad_request(
            ApiErrorCode::InvalidBurnBlockHeight,
            format!("Failed to parse burn block height: {burn_block_height}"),
        )
    })?;
    get_sortitions(state, SortitionQuery::BurnBlockHeight(burn_block_height)).await
}

async fn get_sortitions(state: AppState, query: SortitionQuery) -> Result<Response, ApiError> {
    let reads = state.chainstate_reads.clone();
    let sortitions = run_blocking(move || reads.get_sortitions(query)).await?;
    Ok(Json(SortitionsResponse { sortitions }).into_response())
}

#[derive(Default, Deserialize)]
pub struct HeaderQuery {
    tip: Option<String>,
    limit: Option<String>,
}

pub async fn get_headers(
    State(state): State<AppState>,
    Query(query): Query<HeaderQuery>,
) -> Result<Response, ApiError> {
    let tip = parse_tip(query.tip)?;
    let limit = parse_limit(query.limit.as_deref(), 100, stacks::net::MAX_HEADERS)? as u32;
    let reads = state.chainstate_reads.clone();
    let headers = run_blocking(move || reads.get_headers(limit, tip)).await?;
    Ok(Json(HeadersResponse { headers }).into_response())
}

pub async fn get_tenure_blocks_by_consensus(
    State(state): State<AppState>,
    Path(consensus_hash): Path<String>,
    Query(query): Query<PageQuery>,
) -> Result<Response, ApiError> {
    let consensus_hash = parse_consensus_hash(&consensus_hash)?;
    get_tenure_blocks_page(state, TenureSelector::ConsensusHash(consensus_hash), query).await
}

pub async fn get_tenure_blocks_by_burn_block(
    State(state): State<AppState>,
    Path(burn_block_hash): Path<String>,
    Query(query): Query<PageQuery>,
) -> Result<Response, ApiError> {
    let hash = BurnchainHeaderHash::from_hex(&burn_block_hash).map_err(|_| {
        ApiError::bad_request(
            ApiErrorCode::InvalidBurnBlockHash,
            format!("Failed to parse burn block hash: {burn_block_hash}"),
        )
    })?;
    get_tenure_blocks_page(state, TenureSelector::BurnBlockHash(hash), query).await
}

pub async fn get_tenure_blocks_by_burn_height(
    State(state): State<AppState>,
    Path(burn_block_height): Path<String>,
    Query(query): Query<PageQuery>,
) -> Result<Response, ApiError> {
    let height = burn_block_height.parse::<u64>().map_err(|_| {
        ApiError::bad_request(
            ApiErrorCode::InvalidBurnBlockHeight,
            format!("Failed to parse burn block height: {burn_block_height}"),
        )
    })?;
    get_tenure_blocks_page(state, TenureSelector::BurnBlockHeight(height), query).await
}

async fn get_tenure_blocks_page(
    state: AppState,
    selector: TenureSelector,
    query: PageQuery,
) -> Result<Response, ApiError> {
    let cursor = query
        .cursor
        .map(|cursor| parse_block_id(&cursor))
        .transpose()?;
    let limit = parse_limit(query.limit.as_deref(), 100, 1_000)?;
    let reads = state.chainstate_reads.clone();
    let page = run_blocking(move || reads.get_tenure_blocks_page(selector, cursor, limit)).await?;
    Ok(Json(TenureBlocksPageResponse::from(page)).into_response())
}

pub async fn get_tenure_fork_info(
    State(state): State<AppState>,
    Path((start, end)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let start = parse_consensus_hash(&start)?;
    let end = parse_consensus_hash(&end)?;
    let reads = state.chainstate_reads.clone();
    let tenures = run_blocking(move || reads.get_tenure_fork_info(start, end)).await?;
    Ok(Json(TenureForkInfoResponse { tenures }).into_response())
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use stacks::net::rpc_bridge::rpc_bridge;

    use super::super::test_support::*;

    #[test]
    fn serves_signer_activity_from_read_pool() {
        let (node, endpoints) = rpc_bridge();
        spawn_test_node(&node, endpoints);
        let addr = free_addr();
        let _server =
            spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
                .unwrap();
        let client = reqwest::blocking::Client::new();

        let signer = "0243311589af63c2adda04fcd7792c038a05c12a4fe40351b3eb1612ff6b2e5a0e";
        let activity = wait_get(
            &client,
            &format!("http://{addr}/rpc/v1/signers/{signer}/cycles/12"),
        );
        assert_eq!(activity.status().as_u16(), StatusCode::OK.as_u16());
        let activity: serde_json::Value = activity.json().unwrap();
        assert_eq!(activity["blocks_signed"], 7);
    }

    #[test]
    fn rejects_invalid_chain_parameters() {
        let (node, endpoints) = rpc_bridge();
        spawn_test_node(&node, endpoints);
        let addr = free_addr();
        let _server =
            spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
                .unwrap();
        let client = reqwest::blocking::Client::new();

        let cases = [
            (
                "signers/not-a-public-key/cycles/1",
                "invalid_signer_public_key",
            ),
            ("tenures/not-a-consensus-hash/tip", "invalid_consensus_hash"),
        ];
        for (path, code) in cases {
            let response = wait_get(&client, &format!("http://{addr}/rpc/v1/{path}"));
            assert_eq!(response.status().as_u16(), StatusCode::BAD_REQUEST.as_u16());
            let body: serde_json::Value = response.json().unwrap();
            assert_eq!(body["error"]["code"], code);
        }
    }

    #[test]
    fn serves_bounded_header_and_tenure_fork_queries() {
        let (node, endpoints) = rpc_bridge();
        spawn_test_node(&node, endpoints);
        let addr = free_addr();
        let _server =
            spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
                .unwrap();
        let client = reqwest::blocking::Client::new();

        let headers = wait_get(&client, &format!("http://{addr}/rpc/v1/headers?limit=25"));
        assert_eq!(headers.status().as_u16(), StatusCode::OK.as_u16());
        let headers: serde_json::Value = headers.json().unwrap();
        assert_eq!(headers["headers"], serde_json::json!([]));

        let start = "0101010101010101010101010101010101010101";
        let end = "0202020202020202020202020202020202020202";
        let forks = wait_get(
            &client,
            &format!("http://{addr}/rpc/v1/tenures/forks/{start}/{end}"),
        );
        assert_eq!(forks.status().as_u16(), StatusCode::OK.as_u16());
        let forks: serde_json::Value = forks.json().unwrap();
        assert_eq!(forks["tenures"], serde_json::json!([]));

        let tenure = wait_get(
            &client,
            &format!("http://{addr}/rpc/v1/tenures/by-consensus/{start}/blocks?limit=1"),
        );
        assert_eq!(tenure.status().as_u16(), StatusCode::OK.as_u16());
        let tenure: serde_json::Value = tenure.json().unwrap();
        assert_eq!(tenure["burn_block_height"], 100);
        assert_eq!(tenure["blocks"].as_array().unwrap().len(), 1);
        assert_eq!(
            tenure["next_cursor"],
            "0606060606060606060606060606060606060606060606060606060606060606"
        );
    }

    #[test]
    fn rejects_invalid_pagination() {
        let (node, endpoints) = rpc_bridge();
        spawn_test_node(&node, endpoints);
        let addr = free_addr();
        let _server =
            spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
                .unwrap();
        let client = reqwest::blocking::Client::new();

        let response = wait_get(&client, &format!("http://{addr}/rpc/v1/headers?limit=0"));
        assert_eq!(response.status().as_u16(), StatusCode::BAD_REQUEST.as_u16());
        let body: serde_json::Value = response.json().unwrap();
        assert_eq!(body["error"]["code"], "invalid_pagination");
    }
}
