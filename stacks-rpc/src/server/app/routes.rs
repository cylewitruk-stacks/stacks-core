use std::sync::Arc;
use std::time::Duration;

use axum::error_handling::HandleErrorLayer;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::{BoxError, Router};
use stacks::net::rpc_bridge::RpcNodeHandle;
use stacks_common::codec::MAX_PAYLOAD_LEN;
use tokio::sync::Semaphore;
use tower::limit::GlobalConcurrencyLimitLayer;
use tower::ServiceBuilder;

use super::chainstate::ChainstateReadService;
use super::fees::FeeEstimationService;
use super::mempool::MempoolReadService;
use super::AppState;
use crate::error::{ApiError, ApiErrorCode};

mod blocks;
mod chain;
mod common;
mod contracts;
mod node;
mod proposals;
mod transactions;

const MAX_CONCURRENT_BLOCK_STREAMS: usize = 16;
const MAX_CONCURRENT_RPC_REQUESTS: usize = 256;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REQUEST_BODY_BYTES: usize = MAX_PAYLOAD_LEN as usize + 1;

#[derive(Clone, Copy)]
struct RouterLimits {
    block_streams: usize,
    max_concurrent_requests: usize,
    request_timeout: Duration,
    request_body_bytes: usize,
}

impl Default for RouterLimits {
    fn default() -> Self {
        Self {
            block_streams: MAX_CONCURRENT_BLOCK_STREAMS,
            max_concurrent_requests: MAX_CONCURRENT_RPC_REQUESTS,
            request_timeout: REQUEST_TIMEOUT,
            request_body_bytes: MAX_REQUEST_BODY_BYTES,
        }
    }
}

pub fn router(
    node: RpcNodeHandle,
    chainstate_reads: ChainstateReadService,
    mempool_reads: MempoolReadService,
    fee_estimation: FeeEstimationService,
    auth_token: Option<String>,
) -> Router {
    router_with_limits(
        node,
        chainstate_reads,
        mempool_reads,
        fee_estimation,
        auth_token,
        RouterLimits::default(),
    )
}

#[cfg(test)]
fn router_with_block_stream_limit(
    node: RpcNodeHandle,
    chainstate_reads: ChainstateReadService,
    mempool_reads: MempoolReadService,
    fee_estimation: FeeEstimationService,
    auth_token: Option<String>,
    block_stream_limit: usize,
) -> Router {
    router_with_limits(
        node,
        chainstate_reads,
        mempool_reads,
        fee_estimation,
        auth_token,
        RouterLimits {
            block_streams: block_stream_limit,
            ..RouterLimits::default()
        },
    )
}

fn router_with_limits(
    node: RpcNodeHandle,
    chainstate_reads: ChainstateReadService,
    mempool_reads: MempoolReadService,
    fee_estimation: FeeEstimationService,
    auth_token: Option<String>,
    limits: RouterLimits,
) -> Router {
    Router::new()
        .route("/rpc/v1/info", get(node::get_info))
        .route("/rpc/v1/health", get(node::get_health))
        .route("/rpc/v1/tenures/current", get(node::get_current_tenure))
        .route("/rpc/v1/accounts/{principal}", get(node::get_account))
        .route(
            "/rpc/v1/contracts/{address}/{contract}/source",
            get(contracts::get_contract_source),
        )
        .route(
            "/rpc/v1/contracts/{address}/{contract}/interface",
            get(contracts::get_contract_interface),
        )
        .route(
            "/rpc/v1/contracts/{address}/{contract}/data-vars/{name}",
            get(contracts::get_data_var),
        )
        .route(
            "/rpc/v1/contracts/{address}/{contract}/constants/{name}",
            get(contracts::get_constant),
        )
        .route(
            "/rpc/v1/contracts/{address}/{contract}/maps/{name}/entries",
            post(contracts::get_map_entry),
        )
        .route(
            "/rpc/v1/contracts/{address}/{contract}/metadata/{key}",
            get(contracts::get_clarity_metadata),
        )
        .route(
            "/rpc/v1/contracts/{address}/{contract}/functions/{function}/call-read",
            post(contracts::call_read_only),
        )
        .route(
            "/rpc/v1/contracts/{address}/{contract}/traits/{trait_address}/{trait_contract}/{trait_name}",
            get(contracts::get_trait_implementation),
        )
        .route(
            "/rpc/v1/blocks/{block_id}",
            get(blocks::get_nakamoto_block),
        )
        .route(
            "/rpc/v1/blocks/by-height/{height}",
            get(blocks::get_nakamoto_block_by_height),
        )
        .route(
            "/rpc/v1/transactions/{txid}",
            get(transactions::get_confirmed_transaction),
        )
        .route(
            "/rpc/v1/transactions",
            post(transactions::post_transaction),
        )
        .route(
            "/rpc/v1/fees/transactions",
            post(transactions::estimate_transaction_fee),
        )
        .route(
            "/rpc/v1/mempool/transactions/{txid}",
            get(transactions::get_mempool_transaction),
        )
        .route(
            "/rpc/v1/mempool/transactions",
            get(transactions::get_mempool_transactions),
        )
        .route(
            "/rpc/v1/signers/{public_key}/cycles/{reward_cycle}",
            get(chain::get_signer_activity),
        )
        .route(
            "/rpc/v1/tenures/{consensus_hash}/tip",
            get(chain::get_tenure_tip),
        )
        .route("/rpc/v1/pox", get(chain::get_pox_info))
        .route(
            "/rpc/v1/stacking/reward-cycles/{reward_cycle}/stackers",
            get(chain::get_stacker_set),
        )
        .route(
            "/rpc/v1/sortitions/latest",
            get(chain::get_latest_sortition),
        )
        .route(
            "/rpc/v1/sortitions/latest-and-last",
            get(chain::get_latest_and_last_sortitions),
        )
        .route(
            "/rpc/v1/sortitions/by-consensus/{consensus_hash}",
            get(chain::get_sortition_by_consensus),
        )
        .route(
            "/rpc/v1/sortitions/by-burn-block/{burn_block_hash}",
            get(chain::get_sortition_by_burn_block),
        )
        .route(
            "/rpc/v1/sortitions/by-burn-height/{burn_block_height}",
            get(chain::get_sortition_by_burn_height),
        )
        .route("/rpc/v1/headers", get(chain::get_headers))
        .route(
            "/rpc/v1/tenures/by-consensus/{consensus_hash}/blocks",
            get(chain::get_tenure_blocks_by_consensus),
        )
        .route(
            "/rpc/v1/tenures/by-burn-block/{burn_block_hash}/blocks",
            get(chain::get_tenure_blocks_by_burn_block),
        )
        .route(
            "/rpc/v1/tenures/by-burn-height/{burn_block_height}/blocks",
            get(chain::get_tenure_blocks_by_burn_height),
        )
        .route(
            "/rpc/v1/tenures/forks/{start}/{end}",
            get(chain::get_tenure_fork_info),
        )
        .route(
            "/rpc/v1/block-proposals",
            post(proposals::post_block_proposal),
        )
        .with_state(AppState {
            node,
            chainstate_reads,
            mempool_reads,
            fee_estimation,
            auth_token,
            block_streams: Arc::new(Semaphore::new(limits.block_streams)),
        })
        .layer(DefaultBodyLimit::max(limits.request_body_bytes))
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(handle_middleware_error))
                .timeout(limits.request_timeout)
                .layer(GlobalConcurrencyLimitLayer::new(
                    limits.max_concurrent_requests,
                )),
        )
}

async fn handle_middleware_error(error: BoxError) -> ApiError {
    if error.is::<tower::timeout::error::Elapsed>() {
        return ApiError::unavailable(ApiErrorCode::RequestTimeout, "RPC request timed out");
    }

    ApiError::internal(
        ApiErrorCode::InternalError,
        format!("RPC middleware failed: {error}"),
    )
}

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::http::StatusCode;
    use stacks::net::rpc_bridge::rpc_bridge;

    use super::super::fees::FeeEstimationService;
    use super::test_support::*;
    use super::{router_with_limits, RouterLimits};

    #[test]
    fn request_timeout_layer_returns_json_error() {
        let (node, endpoints) = rpc_bridge();
        spawn_test_node(&node, endpoints);
        let addr = free_addr();
        let _server = spawn_test_router(
            addr,
            router_with_limits(
                node,
                slow_chainstate_reads(Duration::from_millis(100)),
                mock_mempool_reads(),
                FeeEstimationService::new(None),
                Some("password".into()),
                RouterLimits {
                    request_timeout: Duration::from_millis(10),
                    ..RouterLimits::default()
                },
            ),
        )
        .unwrap();
        let client = reqwest::blocking::Client::new();

        let response = wait_get(
            &client,
            &format!("http://{addr}/rpc/v1/accounts/ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R"),
        );
        assert_eq!(
            response.status().as_u16(),
            StatusCode::SERVICE_UNAVAILABLE.as_u16()
        );
        let body: serde_json::Value = response.json().unwrap();
        assert_eq!(body["error"]["code"], "request_timeout");
    }
}
