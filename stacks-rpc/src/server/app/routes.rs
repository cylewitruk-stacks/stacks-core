use std::io;
use std::sync::Arc;
use std::time::Duration;

use async_stream::stream;
use axum::body::{Body, Bytes};
use axum::error_handling::HandleErrorLayer;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{BoxError, Json, Router};
use clarity::vm::types::PrincipalData;
use serde::Deserialize;
use stacks::net::httpcore::TipRequest;
use stacks::net::rpc_bridge::{status_reply_channel, BlockProposalQuery, RpcNodeHandle};
use stacks::net::rpc_services::NakamotoBlockStreamDescriptor;
use stacks_common::codec::MAX_PAYLOAD_LEN;
use stacks_common::types::chainstate::StacksBlockId;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower::limit::GlobalConcurrencyLimitLayer;
use tower::ServiceBuilder;

use super::blocking::{map_domain_send_error, recv_reply, run_blocking};
use super::chainstate::ChainstateReadService;
use super::extractors::{BlockProposalAuth, BlockProposalBody};
use super::AppState;
use crate::error::{ApiError, ApiErrorCode};
use crate::models::{AccountResponse, BlockProposalSubmitResponse, InfoResponse};

type StreamError = Box<dyn std::error::Error + Send + Sync>;

const BLOCK_STREAM_BATCH_BYTES: usize = 256 * 1024;
const MAX_CONCURRENT_BLOCK_STREAMS: usize = 16;
const MAX_CONCURRENT_RPC_REQUESTS: usize = 256;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REQUEST_BODY_BYTES: usize = MAX_PAYLOAD_LEN as usize + 1;

#[derive(Clone, Copy)]
struct RouterLimits {
    pub block_streams: usize,
    pub max_concurrent_requests: usize,
    pub request_timeout: Duration,
    pub request_body_bytes: usize,
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
    auth_token: Option<String>,
) -> Router {
    router_with_limits(node, chainstate_reads, auth_token, RouterLimits::default())
}

#[cfg(test)]
fn router_with_block_stream_limit(
    node: RpcNodeHandle,
    chainstate_reads: ChainstateReadService,
    auth_token: Option<String>,
    block_stream_limit: usize,
) -> Router {
    router_with_limits(
        node,
        chainstate_reads,
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
    auth_token: Option<String>,
    limits: RouterLimits,
) -> Router {
    Router::new()
        .route("/rpc/v1/info", get(get_info))
        .route("/rpc/v1/accounts/{principal}", get(get_account))
        .route("/rpc/v1/blocks/{block_id}", get(get_nakamoto_block))
        .route("/rpc/v1/block-proposals", post(post_block_proposal))
        .with_state(AppState {
            node,
            chainstate_reads,
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

async fn get_info(State(state): State<AppState>) -> Result<Response, ApiError> {
    let info = state.node.peer_info.load().ok_or_else(|| {
        ApiError::unavailable(
            ApiErrorCode::PeerInfoUnavailable,
            "RPC peer info snapshot is not ready",
        )
    })?;
    Ok(Json(InfoResponse::from((*info).clone())).into_response())
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

#[derive(Deserialize)]
struct AccountQuery {
    tip: Option<String>,
    proof: Option<String>,
}

async fn get_account(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    Query(query): Query<AccountQuery>,
) -> Result<Response, ApiError> {
    let principal = PrincipalData::parse(&principal).map_err(|_| {
        ApiError::bad_request(
            ApiErrorCode::InvalidPrincipal,
            format!("Failed to parse `principal`: {principal}"),
        )
    })?;
    let tip = parse_tip(query.tip)?;
    let with_proof = parse_proof(query.proof);
    let chainstate_reads = state.chainstate_reads.clone();

    let account =
        run_blocking(move || chainstate_reads.get_account(principal, tip, with_proof)).await?;
    Ok(Json(AccountResponse::from(account)).into_response())
}

async fn get_nakamoto_block(
    State(state): State<AppState>,
    Path(block_id): Path<String>,
) -> Result<Response, ApiError> {
    let block_id = parse_block_id(&block_id)?;
    let chainstate_reads = state.chainstate_reads.clone();
    let stream_permit = state
        .block_streams
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            ApiError::unavailable(
                ApiErrorCode::BlockStreamQueueFull,
                "RPC block stream limit is full",
            )
        })?;

    let descriptor = run_blocking(move || chainstate_reads.get_nakamoto_block(block_id)).await?;

    Ok(block_stream_response(descriptor, stream_permit))
}

fn parse_block_id(block_id: &str) -> Result<StacksBlockId, ApiError> {
    StacksBlockId::from_hex(block_id).map_err(|_| {
        ApiError::bad_request(
            ApiErrorCode::InvalidBlockId,
            format!("Failed to parse block ID: {block_id}"),
        )
    })
}

fn block_stream_response(
    mut descriptor: NakamotoBlockStreamDescriptor,
    stream_permit: OwnedSemaphorePermit,
) -> Response {
    let stream = stream! {
        let _stream_permit = stream_permit;
        loop {
            let next = tokio::task::spawn_blocking(move || {
                let chunks = descriptor.generate_next_chunks(BLOCK_STREAM_BATCH_BYTES);
                (descriptor, chunks)
            })
            .await
            .map_err(|e| -> StreamError {
                io::Error::other(
                    format!("RPC stream task failed: {e}"),
                ).into()
            });

            let (next_descriptor, next_chunk) = match next {
                Ok(value) => value,
                Err(e) => {
                    yield Err::<Bytes, StreamError>(e);
                    break;
                }
            };

            descriptor = next_descriptor;
            let chunks = match next_chunk {
                Ok(chunks) => chunks,
                Err(e) => {
                    yield Err(io::Error::other(
                        format!("{e:?}"),
                    ).into());
                    break;
                }
            };

            if chunks.is_empty() {
                break;
            }

            for chunk in chunks {
                yield Ok::<Bytes, StreamError>(Bytes::from(chunk));
            }
        }
    };

    let mut response = Body::from_stream(stream).into_response();
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response
}

async fn post_block_proposal(
    _auth: BlockProposalAuth,
    State(state): State<AppState>,
    BlockProposalBody(proposal): BlockProposalBody,
) -> Result<Response, ApiError> {
    let node = state.node.clone();
    let response = run_blocking(move || {
        let (reply, rx) = status_reply_channel();
        node.block_proposal
            .try_send(BlockProposalQuery::Validate { proposal, reply })
            .map_err(map_domain_send_error)?;
        recv_reply(rx)
    })
    .await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(BlockProposalSubmitResponse::from(response)),
    )
        .into_response())
}

fn parse_tip(tip: Option<String>) -> Result<TipRequest, ApiError> {
    let Some(tip) = tip else {
        return Ok(TipRequest::UseLatestAnchoredTip);
    };
    if tip == "latest" {
        return Ok(TipRequest::UseLatestUnconfirmedTip);
    }
    StacksBlockId::from_hex(&tip)
        .map(TipRequest::SpecificTip)
        .map_err(|_| {
            ApiError::bad_request(
                ApiErrorCode::InvalidTip,
                format!("Failed to parse `tip`: {tip}"),
            )
        })
}

fn parse_proof(proof: Option<String>) -> bool {
    proof.as_deref().unwrap_or("1") == "1"
}

#[cfg(test)]
#[path = "routes_tests.rs"]
mod tests;
