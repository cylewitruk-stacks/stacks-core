use std::io;

use async_stream::stream;
use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use clarity::vm::types::PrincipalData;
use serde::Deserialize;
use stacks::net::httpcore::TipRequest;
use stacks::net::rpc_domains::{
    reply_channel, status_reply_channel, BlockProposalQuery, PeerQuery, RpcDomainChannels,
};
use stacks::net::rpc_services::NakamotoBlockStreamDescriptor;
use stacks_common::types::chainstate::StacksBlockId;

use crate::blocking::{map_domain_send_error, recv_reply, run_blocking};
use crate::chainstate_read::ChainstateReadService;
use crate::error::{ApiError, ApiErrorCode};
use crate::extractors::{BlockProposalAuth, BlockProposalBody};
use crate::models::{AccountResponse, BlockProposalSubmitResponse, InfoResponse};
use crate::state::AppState;

type StreamError = Box<dyn std::error::Error + Send + Sync>;

pub fn router(
    domains: RpcDomainChannels,
    chainstate_reads: ChainstateReadService,
    auth_token: Option<String>,
) -> Router {
    Router::new()
        .route("/rpc/v1/info", get(get_info))
        .route("/rpc/v1/accounts/{principal}", get(get_account))
        .route("/rpc/v1/blocks/{block_id}", get(get_nakamoto_block))
        .route("/rpc/v1/block-proposals", post(post_block_proposal))
        .with_state(AppState {
            domains,
            chainstate_reads,
            auth_token,
        })
}

async fn get_info(State(state): State<AppState>) -> Result<Response, ApiError> {
    let domains = state.domains.clone();
    let info = run_blocking(move || {
        let (reply, rx) = reply_channel();
        domains
            .peer
            .try_send(PeerQuery::GetInfo { reply })
            .map_err(map_domain_send_error)?;
        recv_reply(rx)
    })
    .await?;
    Ok(Json(InfoResponse::from(info)).into_response())
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
    let tip = parse_tip(query.tip);
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

    let descriptor = run_blocking(move || chainstate_reads.get_nakamoto_block(block_id)).await?;

    Ok(block_stream_response(descriptor))
}

fn parse_block_id(block_id: &str) -> Result<StacksBlockId, ApiError> {
    StacksBlockId::from_hex(block_id).map_err(|_| {
        ApiError::bad_request(
            ApiErrorCode::InvalidBlockId,
            format!("Failed to parse block ID: {block_id}"),
        )
    })
}

fn block_stream_response(mut descriptor: NakamotoBlockStreamDescriptor) -> Response {
    let stream = stream! {
        loop {
            let next = tokio::task::spawn_blocking(move || {
                let chunk = descriptor.generate_next_chunk();
                (descriptor, chunk)
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
            let chunk = match next_chunk {
                Ok(chunk) => chunk,
                Err(e) => {
                    yield Err(io::Error::other(
                        format!("{e:?}"),
                    ).into());
                    break;
                }
            };

            if chunk.is_empty() {
                break;
            }

            yield Ok::<Bytes, StreamError>(Bytes::from(chunk));
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
    let domains = state.domains.clone();
    let response = run_blocking(move || {
        let (reply, rx) = status_reply_channel();
        domains
            .block_proposal
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

fn parse_tip(tip: Option<String>) -> TipRequest {
    tip.as_deref()
        .map(TipRequest::from)
        .unwrap_or(TipRequest::UseLatestAnchoredTip)
}

pub fn parse_proof(proof: Option<String>) -> bool {
    proof.as_deref().unwrap_or("1") == "1"
}
