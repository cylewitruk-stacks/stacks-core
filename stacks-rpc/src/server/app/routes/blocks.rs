use std::io;

use async_stream::stream;
use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::HeaderValue;
use axum::response::{IntoResponse, Response};
use stacks::net::rpc_services::NakamotoBlockStreamDescriptor;
use tokio::sync::OwnedSemaphorePermit;

use super::super::blocking::run_blocking;
use super::super::AppState;
use super::common::{parse_block_id, parse_tip, ReadQuery};
use crate::error::{ApiError, ApiErrorCode};

type StreamError = Box<dyn std::error::Error + Send + Sync>;

const BLOCK_STREAM_BATCH_BYTES: usize = 256 * 1024;

pub async fn get_nakamoto_block(
    State(state): State<AppState>,
    Path(block_id): Path<String>,
) -> Result<Response, ApiError> {
    let block_id = parse_block_id(&block_id)?;
    let stream_permit = acquire_block_stream(&state)?;
    let reads = state.chainstate_reads.clone();
    let descriptor = run_blocking(move || reads.get_nakamoto_block(block_id)).await?;
    Ok(block_stream_response(descriptor, stream_permit))
}

pub async fn get_nakamoto_block_by_height(
    State(state): State<AppState>,
    Path(height): Path<String>,
    Query(query): Query<ReadQuery>,
) -> Result<Response, ApiError> {
    let height = height.parse::<u64>().map_err(|_| {
        ApiError::bad_request(
            ApiErrorCode::InvalidBlockHeight,
            format!("Failed to parse block height: {height}"),
        )
    })?;
    let tip = parse_tip(query.tip)?;
    let stream_permit = acquire_block_stream(&state)?;
    let reads = state.chainstate_reads.clone();
    let descriptor = run_blocking(move || reads.get_nakamoto_block_by_height(height, tip)).await?;
    Ok(block_stream_response(descriptor, stream_permit))
}

fn acquire_block_stream(state: &AppState) -> Result<OwnedSemaphorePermit, ApiError> {
    state
        .block_streams
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            ApiError::unavailable(
                ApiErrorCode::BlockStreamQueueFull,
                "RPC block stream limit is full",
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
                io::Error::other(format!("RPC stream task failed: {e}")).into()
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
                    yield Err(io::Error::other(format!("{e:?}")).into());
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

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use stacks::net::rpc_bridge::rpc_bridge;

    use super::super::super::fees::FeeEstimationService;
    use super::super::router_with_block_stream_limit;
    use super::super::test_support::*;

    #[test]
    fn rejects_invalid_block_id() {
        let (node, endpoints) = rpc_bridge();
        spawn_test_node(&node, endpoints);
        let addr = free_addr();
        let _server =
            spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
                .unwrap();
        let client = reqwest::blocking::Client::new();

        let response = wait_get(
            &client,
            &format!("http://{addr}/rpc/v1/blocks/not-a-block-id"),
        );
        assert_eq!(response.status().as_u16(), StatusCode::BAD_REQUEST.as_u16());
        let body: serde_json::Value = response.json().unwrap();
        assert_eq!(body["error"]["code"], "invalid_block_id");
    }

    #[test]
    fn rejects_invalid_block_height() {
        let (node, endpoints) = rpc_bridge();
        spawn_test_node(&node, endpoints);
        let addr = free_addr();
        let _server =
            spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
                .unwrap();
        let client = reqwest::blocking::Client::new();

        let response = wait_get(
            &client,
            &format!("http://{addr}/rpc/v1/blocks/by-height/not-a-height"),
        );
        assert_eq!(response.status().as_u16(), StatusCode::BAD_REQUEST.as_u16());
        let body: serde_json::Value = response.json().unwrap();
        assert_eq!(body["error"]["code"], "invalid_block_height");
    }

    #[test]
    fn block_stream_limit_returns_503() {
        let (node, endpoints) = rpc_bridge();
        spawn_test_node(&node, endpoints);
        let addr = free_addr();
        let _server = spawn_test_router(
            addr,
            router_with_block_stream_limit(
                node,
                mock_chainstate_reads(),
                mock_mempool_reads(),
                FeeEstimationService::new(None),
                Some("password".into()),
                0,
            ),
        )
        .unwrap();
        let client = reqwest::blocking::Client::new();

        let block_id = "00".repeat(32);
        let response = wait_get(&client, &format!("http://{addr}/rpc/v1/blocks/{block_id}"));
        assert_eq!(
            response.status().as_u16(),
            StatusCode::SERVICE_UNAVAILABLE.as_u16()
        );
        let body: serde_json::Value = response.json().unwrap();
        assert_eq!(body["error"]["code"], "block_stream_queue_full");
    }
}
