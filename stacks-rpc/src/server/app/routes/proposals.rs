use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use stacks::net::rpc_bridge::{status_reply_channel, BlockProposalQuery};

use super::super::blocking::{map_domain_send_error, recv_reply, run_blocking};
use super::super::extractors::{BlockProposalAuth, BlockProposalBody};
use super::super::AppState;
use crate::error::ApiError;
use crate::models::BlockProposalSubmitResponse;

pub async fn post_block_proposal(
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

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use stacks::net::rpc_bridge::rpc_bridge;
    use stacks::net::rpc_services::BlockProposalError;
    use stacks_common::codec::MAX_PAYLOAD_LEN;

    use super::super::test_support::*;

    #[test]
    fn rejects_block_proposal_without_auth() {
        let (node, endpoints) = rpc_bridge();
        spawn_test_node(&node, endpoints);
        let addr = free_addr();
        let _server =
            spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
                .unwrap();
        let client = reqwest::blocking::Client::new();

        let response = client
            .post(format!("http://{addr}/rpc/v1/block-proposals"))
            .json(&sample_block_proposal())
            .send()
            .unwrap();
        assert_eq!(
            response.status().as_u16(),
            StatusCode::UNAUTHORIZED.as_u16()
        );
    }

    #[test]
    fn rejects_block_proposal_without_bearer_auth_scheme() {
        let (node, endpoints) = rpc_bridge();
        spawn_test_node(&node, endpoints);
        let addr = free_addr();
        let _server =
            spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
                .unwrap();
        let client = reqwest::blocking::Client::new();

        let response = client
            .post(format!("http://{addr}/rpc/v1/block-proposals"))
            .header("authorization", "password")
            .json(&sample_block_proposal())
            .send()
            .unwrap();
        assert_eq!(
            response.status().as_u16(),
            StatusCode::UNAUTHORIZED.as_u16()
        );
    }

    #[test]
    fn rejects_oversized_block_proposal() {
        let (node, endpoints) = rpc_bridge();
        spawn_test_node(&node, endpoints);
        let addr = free_addr();
        let _server =
            spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
                .unwrap();
        let client = reqwest::blocking::Client::new();

        let response = client
            .post(format!("http://{addr}/rpc/v1/block-proposals"))
            .header("authorization", "Bearer password")
            .header("content-type", "application/json")
            .body(vec![0u8; MAX_PAYLOAD_LEN as usize + 1])
            .send()
            .unwrap();
        assert_eq!(response.status().as_u16(), StatusCode::BAD_REQUEST.as_u16());
        let body: serde_json::Value = response.json().unwrap();
        assert_eq!(body["error"]["code"], "body_too_large");
        assert_eq!(
            body["error"]["message"],
            format!("Block proposal body exceeds {MAX_PAYLOAD_LEN} bytes")
        );
    }

    #[test]
    fn serves_block_proposal_through_rpc_bridge() {
        let (node, endpoints) = rpc_bridge();
        spawn_test_node(&node, endpoints);
        let addr = free_addr();
        let _server =
            spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
                .unwrap();
        let client = reqwest::blocking::Client::new();

        let response = client
            .post(format!("http://{addr}/rpc/v1/block-proposals"))
            .header("authorization", "Bearer password")
            .json(&sample_block_proposal())
            .send()
            .unwrap();
        assert_eq!(response.status().as_u16(), StatusCode::ACCEPTED.as_u16());
        let body: serde_json::Value = response.json().unwrap();
        assert_eq!(body["status"], "accepted");
        assert_eq!(
            body["message"],
            "Block proposal is processing, result will be returned via the event observer"
        );
    }

    #[test]
    fn block_proposal_rejection_uses_new_api_error_framing() {
        let (node, endpoints) = rpc_bridge();
        spawn_block_proposal_rejection_endpoint(endpoints, BlockProposalError::AlreadyValidating);
        let addr = free_addr();
        let _server =
            spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
                .unwrap();
        let client = reqwest::blocking::Client::new();

        let response = client
            .post(format!("http://{addr}/rpc/v1/block-proposals"))
            .header("authorization", "Bearer password")
            .json(&sample_block_proposal())
            .send()
            .unwrap();
        assert_eq!(
            response.status().as_u16(),
            StatusCode::TOO_MANY_REQUESTS.as_u16()
        );
        let body: serde_json::Value = response.json().unwrap();
        assert_eq!(body["error"]["code"], "block_proposal_rejected");
        assert_eq!(
            body["error"]["message"],
            "Proposal currently being evaluated"
        );
    }
}
