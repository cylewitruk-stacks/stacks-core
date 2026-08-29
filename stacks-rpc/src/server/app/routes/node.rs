use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use clarity::vm::types::PrincipalData;

use super::super::blocking::run_blocking;
use super::super::AppState;
use super::common::{parse_proof, parse_tip, ReadQuery};
use crate::error::{ApiError, ApiErrorCode};
use crate::models::{AccountResponse, CurrentTenureResponse, HealthResponse, InfoResponse};

pub async fn get_info(State(state): State<AppState>) -> Result<Response, ApiError> {
    let snapshot = state.node.snapshot.load().ok_or_else(|| {
        ApiError::unavailable(
            ApiErrorCode::NodeSnapshotUnavailable,
            "RPC node snapshot is not ready",
        )
    })?;
    Ok(Json(InfoResponse::from((*snapshot).clone())).into_response())
}

pub async fn get_health(State(state): State<AppState>) -> Result<Response, ApiError> {
    let snapshot = state.node.snapshot.load().ok_or_else(|| {
        ApiError::unavailable(
            ApiErrorCode::NodeSnapshotUnavailable,
            "RPC node snapshot is not ready",
        )
    })?;
    Ok(Json(HealthResponse::from_snapshot(
        snapshot.observed_at,
        snapshot.health.clone(),
    ))
    .into_response())
}

pub async fn get_current_tenure(State(state): State<AppState>) -> Result<Response, ApiError> {
    let snapshot = state.node.snapshot.load().ok_or_else(|| {
        ApiError::unavailable(
            ApiErrorCode::NodeSnapshotUnavailable,
            "RPC node snapshot is not ready",
        )
    })?;
    let tenure = snapshot.current_tenure.clone().ok_or_else(|| {
        ApiError::unavailable(
            ApiErrorCode::CurrentTenureUnavailable,
            "Current tenure is not available yet",
        )
    })?;
    Ok(Json(CurrentTenureResponse::from_snapshot(
        snapshot.observed_at,
        tenure,
    ))
    .into_response())
}

pub async fn get_account(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    Query(query): Query<ReadQuery>,
) -> Result<Response, ApiError> {
    let principal = PrincipalData::parse(&principal).map_err(|_| {
        ApiError::bad_request(
            ApiErrorCode::InvalidPrincipal,
            format!("Failed to parse `principal`: {principal}"),
        )
    })?;
    let tip = parse_tip(query.tip)?;
    let with_proof = parse_proof(query.proof.as_deref())?;
    let reads = state.chainstate_reads.clone();
    let account = run_blocking(move || reads.get_account(principal, tip, with_proof)).await?;
    Ok(Json(AccountResponse::from(account)).into_response())
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use clarity::vm::types::PrincipalData;
    use stacks::net::httpcore::TipRequest;
    use stacks::net::rpc_bridge::rpc_bridge;

    use super::super::test_support::*;

    #[test]
    fn rejects_bad_principal() {
        assert!(PrincipalData::parse("not-a-principal").is_err());
    }

    #[test]
    fn serves_info_and_account_state() {
        let (node, endpoints) = rpc_bridge();
        spawn_test_node(&node, endpoints);
        let addr = free_addr();
        let _server =
            spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
                .unwrap();
        let client = reqwest::blocking::Client::new();

        let info = wait_get(&client, &format!("http://{addr}/rpc/v1/info"));
        assert_eq!(info.status().as_u16(), StatusCode::OK.as_u16());
        let info: serde_json::Value = info.json().unwrap();
        assert_eq!(info["server_version"], "stacks-node-test");
        assert_eq!(info["stacks_tip"]["height"], 7);
        assert_eq!(info["burn_block"]["height"], 2);

        let account = wait_get(
            &client,
            &format!(
                "http://{addr}/rpc/v1/accounts/ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R?proof=false"
            ),
        );
        assert_eq!(account.status().as_u16(), StatusCode::OK.as_u16());
        let account: serde_json::Value = account.json().unwrap();
        assert_eq!(account["balance"], "42");
        assert_eq!(account["nonce"], 3);
        assert!(account.get("proofs").is_none());
    }

    #[test]
    fn info_without_node_snapshot_returns_503() {
        let (node, _endpoints) = rpc_bridge();
        let addr = free_addr();
        let _server =
            spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
                .unwrap();
        let client = reqwest::blocking::Client::new();

        let response = wait_get(&client, &format!("http://{addr}/rpc/v1/info"));
        assert_eq!(
            response.status().as_u16(),
            StatusCode::SERVICE_UNAVAILABLE.as_u16()
        );
        let body: serde_json::Value = response.json().unwrap();
        assert_eq!(body["error"]["code"], "node_snapshot_unavailable");
    }

    #[test]
    fn serves_health_and_current_tenure_from_one_snapshot() {
        let (node, endpoints) = rpc_bridge();
        spawn_test_node(&node, endpoints);
        let addr = free_addr();
        let _server =
            spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
                .unwrap();
        let client = reqwest::blocking::Client::new();

        let health = wait_get(&client, &format!("http://{addr}/rpc/v1/health"));
        assert_eq!(health.status().as_u16(), StatusCode::OK.as_u16());
        let health: serde_json::Value = health.json().unwrap();
        assert_eq!(health["observed_at"], 1234);
        assert_eq!(health["difference_from_max_peer"], 2);
        assert_eq!(health["max_peer_address"], "127.0.0.1:20444");

        let tenure = wait_get(&client, &format!("http://{addr}/rpc/v1/tenures/current"));
        assert_eq!(tenure.status().as_u16(), StatusCode::OK.as_u16());
        let tenure: serde_json::Value = tenure.json().unwrap();
        assert_eq!(tenure["observed_at"], 1234);
        assert_eq!(tenure["tip_height"], 6);
        assert_eq!(tenure["reward_cycle"], 4);
    }

    #[test]
    fn account_latest_tip_uses_chainstate_read_service() {
        let (node, endpoints) = rpc_bridge();
        spawn_test_node(&node, endpoints);
        let addr = free_addr();
        let _server = spawn_axum_rpc_server(
            addr,
            node,
            mock_chainstate_reads_with_tip(Some(TipRequest::UseLatestUnconfirmedTip)),
            Some("password".into()),
        )
        .unwrap();
        let client = reqwest::blocking::Client::new();

        let response = wait_get(
            &client,
            &format!(
                "http://{addr}/rpc/v1/accounts/ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R?tip=latest"
            ),
        );
        assert_eq!(response.status().as_u16(), StatusCode::OK.as_u16());
        let account: serde_json::Value = response.json().unwrap();
        assert_eq!(account["balance"], "42");
    }

    #[test]
    fn account_invalid_tip_returns_400() {
        let (node, endpoints) = rpc_bridge();
        spawn_test_node(&node, endpoints);
        let addr = free_addr();
        let _server =
            spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
                .unwrap();
        let client = reqwest::blocking::Client::new();

        let response = wait_get(
            &client,
            &format!(
                "http://{addr}/rpc/v1/accounts/ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R?tip=not-a-tip"
            ),
        );
        assert_eq!(response.status().as_u16(), StatusCode::BAD_REQUEST.as_u16());
        let body: serde_json::Value = response.json().unwrap();
        assert_eq!(body["error"]["code"], "invalid_tip");
    }

    #[test]
    fn account_invalid_proof_returns_400() {
        let (node, endpoints) = rpc_bridge();
        spawn_test_node(&node, endpoints);
        let addr = free_addr();
        let _server =
            spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
                .unwrap();
        let client = reqwest::blocking::Client::new();

        let response = wait_get(
            &client,
            &format!(
                "http://{addr}/rpc/v1/accounts/ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R?proof=1"
            ),
        );
        assert_eq!(response.status().as_u16(), StatusCode::BAD_REQUEST.as_u16());
        let body: serde_json::Value = response.json().unwrap();
        assert_eq!(body["error"]["code"], "bad_request");
    }

    #[test]
    fn saturated_chainstate_read_queue_returns_503() {
        let (node, endpoints) = rpc_bridge();
        spawn_test_node(&node, endpoints);
        let addr = free_addr();
        let _server = spawn_axum_rpc_server(
            addr,
            node,
            saturated_chainstate_reads(),
            Some("password".into()),
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
        assert_eq!(body["error"]["code"], "read_queue_full");
    }
}
