use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use clarity::vm::database::clarity_db::ContractDataVarName;
use clarity::vm::database::StoreType;
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier};
use clarity::vm::{ClarityName, Value};
use serde::Deserialize;
use stacks::net::rpc_services::ReadOnlyCallView;

use super::super::blocking::run_blocking;
use super::super::extractors::ApiJson;
use super::super::AppState;
use super::common::{parse_proof, parse_tip, ReadQuery};
use crate::error::{ApiError, ApiErrorCode};
use crate::models::{
    ClarityMetadataResponse, ClarityValueResponse, ContractInterfaceResponse,
    ContractSourceResponse, ReadOnlyCallRequest, ReadOnlyCallResponse, TraitImplementationResponse,
};

pub async fn get_contract_source(
    State(state): State<AppState>,
    Path((address, contract)): Path<(String, String)>,
    Query(query): Query<ReadQuery>,
) -> Result<Response, ApiError> {
    let contract = parse_contract(&address, &contract)?;
    let tip = parse_tip(query.tip)?;
    let reads = state.chainstate_reads.clone();
    let with_proof = parse_proof(query.proof.as_deref())?;
    let source = run_blocking(move || reads.get_contract_source(contract, tip, with_proof)).await?;
    Ok(Json(ContractSourceResponse::from(source)).into_response())
}

pub async fn get_contract_interface(
    State(state): State<AppState>,
    Path((address, contract)): Path<(String, String)>,
    Query(query): Query<ReadQuery>,
) -> Result<Response, ApiError> {
    let contract = parse_contract(&address, &contract)?;
    let tip = parse_tip(query.tip)?;
    let reads = state.chainstate_reads.clone();
    let interface = run_blocking(move || reads.get_contract_interface(contract, tip)).await?;
    Ok(Json(ContractInterfaceResponse { interface }).into_response())
}

pub async fn get_data_var(
    State(state): State<AppState>,
    Path((address, contract, name)): Path<(String, String, String)>,
    Query(query): Query<ReadQuery>,
) -> Result<Response, ApiError> {
    let contract = parse_contract(&address, &contract)?;
    let name = parse_clarity_name(&name)?;
    let tip = parse_tip(query.tip)?;
    let reads = state.chainstate_reads.clone();
    let with_proof = parse_proof(query.proof.as_deref())?;
    let value = run_blocking(move || reads.get_data_var(contract, name, tip, with_proof)).await?;
    Ok(Json(ClarityValueResponse::from(value)).into_response())
}

pub async fn get_constant(
    State(state): State<AppState>,
    Path((address, contract, name)): Path<(String, String, String)>,
    Query(query): Query<ReadQuery>,
) -> Result<Response, ApiError> {
    let contract = parse_contract(&address, &contract)?;
    let name = parse_clarity_name(&name)?;
    let tip = parse_tip(query.tip)?;
    let reads = state.chainstate_reads.clone();
    let value = run_blocking(move || reads.get_constant(contract, name, tip)).await?;
    Ok(Json(ClarityValueResponse::from(value)).into_response())
}

#[derive(Deserialize)]
pub struct MapEntryRequest {
    key: String,
}

pub async fn get_map_entry(
    State(state): State<AppState>,
    Path((address, contract, name)): Path<(String, String, String)>,
    Query(query): Query<ReadQuery>,
    ApiJson(body): ApiJson<MapEntryRequest>,
) -> Result<Response, ApiError> {
    let contract = parse_contract(&address, &contract)?;
    let name = parse_clarity_name(&name)?;
    let key = Value::try_deserialize_hex_untyped(&body.key).map_err(|_| {
        ApiError::bad_request(
            ApiErrorCode::InvalidClarityValue,
            "Map key must be a serialized Clarity value encoded as hex",
        )
    })?;
    let tip = parse_tip(query.tip)?;
    let reads = state.chainstate_reads.clone();
    let with_proof = parse_proof(query.proof.as_deref())?;
    let value =
        run_blocking(move || reads.get_map_entry(contract, name, key, tip, with_proof)).await?;
    Ok(Json(ClarityValueResponse::from(value)).into_response())
}

pub async fn get_trait_implementation(
    State(state): State<AppState>,
    Path((address, contract, trait_address, trait_contract, trait_name)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
    Query(query): Query<ReadQuery>,
) -> Result<Response, ApiError> {
    let contract = parse_contract(&address, &contract)?;
    let trait_contract = parse_contract(&trait_address, &trait_contract)?;
    let trait_name = parse_clarity_name(&trait_name)?;
    let tip = parse_tip(query.tip)?;
    let reads = state.chainstate_reads.clone();
    let implemented =
        run_blocking(move || reads.is_trait_implemented(contract, trait_contract, trait_name, tip))
            .await?;
    Ok(Json(TraitImplementationResponse { implemented }).into_response())
}

pub async fn get_clarity_metadata(
    State(state): State<AppState>,
    Path((address, contract, key)): Path<(String, String, String)>,
    Query(query): Query<ReadQuery>,
) -> Result<Response, ApiError> {
    let contract = parse_contract(&address, &contract)?;
    validate_metadata_key(&key)?;
    let tip = parse_tip(query.tip)?;
    let reads = state.chainstate_reads.clone();
    let value = run_blocking(move || reads.get_clarity_metadata(contract, key, tip)).await?;
    Ok(Json(ClarityMetadataResponse { value }).into_response())
}

pub async fn call_read_only(
    State(state): State<AppState>,
    Path((address, contract, function)): Path<(String, String, String)>,
    Query(query): Query<ReadQuery>,
    ApiJson(body): ApiJson<ReadOnlyCallRequest>,
) -> Result<Response, ApiError> {
    let contract = parse_contract(&address, &contract)?;
    let function = parse_clarity_name(&function)?;
    let sender = PrincipalData::parse(&body.sender).map_err(|_| {
        ApiError::bad_request(
            ApiErrorCode::InvalidPrincipal,
            format!("Failed to parse sender principal: {}", body.sender),
        )
    })?;
    let sponsor = body
        .sponsor
        .map(|sponsor| {
            PrincipalData::parse(&sponsor).map_err(|_| {
                ApiError::bad_request(
                    ApiErrorCode::InvalidPrincipal,
                    format!("Failed to parse sponsor principal: {sponsor}"),
                )
            })
        })
        .transpose()?;
    let argument_bytes = body.arguments.iter().map(String::len).sum::<usize>();
    if argument_bytes > state.chainstate_reads.maximum_call_argument_bytes() as usize {
        return Err(ApiError::bad_request(
            ApiErrorCode::CallArgumentsTooLarge,
            "Serialized Clarity arguments exceed the configured limit",
        ));
    }
    let arguments = body
        .arguments
        .into_iter()
        .map(|argument| {
            Value::try_deserialize_hex_untyped(&argument).map_err(|_| {
                ApiError::bad_request(
                    ApiErrorCode::InvalidClarityValue,
                    format!("Failed to deserialize Clarity argument: {argument}"),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let tip = parse_tip(query.tip)?;
    let reads = state.chainstate_reads.clone();
    let result = run_blocking(move || {
        reads.call_read_only(contract, function, sender, sponsor, arguments, tip)
    })
    .await?;
    match result {
        ReadOnlyCallView::Success(result) => {
            Ok(Json(ReadOnlyCallResponse { result }).into_response())
        }
        ReadOnlyCallView::NotReadOnly => Err(ApiError::status(
            StatusCode::UNPROCESSABLE_ENTITY,
            ApiErrorCode::ContractCallNotReadOnly,
            "Contract call attempted to write state",
        )),
        ReadOnlyCallView::ExecutionTimedOut => Err(ApiError::unavailable(
            ApiErrorCode::RequestTimeout,
            "Contract call exceeded the execution deadline",
        )),
        ReadOnlyCallView::Failed(message) => Err(ApiError::status(
            StatusCode::UNPROCESSABLE_ENTITY,
            ApiErrorCode::ContractCallFailed,
            message,
        )),
    }
}

fn parse_contract(address: &str, contract: &str) -> Result<QualifiedContractIdentifier, ApiError> {
    let identifier = format!("{address}.{contract}");
    QualifiedContractIdentifier::parse(&identifier).map_err(|_| {
        ApiError::bad_request(
            ApiErrorCode::InvalidContract,
            format!("Failed to parse contract identifier: {identifier}"),
        )
    })
}

fn parse_clarity_name(name: &str) -> Result<ClarityName, ApiError> {
    ClarityName::try_from(name.to_string()).map_err(|_| {
        ApiError::bad_request(
            ApiErrorCode::InvalidClarityName,
            format!("Failed to parse Clarity name: {name}"),
        )
    })
}

fn validate_metadata_key(key: &str) -> Result<(), ApiError> {
    if key == "analysis" {
        return Ok(());
    }
    let Some((store_type, name)) = key
        .strip_prefix("vm-metadata::")
        .and_then(|key| key.split_once("::"))
    else {
        return Err(invalid_metadata_key(key));
    };
    if name.contains("::") {
        return Err(invalid_metadata_key(key));
    }
    let store_type = StoreType::try_from(store_type).map_err(|_| invalid_metadata_key(key))?;
    match store_type {
        StoreType::DataMapMeta
        | StoreType::VariableMeta
        | StoreType::FungibleTokenMeta
        | StoreType::NonFungibleTokenMeta => {
            ClarityName::try_from(name.to_string()).map_err(|_| invalid_metadata_key(key))?;
        }
        StoreType::Contract => {
            ContractDataVarName::try_from(name).map_err(|_| invalid_metadata_key(key))?;
        }
        _ => return Err(invalid_metadata_key(key)),
    }
    Ok(())
}

fn invalid_metadata_key(key: &str) -> ApiError {
    ApiError::bad_request(
        ApiErrorCode::InvalidMetadataKey,
        format!("Invalid Clarity metadata key: {key}"),
    )
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use stacks::net::rpc_bridge::rpc_bridge;

    use super::super::test_support::*;

    fn contract_url(addr: std::net::SocketAddr) -> String {
        format!("http://{addr}/rpc/v1/contracts/ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R/sample")
    }

    #[test]
    fn serves_contract_state_resources_through_read_pool() {
        let (node, endpoints) = rpc_bridge();
        spawn_test_node(&node, endpoints);
        let addr = free_addr();
        let _server =
            spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
                .unwrap();
        let client = reqwest::blocking::Client::new();
        let base = contract_url(addr);

        let source = wait_get(&client, &format!("{base}/source?proof=true"));
        assert_eq!(source.status().as_u16(), StatusCode::OK.as_u16());
        let source: serde_json::Value = source.json().unwrap();
        assert_eq!(source["publish_height"], 123);
        assert_eq!(source["proof"], "0xabcd");

        let data_var = wait_get(&client, &format!("{base}/data-vars/answer"));
        assert_eq!(data_var.status().as_u16(), StatusCode::OK.as_u16());
        let data_var: serde_json::Value = data_var.json().unwrap();
        assert_eq!(data_var["value"], "0x010000000000000000000000000000002a");
        assert!(data_var.get("proof").is_none());

        assert_eq!(
            wait_get(&client, &format!("{base}/constants/answer"))
                .status()
                .as_u16(),
            StatusCode::OK.as_u16()
        );

        let metadata = wait_get(&client, &format!("{base}/metadata/analysis"));
        assert_eq!(metadata.status().as_u16(), StatusCode::OK.as_u16());
        let metadata: serde_json::Value = metadata.json().unwrap();
        assert_eq!(metadata["value"], "metadata:analysis");

        let map = client
            .post(format!("{base}/maps/entries/entries?proof=true"))
            .json(&serde_json::json!({ "key": "0x03" }))
            .send()
            .unwrap();
        assert_eq!(map.status().as_u16(), StatusCode::OK.as_u16());
        let map: serde_json::Value = map.json().unwrap();
        assert_eq!(map["proof"], "0xabcd");

        let trait_response = wait_get(
            &client,
            &format!("{base}/traits/ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R/traits/sample-trait"),
        );
        assert_eq!(trait_response.status().as_u16(), StatusCode::OK.as_u16());
        let trait_response: serde_json::Value = trait_response.json().unwrap();
        assert_eq!(trait_response["implemented"], true);

        let call = client
            .post(format!("{base}/functions/read-answer/call-read"))
            .json(&serde_json::json!({
                "sender": "ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R",
                "arguments": ["0x03"]
            }))
            .send()
            .unwrap();
        assert_eq!(call.status().as_u16(), StatusCode::OK.as_u16());
        let call: serde_json::Value = call.json().unwrap();
        assert_eq!(call["result"], "0x0703");
    }

    #[test]
    fn rejects_invalid_identifiers_and_values() {
        let (node, endpoints) = rpc_bridge();
        spawn_test_node(&node, endpoints);
        let addr = free_addr();
        let _server =
            spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
                .unwrap();
        let client = reqwest::blocking::Client::new();

        let bad_contract = wait_get(
            &client,
            &format!("http://{addr}/rpc/v1/contracts/not-an-address/sample/source"),
        );
        assert_eq!(
            bad_contract.status().as_u16(),
            StatusCode::BAD_REQUEST.as_u16()
        );
        let bad_contract: serde_json::Value = bad_contract.json().unwrap();
        assert_eq!(bad_contract["error"]["code"], "invalid_contract");

        let bad_key = client
            .post(format!("{}/maps/entries/entries", contract_url(addr)))
            .json(&serde_json::json!({ "key": "not-hex" }))
            .send()
            .unwrap();
        assert_eq!(bad_key.status().as_u16(), StatusCode::BAD_REQUEST.as_u16());
        let bad_key: serde_json::Value = bad_key.json().unwrap();
        assert_eq!(bad_key["error"]["code"], "invalid_clarity_value");

        let bad_metadata = wait_get(
            &client,
            &format!("{}/metadata/arbitrary", contract_url(addr)),
        );
        assert_eq!(
            bad_metadata.status().as_u16(),
            StatusCode::BAD_REQUEST.as_u16()
        );
        let bad_metadata: serde_json::Value = bad_metadata.json().unwrap();
        assert_eq!(bad_metadata["error"]["code"], "invalid_metadata_key");
    }

    #[test]
    fn malformed_json_uses_the_api_error_envelope() {
        let (node, endpoints) = rpc_bridge();
        spawn_test_node(&node, endpoints);
        let addr = free_addr();
        let _server =
            spawn_axum_rpc_server(addr, node, mock_chainstate_reads(), Some("password".into()))
                .unwrap();
        let client = reqwest::blocking::Client::new();
        let base = contract_url(addr);

        for path in ["maps/entries/entries", "functions/read-answer/call-read"] {
            let response = client
                .post(format!("{base}/{path}"))
                .header("content-type", "application/json")
                .body("{")
                .send()
                .unwrap();
            assert_eq!(response.status().as_u16(), StatusCode::BAD_REQUEST.as_u16());
            let body: serde_json::Value = response.json().unwrap();
            assert_eq!(body["error"]["code"], "invalid_json");
        }

        let response = client
            .post(format!("{base}/maps/entries/entries"))
            .body(r#"{"key":"0x03"}"#)
            .send()
            .unwrap();
        assert_eq!(
            response.status().as_u16(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE.as_u16()
        );
        let body: serde_json::Value = response.json().unwrap();
        assert_eq!(body["error"]["code"], "invalid_content_type");
    }
}
