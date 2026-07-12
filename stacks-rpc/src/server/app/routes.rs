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
use clarity::util::secp256k1::Secp256k1PublicKey;
use clarity::vm::database::clarity_db::ContractDataVarName;
use clarity::vm::database::StoreType;
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier};
use clarity::vm::{ClarityName, Value};
use serde::Deserialize;
use stacks::burnchains::Txid;
use stacks::net::httpcore::TipRequest;
use stacks::net::rpc_bridge::{status_reply_channel, BlockProposalQuery, RpcNodeHandle};
use stacks::net::rpc_services::{
    NakamotoBlockStreamDescriptor, ReadOnlyCallView, SortitionQuery, TenureSelector,
};
use stacks_common::codec::MAX_PAYLOAD_LEN;
use stacks_common::types::chainstate::{BurnchainHeaderHash, ConsensusHash, StacksBlockId};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower::limit::GlobalConcurrencyLimitLayer;
use tower::ServiceBuilder;

use super::blocking::{map_domain_send_error, recv_reply, run_blocking};
use super::chainstate::ChainstateReadService;
use super::extractors::{ApiJson, BlockProposalAuth, BlockProposalBody};
use super::AppState;
use crate::error::{ApiError, ApiErrorCode};
use crate::models::{
    AccountResponse, BlockProposalSubmitResponse, ClarityMetadataResponse, ClarityValueResponse,
    ConfirmedTransactionResponse, ContractInterfaceResponse, ContractSourceResponse,
    HeadersResponse, InfoResponse, ReadOnlyCallRequest, ReadOnlyCallResponse,
    SignerActivityResponse, SortitionsResponse, StackerSetResponse, TenureBlocksPageResponse,
    TenureForkInfoResponse, TenureTipResponse, TraitImplementationResponse,
};

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
        .route(
            "/rpc/v1/contracts/{address}/{contract}/source",
            get(get_contract_source),
        )
        .route(
            "/rpc/v1/contracts/{address}/{contract}/interface",
            get(get_contract_interface),
        )
        .route(
            "/rpc/v1/contracts/{address}/{contract}/data-vars/{name}",
            get(get_data_var),
        )
        .route(
            "/rpc/v1/contracts/{address}/{contract}/constants/{name}",
            get(get_constant),
        )
        .route(
            "/rpc/v1/contracts/{address}/{contract}/maps/{name}/entries",
            post(get_map_entry),
        )
        .route(
            "/rpc/v1/contracts/{address}/{contract}/metadata/{key}",
            get(get_clarity_metadata),
        )
        .route(
            "/rpc/v1/contracts/{address}/{contract}/functions/{function}/call-read",
            post(call_read_only),
        )
        .route(
            "/rpc/v1/contracts/{address}/{contract}/traits/{trait_address}/{trait_contract}/{trait_name}",
            get(get_trait_implementation),
        )
        .route("/rpc/v1/blocks/{block_id}", get(get_nakamoto_block))
        .route(
            "/rpc/v1/blocks/by-height/{height}",
            get(get_nakamoto_block_by_height),
        )
        .route(
            "/rpc/v1/transactions/{txid}",
            get(get_confirmed_transaction),
        )
        .route(
            "/rpc/v1/signers/{public_key}/cycles/{reward_cycle}",
            get(get_signer_activity),
        )
        .route(
            "/rpc/v1/tenures/{consensus_hash}/tip",
            get(get_tenure_tip),
        )
        .route("/rpc/v1/pox", get(get_pox_info))
        .route(
            "/rpc/v1/stacking/reward-cycles/{reward_cycle}/stackers",
            get(get_stacker_set),
        )
        .route("/rpc/v1/sortitions/latest", get(get_latest_sortition))
        .route(
            "/rpc/v1/sortitions/latest-and-last",
            get(get_latest_and_last_sortitions),
        )
        .route(
            "/rpc/v1/sortitions/by-consensus/{consensus_hash}",
            get(get_sortition_by_consensus),
        )
        .route(
            "/rpc/v1/sortitions/by-burn-block/{burn_block_hash}",
            get(get_sortition_by_burn_block),
        )
        .route(
            "/rpc/v1/sortitions/by-burn-height/{burn_block_height}",
            get(get_sortition_by_burn_height),
        )
        .route("/rpc/v1/headers", get(get_headers))
        .route(
            "/rpc/v1/tenures/by-consensus/{consensus_hash}/blocks",
            get(get_tenure_blocks_by_consensus),
        )
        .route(
            "/rpc/v1/tenures/by-burn-block/{burn_block_hash}/blocks",
            get(get_tenure_blocks_by_burn_block),
        )
        .route(
            "/rpc/v1/tenures/by-burn-height/{burn_block_height}/blocks",
            get(get_tenure_blocks_by_burn_height),
        )
        .route(
            "/rpc/v1/tenures/forks/{start}/{end}",
            get(get_tenure_fork_info),
        )
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

#[derive(Default, Deserialize)]
struct ReadQuery {
    tip: Option<String>,
    proof: Option<String>,
}

async fn get_account(
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
    let chainstate_reads = state.chainstate_reads.clone();

    let account =
        run_blocking(move || chainstate_reads.get_account(principal, tip, with_proof)).await?;
    Ok(Json(AccountResponse::from(account)).into_response())
}

async fn get_contract_source(
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

async fn get_contract_interface(
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

async fn get_data_var(
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

async fn get_constant(
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
struct MapEntryRequest {
    key: String,
}

async fn get_map_entry(
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

async fn get_trait_implementation(
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

async fn get_clarity_metadata(
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

async fn call_read_only(
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

async fn get_nakamoto_block(
    State(state): State<AppState>,
    Path(block_id): Path<String>,
) -> Result<Response, ApiError> {
    let block_id = parse_block_id(&block_id)?;
    let chainstate_reads = state.chainstate_reads.clone();
    let stream_permit = acquire_block_stream(&state)?;

    let descriptor = run_blocking(move || chainstate_reads.get_nakamoto_block(block_id)).await?;

    Ok(block_stream_response(descriptor, stream_permit))
}

async fn get_nakamoto_block_by_height(
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

async fn get_confirmed_transaction(
    State(state): State<AppState>,
    Path(txid): Path<String>,
    Query(query): Query<ReadQuery>,
) -> Result<Response, ApiError> {
    let txid = Txid::from_hex(&txid).map_err(|_| {
        ApiError::bad_request(
            ApiErrorCode::InvalidTransactionId,
            format!("Failed to parse transaction ID: {txid}"),
        )
    })?;
    let tip = parse_tip(query.tip)?;
    let reads = state.chainstate_reads.clone();
    let transaction = run_blocking(move || reads.get_confirmed_transaction(txid, tip)).await?;
    Ok(Json(ConfirmedTransactionResponse::from(transaction)).into_response())
}

async fn get_signer_activity(
    State(state): State<AppState>,
    Path((public_key, reward_cycle)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let public_key = Secp256k1PublicKey::from_hex(&public_key).map_err(|_| {
        ApiError::bad_request(
            ApiErrorCode::InvalidSignerPublicKey,
            format!("Failed to parse signer public key: {public_key}"),
        )
    })?;
    let reward_cycle = reward_cycle.parse::<u64>().map_err(|_| {
        ApiError::bad_request(
            ApiErrorCode::InvalidRewardCycle,
            format!("Failed to parse reward cycle: {reward_cycle}"),
        )
    })?;
    let reads = state.chainstate_reads.clone();
    let blocks_signed =
        run_blocking(move || reads.get_signer_block_count(public_key, reward_cycle)).await?;
    Ok(Json(SignerActivityResponse { blocks_signed }).into_response())
}

async fn get_tenure_tip(
    State(state): State<AppState>,
    Path(consensus_hash): Path<String>,
) -> Result<Response, ApiError> {
    let consensus_hash = ConsensusHash::from_hex(&consensus_hash).map_err(|_| {
        ApiError::bad_request(
            ApiErrorCode::InvalidConsensusHash,
            format!("Failed to parse consensus hash: {consensus_hash}"),
        )
    })?;
    let reads = state.chainstate_reads.clone();
    let tip = run_blocking(move || reads.get_tenure_tip(consensus_hash)).await?;
    Ok(Json(TenureTipResponse::from(tip)).into_response())
}

async fn get_pox_info(
    State(state): State<AppState>,
    Query(query): Query<ReadQuery>,
) -> Result<Response, ApiError> {
    let tip = parse_tip(query.tip)?;
    let reads = state.chainstate_reads.clone();
    let pox = run_blocking(move || reads.get_pox_info(tip)).await?;
    Ok(Json(pox).into_response())
}

async fn get_stacker_set(
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

async fn get_latest_sortition(State(state): State<AppState>) -> Result<Response, ApiError> {
    get_sortitions(state, SortitionQuery::Latest).await
}

async fn get_latest_and_last_sortitions(
    State(state): State<AppState>,
) -> Result<Response, ApiError> {
    get_sortitions(state, SortitionQuery::LatestAndLast).await
}

async fn get_sortition_by_consensus(
    State(state): State<AppState>,
    Path(consensus_hash): Path<String>,
) -> Result<Response, ApiError> {
    let consensus_hash = parse_consensus_hash(&consensus_hash)?;
    get_sortitions(state, SortitionQuery::ConsensusHash(consensus_hash)).await
}

async fn get_sortition_by_burn_block(
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

async fn get_sortition_by_burn_height(
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

fn parse_reward_cycle(value: &str) -> Result<u64, ApiError> {
    value.parse::<u64>().map_err(|_| {
        ApiError::bad_request(
            ApiErrorCode::InvalidRewardCycle,
            format!("Failed to parse reward cycle: {value}"),
        )
    })
}

fn parse_consensus_hash(value: &str) -> Result<ConsensusHash, ApiError> {
    ConsensusHash::from_hex(value).map_err(|_| {
        ApiError::bad_request(
            ApiErrorCode::InvalidConsensusHash,
            format!("Failed to parse consensus hash: {value}"),
        )
    })
}

#[derive(Default, Deserialize)]
struct HeaderQuery {
    tip: Option<String>,
    limit: Option<String>,
}

async fn get_headers(
    State(state): State<AppState>,
    Query(query): Query<HeaderQuery>,
) -> Result<Response, ApiError> {
    let tip = parse_tip(query.tip)?;
    let limit = parse_limit(query.limit.as_deref(), 100, stacks::net::MAX_HEADERS)? as u32;
    let reads = state.chainstate_reads.clone();
    let headers = run_blocking(move || reads.get_headers(limit, tip)).await?;
    Ok(Json(HeadersResponse { headers }).into_response())
}

#[derive(Default, Deserialize)]
struct PageQuery {
    cursor: Option<String>,
    limit: Option<String>,
}

async fn get_tenure_blocks_by_consensus(
    State(state): State<AppState>,
    Path(consensus_hash): Path<String>,
    Query(query): Query<PageQuery>,
) -> Result<Response, ApiError> {
    let consensus_hash = parse_consensus_hash(&consensus_hash)?;
    get_tenure_blocks_page(state, TenureSelector::ConsensusHash(consensus_hash), query).await
}

async fn get_tenure_blocks_by_burn_block(
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

async fn get_tenure_blocks_by_burn_height(
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

async fn get_tenure_fork_info(
    State(state): State<AppState>,
    Path((start, end)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let start = parse_consensus_hash(&start)?;
    let end = parse_consensus_hash(&end)?;
    let reads = state.chainstate_reads.clone();
    let tenures = run_blocking(move || reads.get_tenure_fork_info(start, end)).await?;
    Ok(Json(TenureForkInfoResponse { tenures }).into_response())
}

fn parse_limit(value: Option<&str>, default: usize, maximum: usize) -> Result<usize, ApiError> {
    let limit = value
        .map(str::parse::<usize>)
        .transpose()
        .map_err(|_| {
            ApiError::bad_request(ApiErrorCode::InvalidPagination, "Invalid pagination limit")
        })?
        .unwrap_or(default);
    if limit == 0 || limit > maximum {
        return Err(ApiError::bad_request(
            ApiErrorCode::InvalidPagination,
            format!("Pagination limit must be between 1 and {maximum}"),
        ));
    }
    Ok(limit)
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

fn parse_proof(proof: Option<&str>) -> Result<bool, ApiError> {
    match proof {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        Some(value) => Err(ApiError::bad_request(
            ApiErrorCode::BadRequest,
            format!("`proof` must be `true` or `false`, got: {value}"),
        )),
    }
}

#[cfg(test)]
#[path = "routes_tests.rs"]
mod tests;
