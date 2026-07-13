use serde::Deserialize;
use stacks::burnchains::Txid;
use stacks::net::httpcore::TipRequest;
use stacks_common::types::chainstate::{ConsensusHash, StacksBlockId};
use stacks_common::util::hash::hex_bytes;

use crate::error::{ApiError, ApiErrorCode};

#[derive(Default, Deserialize)]
pub struct ReadQuery {
    pub tip: Option<String>,
    pub proof: Option<String>,
}

#[derive(Default, Deserialize)]
pub struct PageQuery {
    pub cursor: Option<String>,
    pub limit: Option<String>,
}

pub fn parse_tip(tip: Option<String>) -> Result<TipRequest, ApiError> {
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

pub fn parse_proof(proof: Option<&str>) -> Result<bool, ApiError> {
    match proof {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        Some(value) => Err(ApiError::bad_request(
            ApiErrorCode::BadRequest,
            format!("`proof` must be `true` or `false`, got: {value}"),
        )),
    }
}

pub fn parse_limit(value: Option<&str>, default: usize, maximum: usize) -> Result<usize, ApiError> {
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

pub fn parse_block_id(block_id: &str) -> Result<StacksBlockId, ApiError> {
    StacksBlockId::from_hex(block_id).map_err(|_| {
        ApiError::bad_request(
            ApiErrorCode::InvalidBlockId,
            format!("Failed to parse block ID: {block_id}"),
        )
    })
}

pub fn parse_consensus_hash(value: &str) -> Result<ConsensusHash, ApiError> {
    ConsensusHash::from_hex(value).map_err(|_| {
        ApiError::bad_request(
            ApiErrorCode::InvalidConsensusHash,
            format!("Failed to parse consensus hash: {value}"),
        )
    })
}

pub fn parse_reward_cycle(value: &str) -> Result<u64, ApiError> {
    value.parse::<u64>().map_err(|_| {
        ApiError::bad_request(
            ApiErrorCode::InvalidRewardCycle,
            format!("Failed to parse reward cycle: {value}"),
        )
    })
}

pub fn parse_hex_bytes(value: &str, code: ApiErrorCode) -> Result<Vec<u8>, ApiError> {
    hex_bytes(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|_| ApiError::bad_request(code, "Value must be an even-length hexadecimal string"))
}

pub fn parse_txid(txid: &str) -> Result<Txid, ApiError> {
    Txid::from_hex(txid).map_err(|_| {
        ApiError::bad_request(
            ApiErrorCode::InvalidTransactionId,
            format!("Failed to parse transaction ID: {txid}"),
        )
    })
}
