use axum::body::{to_bytes, Bytes};
use axum::extract::{FromRequest, FromRequestParts, Request};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use stacks::net::api::postblock_proposal::NakamotoBlockProposal;
use stacks_common::codec::MAX_PAYLOAD_LEN;

use crate::error::{ApiError, ApiErrorCode};
use crate::state::AppState;

pub struct BlockProposalAuth;

impl FromRequestParts<AppState> for BlockProposalAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        require_block_proposal_auth(&state.auth_token, &parts.headers)?;
        Ok(Self)
    }
}

pub struct BlockProposalBody(pub NakamotoBlockProposal);

impl FromRequest<AppState> for BlockProposalBody {
    type Rejection = ApiError;

    async fn from_request(req: Request, _state: &AppState) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();
        require_json_content_type(&parts.headers)?;

        let body = read_block_proposal_body(body).await?;
        let proposal: NakamotoBlockProposal = serde_json::from_slice(&body).map_err(|e| {
            ApiError::bad_request(
                ApiErrorCode::InvalidJson,
                format!("Failed to parse body: {e}"),
            )
        })?;
        if proposal.block.is_shadow_block() {
            return Err(ApiError::bad_request(
                ApiErrorCode::ShadowBlock,
                "Shadow blocks cannot be submitted for validation",
            ));
        }

        Ok(Self(proposal))
    }
}

fn require_block_proposal_auth(
    auth_token: &Option<String>,
    headers: &HeaderMap,
) -> Result<(), ApiError> {
    let Some(password) = auth_token else {
        return Err(ApiError::bad_request(
            ApiErrorCode::BlockProposalAuthNotConfigured,
            "Block proposal authentication is not configured",
        ));
    };
    let Some(auth_header) = headers.get(AUTHORIZATION) else {
        return Err(unauthorized());
    };
    if auth_header.to_str().ok() != Some(password.as_str()) {
        return Err(unauthorized());
    }
    Ok(())
}

fn unauthorized() -> ApiError {
    ApiError::status(
        StatusCode::UNAUTHORIZED,
        ApiErrorCode::Unauthorized,
        "Unauthorized",
    )
}

fn require_json_content_type(headers: &HeaderMap) -> Result<(), ApiError> {
    let Some(content_type) = headers.get(CONTENT_TYPE) else {
        return Err(ApiError::bad_request(
            ApiErrorCode::MissingContentType,
            "Missing Content-Type for block proposal",
        ));
    };
    let content_type = content_type
        .to_str()
        .map_err(|_| {
            ApiError::bad_request(
                ApiErrorCode::InvalidContentType,
                "Wrong Content-Type for block proposal; expected application/json",
            )
        })?
        .to_ascii_lowercase();
    if content_type == "application/json" || content_type.starts_with("application/json;") {
        Ok(())
    } else {
        Err(ApiError::bad_request(
            ApiErrorCode::InvalidContentType,
            "Wrong Content-Type for block proposal; expected application/json",
        ))
    }
}

async fn read_block_proposal_body(body: axum::body::Body) -> Result<Bytes, ApiError> {
    let body = to_bytes(body, MAX_PAYLOAD_LEN as usize + 1)
        .await
        .map_err(|_| body_too_large())?;
    if body.is_empty() {
        return Err(ApiError::bad_request(
            ApiErrorCode::EmptyBody,
            "Expected non-zero-length body for block proposal endpoint",
        ));
    }
    if body.len() > MAX_PAYLOAD_LEN as usize {
        return Err(body_too_large());
    }

    Ok(body)
}

fn body_too_large() -> ApiError {
    ApiError::bad_request(
        ApiErrorCode::BodyTooLarge,
        format!("Block proposal body exceeds {MAX_PAYLOAD_LEN} bytes"),
    )
}
