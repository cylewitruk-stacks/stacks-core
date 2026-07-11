use axum::body::{to_bytes, Bytes};
use axum::extract::{FromRequest, FromRequestParts, Request};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use http_body_util::LengthLimitError;
use stacks::net::api::postblock_proposal::NakamotoBlockProposal;
use stacks_common::codec::MAX_PAYLOAD_LEN;
use subtle::ConstantTimeEq;

use super::AppState;
use crate::error::{ApiError, ApiErrorCode};

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
        return Err(ApiError::unavailable(
            ApiErrorCode::BlockProposalAuthNotConfigured,
            "Block proposal authentication is not configured",
        ));
    };
    let Some(auth_header) = headers.get(AUTHORIZATION) else {
        return Err(unauthorized());
    };
    let Some(token) = bearer_token(auth_header.to_str().ok()) else {
        return Err(unauthorized());
    };
    if !bool::from(token.as_bytes().ct_eq(password.as_bytes())) {
        return Err(unauthorized());
    }
    Ok(())
}

fn bearer_token(auth_header: Option<&str>) -> Option<&str> {
    let auth_header = auth_header?;
    let (scheme, token) = auth_header.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer") || token.is_empty() {
        return None;
    }
    Some(token)
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
        .map_err(map_body_read_error)?;
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

fn map_body_read_error(error: axum::Error) -> ApiError {
    if std::error::Error::source(&error).is_some_and(|source| source.is::<LengthLimitError>()) {
        body_too_large()
    } else {
        ApiError::bad_request(
            ApiErrorCode::BodyReadFailed,
            format!("Failed to read block proposal body: {error}"),
        )
    }
}

fn body_too_large() -> ApiError {
    ApiError::bad_request(
        ApiErrorCode::BodyTooLarge,
        format!("Block proposal body exceeds {MAX_PAYLOAD_LEN} bytes"),
    )
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::map_body_read_error;
    use crate::error::{ApiError, ApiErrorCode};

    #[test]
    fn block_proposal_body_read_errors_are_specific() {
        let length_limit_error = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async { axum::body::to_bytes(axum::body::Body::from(vec![0u8; 2]), 1).await })
            .unwrap_err();
        match map_body_read_error(length_limit_error) {
            ApiError::BadRequest {
                code: ApiErrorCode::BodyTooLarge,
                ..
            } => {}
            error => panic!("expected body_too_large, got {error:?}"),
        }

        match map_body_read_error(axum::Error::new(io::Error::other("broken body"))) {
            ApiError::BadRequest {
                code: ApiErrorCode::BodyReadFailed,
                ..
            } => {}
            error => panic!("expected body_read_failed, got {error:?}"),
        }
    }
}
