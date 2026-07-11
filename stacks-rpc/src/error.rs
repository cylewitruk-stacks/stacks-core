use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use stacks::net::rpc_services::{BlockProposalError, RpcServiceError};

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: ErrorBody,
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub code: ApiErrorCode,
    pub message: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiErrorCode {
    BadRequest,
    NotFound,
    InternalError,
    DomainReplyTimeout,
    DomainReplyDisconnected,
    BlockProposalRejected,
    WorkerTaskFailed,
    DomainQueueFull,
    DomainQueueDisconnected,
    ReadQueueFull,
    ReadQueueDisconnected,
    BlockStreamQueueFull,
    PeerInfoUnavailable,
    RequestTimeout,
    BlockProposalAuthNotConfigured,
    Unauthorized,
    MissingContentType,
    InvalidContentType,
    BodyTooLarge,
    BodyReadFailed,
    EmptyBody,
    InvalidJson,
    ShadowBlock,
    InvalidPrincipal,
    InvalidBlockId,
    InvalidTip,
}

#[derive(Debug)]
pub enum ApiError {
    BadRequest {
        code: ApiErrorCode,
        message: String,
    },
    NotFound {
        code: ApiErrorCode,
        message: String,
    },
    Unavailable {
        code: ApiErrorCode,
        message: String,
    },
    Internal {
        code: ApiErrorCode,
        message: String,
    },
    Status {
        status: StatusCode,
        code: ApiErrorCode,
        message: String,
    },
}

impl From<RpcServiceError> for ApiError {
    fn from(error: RpcServiceError) -> Self {
        match error {
            RpcServiceError::BadRequest(msg) => Self::bad_request(ApiErrorCode::BadRequest, msg),
            RpcServiceError::NotFound(msg) => Self::not_found(ApiErrorCode::NotFound, msg),
            RpcServiceError::Internal(msg) => Self::internal(ApiErrorCode::InternalError, msg),
        }
    }
}

impl From<BlockProposalError> for ApiError {
    fn from(error: BlockProposalError) -> Self {
        Self::status(
            block_proposal_error_status(&error),
            ApiErrorCode::BlockProposalRejected,
            error.to_string(),
        )
    }
}

impl ApiError {
    pub fn bad_request(code: ApiErrorCode, message: impl Into<String>) -> Self {
        Self::BadRequest {
            code,
            message: message.into(),
        }
    }

    pub fn not_found(code: ApiErrorCode, message: impl Into<String>) -> Self {
        Self::NotFound {
            code,
            message: message.into(),
        }
    }

    pub fn unavailable(code: ApiErrorCode, message: impl Into<String>) -> Self {
        Self::Unavailable {
            code,
            message: message.into(),
        }
    }

    pub fn internal(code: ApiErrorCode, message: impl Into<String>) -> Self {
        Self::Internal {
            code,
            message: message.into(),
        }
    }

    pub fn status(status: StatusCode, code: ApiErrorCode, message: impl Into<String>) -> Self {
        Self::Status {
            status,
            code,
            message: message.into(),
        }
    }
}

fn block_proposal_error_status(error: &BlockProposalError) -> StatusCode {
    match error {
        BlockProposalError::AlreadyValidating | BlockProposalError::SpawnFailed => {
            StatusCode::TOO_MANY_REQUESTS
        }
        BlockProposalError::TooOld => StatusCode::UNPROCESSABLE_ENTITY,
        BlockProposalError::Reopen(_) | BlockProposalError::NoObserver => StatusCode::BAD_REQUEST,
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::BadRequest { code, message } => (StatusCode::BAD_REQUEST, code, message),
            Self::NotFound { code, message } => (StatusCode::NOT_FOUND, code, message),
            Self::Unavailable { code, message } => (StatusCode::SERVICE_UNAVAILABLE, code, message),
            Self::Internal { code, message } => (StatusCode::INTERNAL_SERVER_ERROR, code, message),
            Self::Status {
                status,
                code,
                message,
            } => (status, code, message),
        };
        (
            status,
            Json(ErrorResponse {
                error: ErrorBody { code, message },
            }),
        )
            .into_response()
    }
}
