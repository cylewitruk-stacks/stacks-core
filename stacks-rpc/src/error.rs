use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use stacks::net::rpc_services::{
    BlockProposalError, FeeEstimationError, RpcServiceError, TransactionSubmissionError,
};

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: ErrorBody,
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub code: ApiErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
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
    MempoolUnavailable,
    BlockStreamQueueFull,
    NodeSnapshotUnavailable,
    CurrentTenureUnavailable,
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
    InvalidContract,
    InvalidClarityName,
    InvalidClarityValue,
    InvalidMetadataKey,
    CallArgumentsTooLarge,
    ContractCallNotReadOnly,
    ContractCallFailed,
    InvalidBlockId,
    InvalidBlockHeight,
    InvalidTransactionId,
    InvalidTransaction,
    InvalidAttachment,
    TransactionIndexDisabled,
    TransactionProblematic,
    TransactionRejected,
    FeeEstimationDisabled,
    FeeEstimateUnavailable,
    InvalidTransactionPayload,
    InvalidSignerPublicKey,
    InvalidRewardCycle,
    InvalidConsensusHash,
    InvalidBurnBlockHash,
    InvalidBurnBlockHeight,
    InvalidPagination,
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
    StatusWithDetails {
        status: StatusCode,
        code: ApiErrorCode,
        message: String,
        details: serde_json::Value,
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

impl From<TransactionSubmissionError> for ApiError {
    fn from(error: TransactionSubmissionError) -> Self {
        match error {
            TransactionSubmissionError::Problematic => Self::status(
                StatusCode::UNPROCESSABLE_ENTITY,
                ApiErrorCode::TransactionProblematic,
                "Transaction failed static problematic checks",
            ),
            TransactionSubmissionError::Rejected(details) => Self::status_with_details(
                StatusCode::UNPROCESSABLE_ENTITY,
                ApiErrorCode::TransactionRejected,
                "Transaction was rejected by the mempool",
                details,
            ),
            TransactionSubmissionError::Internal(message) => {
                Self::internal(ApiErrorCode::InternalError, message)
            }
        }
    }
}

impl From<FeeEstimationError> for ApiError {
    fn from(error: FeeEstimationError) -> Self {
        match error {
            FeeEstimationError::NoEstimate(message) => Self::status(
                StatusCode::UNPROCESSABLE_ENTITY,
                ApiErrorCode::FeeEstimateUnavailable,
                message,
            ),
            FeeEstimationError::Internal(message) => {
                Self::internal(ApiErrorCode::InternalError, message)
            }
        }
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

    pub fn status_with_details(
        status: StatusCode,
        code: ApiErrorCode,
        message: impl Into<String>,
        details: serde_json::Value,
    ) -> Self {
        Self::StatusWithDetails {
            status,
            code,
            message: message.into(),
            details,
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
        let (status, code, message, details) = match self {
            Self::BadRequest { code, message } => (StatusCode::BAD_REQUEST, code, message, None),
            Self::NotFound { code, message } => (StatusCode::NOT_FOUND, code, message, None),
            Self::Unavailable { code, message } => {
                (StatusCode::SERVICE_UNAVAILABLE, code, message, None)
            }
            Self::Internal { code, message } => {
                (StatusCode::INTERNAL_SERVER_ERROR, code, message, None)
            }
            Self::Status {
                status,
                code,
                message,
            } => (status, code, message, None),
            Self::StatusWithDetails {
                status,
                code,
                message,
                details,
            } => (status, code, message, Some(details)),
        };
        (
            status,
            Json(ErrorResponse {
                error: ErrorBody {
                    code,
                    message,
                    details,
                },
            }),
        )
            .into_response()
    }
}
