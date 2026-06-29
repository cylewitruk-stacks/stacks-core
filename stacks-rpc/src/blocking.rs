use std::sync::mpsc::{Receiver, RecvTimeoutError, TrySendError};
use std::time::Duration;

use crate::error::{ApiError, ApiErrorCode};

pub const DOMAIN_REPLY_TIMEOUT: Duration = Duration::from_secs(30);

pub fn recv_reply<T, E>(rx: Receiver<Result<T, E>>) -> Result<T, ApiError>
where
    E: Into<ApiError>,
{
    match rx.recv_timeout(DOMAIN_REPLY_TIMEOUT) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(error.into()),
        Err(RecvTimeoutError::Timeout) => Err(ApiError::unavailable(
            ApiErrorCode::DomainReplyTimeout,
            "Timed out waiting for RPC domain reply",
        )),
        Err(RecvTimeoutError::Disconnected) => Err(ApiError::unavailable(
            ApiErrorCode::DomainReplyDisconnected,
            "RPC domain reply channel disconnected",
        )),
    }
}

pub async fn run_blocking<T, F>(func: F) -> Result<T, ApiError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, ApiError> + Send + 'static,
{
    tokio::task::spawn_blocking(func).await.map_err(|e| {
        ApiError::internal(
            ApiErrorCode::WorkerTaskFailed,
            format!("RPC worker task failed: {e}"),
        )
    })?
}

pub fn map_domain_send_error<T>(error: TrySendError<T>) -> ApiError {
    match error {
        TrySendError::Full(_) => {
            ApiError::unavailable(ApiErrorCode::DomainQueueFull, "RPC domain queue is full")
        }
        TrySendError::Disconnected(_) => ApiError::unavailable(
            ApiErrorCode::DomainQueueDisconnected,
            "RPC domain queue is disconnected",
        ),
    }
}
