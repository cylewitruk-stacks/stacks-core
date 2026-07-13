use std::sync::{Arc, Mutex};

use stacks::chainstate::stacks::TransactionPayload;
use stacks::core::StacksEpoch;
use stacks::net::rpc_services::{self, FeeEstimateView};

use crate::config::FeeEstimationSpec;
use crate::error::{ApiError, ApiErrorCode};

#[derive(Clone)]
pub struct FeeEstimationService {
    executor: Option<Arc<dyn FeeEstimationExecutor>>,
}

pub trait FeeEstimationExecutor: Send + Sync {
    fn estimate(
        &self,
        payload: TransactionPayload,
        estimated_len: u64,
        epoch: StacksEpoch,
    ) -> Result<FeeEstimateView, ApiError>;
}

struct ConfiguredFeeEstimator {
    estimators: Mutex<FeeEstimationSpec>,
}

impl FeeEstimationService {
    pub fn new(spec: Option<FeeEstimationSpec>) -> Self {
        Self {
            executor: spec.map(|spec| {
                Arc::new(ConfiguredFeeEstimator {
                    estimators: Mutex::new(spec),
                }) as Arc<dyn FeeEstimationExecutor>
            }),
        }
    }

    #[cfg(test)]
    pub fn test_from_executor(executor: impl FeeEstimationExecutor + 'static) -> Self {
        Self {
            executor: Some(Arc::new(executor)),
        }
    }

    pub fn estimate(
        &self,
        payload: TransactionPayload,
        estimated_len: u64,
        epoch: StacksEpoch,
    ) -> Result<FeeEstimateView, ApiError> {
        let executor = self.executor.as_ref().ok_or_else(|| {
            ApiError::status(
                axum::http::StatusCode::NOT_IMPLEMENTED,
                ApiErrorCode::FeeEstimationDisabled,
                "Fee estimation is not configured on this node",
            )
        })?;
        executor.estimate(payload, estimated_len, epoch)
    }
}

impl FeeEstimationExecutor for ConfiguredFeeEstimator {
    fn estimate(
        &self,
        payload: TransactionPayload,
        estimated_len: u64,
        epoch: StacksEpoch,
    ) -> Result<FeeEstimateView, ApiError> {
        let estimators = self.estimators.lock().map_err(|_| {
            ApiError::internal(
                ApiErrorCode::InternalError,
                "Fee estimator lock was poisoned",
            )
        })?;
        rpc_services::estimate_transaction_fee(
            estimators.cost_estimator.as_ref(),
            estimators.fee_estimator.as_ref(),
            estimators.cost_metric.as_ref(),
            &payload,
            estimated_len,
            &epoch,
        )
        .map_err(ApiError::from)
    }
}
