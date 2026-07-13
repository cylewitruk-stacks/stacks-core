use std::sync::Arc;

use axum::Router;
use stacks::net::rpc_bridge::RpcNodeHandle;
use stacks::net::rpc_services::RpcServiceResult;
use tokio::sync::Semaphore;

use crate::config::{ChainstateReadSpec, FeeEstimationSpec};

mod blocking;
mod chainstate;
mod extractors;
mod fees;
mod mempool;
mod read_pool;
mod routes;

use self::chainstate::ChainstateReadService;
use self::fees::FeeEstimationService;
use self::mempool::MempoolReadService;

pub struct RpcApplication {
    chainstate_reads: ChainstateReadService,
    mempool_reads: MempoolReadService,
    fee_estimation: FeeEstimationService,
    auth_token: Option<String>,
}

impl RpcApplication {
    pub fn open(
        chainstate_read: ChainstateReadSpec,
        mempool_read: crate::config::MempoolReadSpec,
        fee_estimation: Option<FeeEstimationSpec>,
        auth_token: Option<String>,
    ) -> RpcServiceResult<Self> {
        Ok(Self {
            chainstate_reads: ChainstateReadService::open(chainstate_read)?,
            mempool_reads: MempoolReadService::open(mempool_read)?,
            fee_estimation: FeeEstimationService::new(fee_estimation),
            auth_token,
        })
    }

    pub fn router(self, node: RpcNodeHandle) -> Router {
        routes::router(
            node,
            self.chainstate_reads,
            self.mempool_reads,
            self.fee_estimation,
            self.auth_token,
        )
    }
}

#[derive(Clone)]
struct AppState {
    node: RpcNodeHandle,
    chainstate_reads: ChainstateReadService,
    mempool_reads: MempoolReadService,
    fee_estimation: FeeEstimationService,
    auth_token: Option<String>,
    block_streams: Arc<Semaphore>,
}
