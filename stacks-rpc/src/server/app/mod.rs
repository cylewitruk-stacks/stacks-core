use std::sync::Arc;

use axum::Router;
use stacks::net::rpc_bridge::RpcNodeHandle;
use stacks::net::rpc_services::RpcServiceResult;
use tokio::sync::Semaphore;

use crate::config::ChainstateReadSpec;

mod blocking;
mod chainstate;
mod extractors;
mod routes;

use self::chainstate::ChainstateReadService;

pub struct RpcApplication {
    chainstate_reads: ChainstateReadService,
    auth_token: Option<String>,
}

impl RpcApplication {
    pub fn open(
        chainstate_read: ChainstateReadSpec,
        auth_token: Option<String>,
    ) -> RpcServiceResult<Self> {
        Ok(Self {
            chainstate_reads: ChainstateReadService::open(chainstate_read)?,
            auth_token,
        })
    }

    pub fn router(self, node: RpcNodeHandle) -> Router {
        routes::router(node, self.chainstate_reads, self.auth_token)
    }
}

#[derive(Clone)]
struct AppState {
    node: RpcNodeHandle,
    chainstate_reads: ChainstateReadService,
    auth_token: Option<String>,
    block_streams: Arc<Semaphore>,
}
