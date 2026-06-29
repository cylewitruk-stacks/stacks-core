use stacks::net::rpc_domains::RpcDomainChannels;

use crate::chainstate_read::ChainstateReadService;

#[derive(Clone)]
pub struct AppState {
    pub domains: RpcDomainChannels,
    pub chainstate_reads: ChainstateReadService,
    pub auth_token: Option<String>,
}
