use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use stacks::burnchains::PoxConstants;
use stacks::chainstate::stacks::index::marf::MARFOpenOpts;

pub struct AxumRpcConfig {
    pub bind_addr: SocketAddr,
    pub auth_token: Option<String>,
    pub shutdown_signal: Option<Arc<AtomicBool>>,
    pub chainstate_read: ChainstateReadSpec,
}

#[derive(Clone)]
pub struct ChainstateReadSpec {
    pub mainnet: bool,
    pub chain_id: u32,
    pub chainstate_path: String,
    pub sortition_db_path: String,
    pub marf_opts: Option<MARFOpenOpts>,
    pub pox_constants: PoxConstants,
}
