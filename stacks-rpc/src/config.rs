use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use clarity::vm::costs::ExecutionCost;
use stacks::burnchains::Burnchain;
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
    pub burnchain: Burnchain,
    pub txindex: bool,
    pub read_only_call: ReadOnlyCallSpec,
}

#[derive(Clone)]
pub struct ReadOnlyCallSpec {
    pub maximum_argument_bytes: u32,
    pub cost_limit: ExecutionCost,
    pub max_execution_time: Duration,
    pub max_memory_bytes: u64,
}
