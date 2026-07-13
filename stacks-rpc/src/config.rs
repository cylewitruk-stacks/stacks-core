use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use clarity::vm::costs::ExecutionCost;
use stacks::burnchains::Burnchain;
use stacks::chainstate::stacks::index::marf::MARFOpenOpts;
use stacks::cost_estimates::metrics::CostMetric;
use stacks::cost_estimates::{CostEstimator, FeeEstimator};

pub struct AxumRpcConfig {
    pub bind_addr: SocketAddr,
    pub auth_token: Option<String>,
    pub shutdown_signal: Option<Arc<AtomicBool>>,
    pub chainstate_read: ChainstateReadSpec,
    pub mempool_read: MempoolReadSpec,
    pub fee_estimation: Option<FeeEstimationSpec>,
}

pub struct FeeEstimationSpec {
    pub cost_estimator: Box<dyn CostEstimator>,
    pub fee_estimator: Box<dyn FeeEstimator>,
    pub cost_metric: Box<dyn CostMetric>,
}

#[derive(Clone)]
pub struct MempoolReadSpec {
    pub chainstate_path: String,
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
