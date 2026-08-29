use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use clarity::util::secp256k1::Secp256k1PublicKey;
use clarity::vm::analysis::contract_interface_builder::ContractInterface;
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier};
use clarity::vm::{ClarityName, Value};
use r2d2::{ManageConnection, Pool, PooledConnection};
use stacks::burnchains::Txid;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::stacks::boot::RewardSet;
use stacks::chainstate::stacks::db::{ExtendedStacksHeader, StacksChainState};
use stacks::core::StacksEpoch;
use stacks::net::api::get_tenures_fork_info::TenureForkingInfo;
use stacks::net::api::getpoxinfo::RPCPoxInfoData;
use stacks::net::api::getsortition::SortitionInfo;
use stacks::net::httpcore::TipRequest;
use stacks::net::rpc_services::{
    self, AccountView, ClarityValueView, ConfirmedTransactionView, ContractSourceView,
    NakamotoBlockStreamDescriptor, RpcServiceError, RpcServiceResult, SortitionQuery,
    TenureBlocksPage, TenureSelector, TenureTipView,
};
use stacks_common::types::chainstate::{ConsensusHash, StacksBlockId};

use super::read_pool::{
    build_eager_pool, DEFAULT_READ_POOL_SIZE, READ_POOL_CHECKOUT_TIMEOUT, READ_POOL_STARTUP_TIMEOUT,
};
use crate::config::{ChainstateReadSpec, ReadOnlyCallSpec};
use crate::error::{ApiError, ApiErrorCode};

#[derive(Clone)]
pub struct ChainstateReadService {
    executor: Arc<dyn ChainstateReadExecutor>,
    maximum_call_argument_bytes: u32,
    txindex: bool,
}

pub trait ChainstateReadExecutor: Send + Sync {
    fn get_account(
        &self,
        principal: PrincipalData,
        tip: TipRequest,
        with_proof: bool,
    ) -> Result<AccountView, ApiError>;

    fn get_nakamoto_block(
        &self,
        block_id: StacksBlockId,
    ) -> Result<NakamotoBlockStreamDescriptor, ApiError>;

    fn get_contract_source(
        &self,
        contract: QualifiedContractIdentifier,
        tip: TipRequest,
        with_proof: bool,
    ) -> Result<ContractSourceView, ApiError>;

    fn get_contract_interface(
        &self,
        contract: QualifiedContractIdentifier,
        tip: TipRequest,
    ) -> Result<ContractInterface, ApiError>;

    fn get_data_var(
        &self,
        contract: QualifiedContractIdentifier,
        name: ClarityName,
        tip: TipRequest,
        with_proof: bool,
    ) -> Result<ClarityValueView, ApiError>;

    fn get_map_entry(
        &self,
        contract: QualifiedContractIdentifier,
        map: ClarityName,
        key: Value,
        tip: TipRequest,
        with_proof: bool,
    ) -> Result<ClarityValueView, ApiError>;

    fn get_constant(
        &self,
        contract: QualifiedContractIdentifier,
        name: ClarityName,
        tip: TipRequest,
    ) -> Result<ClarityValueView, ApiError>;

    fn is_trait_implemented(
        &self,
        contract: QualifiedContractIdentifier,
        trait_contract: QualifiedContractIdentifier,
        trait_name: ClarityName,
        tip: TipRequest,
    ) -> Result<bool, ApiError>;

    fn get_clarity_metadata(
        &self,
        contract: QualifiedContractIdentifier,
        key: String,
        tip: TipRequest,
    ) -> Result<String, ApiError>;

    fn get_nakamoto_block_by_height(
        &self,
        height: u64,
        tip: TipRequest,
    ) -> Result<NakamotoBlockStreamDescriptor, ApiError>;

    fn get_confirmed_transaction(
        &self,
        txid: Txid,
        tip: TipRequest,
    ) -> Result<ConfirmedTransactionView, ApiError>;

    fn get_signer_block_count(
        &self,
        signer: Secp256k1PublicKey,
        reward_cycle: u64,
    ) -> Result<u64, ApiError>;

    fn get_tenure_tip(&self, consensus_hash: ConsensusHash) -> Result<TenureTipView, ApiError>;

    fn get_pox_info(&self, tip: TipRequest) -> Result<RPCPoxInfoData, ApiError>;

    fn get_stacker_set(&self, reward_cycle: u64, tip: TipRequest) -> Result<RewardSet, ApiError>;

    fn get_sortitions(&self, query: SortitionQuery) -> Result<Vec<SortitionInfo>, ApiError>;

    fn call_read_only(
        &self,
        contract: QualifiedContractIdentifier,
        function: ClarityName,
        sender: PrincipalData,
        sponsor: Option<PrincipalData>,
        arguments: Vec<Value>,
        tip: TipRequest,
    ) -> Result<rpc_services::ReadOnlyCallView, ApiError>;

    fn get_headers(
        &self,
        quantity: u32,
        tip: TipRequest,
    ) -> Result<Vec<ExtendedStacksHeader>, ApiError>;

    fn get_tenure_blocks_page(
        &self,
        selector: TenureSelector,
        cursor: Option<StacksBlockId>,
        limit: usize,
    ) -> Result<TenureBlocksPage, ApiError>;

    fn get_tenure_fork_info(
        &self,
        start: ConsensusHash,
        end: ConsensusHash,
    ) -> Result<Vec<TenureForkingInfo>, ApiError>;

    fn get_current_epoch(&self) -> Result<StacksEpoch, ApiError>;
}

struct PooledChainstateReads {
    pool: Pool<ChainstateReadManager>,
    checkout_timeout: Duration,
    burnchain: stacks::burnchains::Burnchain,
    read_only_call: ReadOnlyCallSpec,
}

struct ChainstateReadHandles {
    chainstate: StacksChainState,
    sortdb: SortitionDB,
}

#[derive(Clone)]
struct ChainstateReadManager {
    spec: ChainstateReadSpec,
}

impl ChainstateReadService {
    pub fn open(spec: ChainstateReadSpec) -> RpcServiceResult<Self> {
        Self::open_with_config(
            spec,
            DEFAULT_READ_POOL_SIZE,
            READ_POOL_CHECKOUT_TIMEOUT,
            READ_POOL_STARTUP_TIMEOUT,
        )
    }

    fn open_with_config(
        spec: ChainstateReadSpec,
        pool_size: u32,
        checkout_timeout: Duration,
        startup_timeout: Duration,
    ) -> RpcServiceResult<Self> {
        if pool_size == 0 {
            return Err(RpcServiceError::BadRequest(
                "Chainstate read pool size must be greater than zero".to_string(),
            ));
        }

        let burnchain = spec.burnchain.clone();
        let read_only_call = spec.read_only_call.clone();
        let maximum_call_argument_bytes = read_only_call.maximum_argument_bytes;
        let txindex = spec.txindex;
        let manager = ChainstateReadManager { spec };
        let pool = build_eager_pool(manager, pool_size, startup_timeout)
            .map_err(|e| RpcServiceError::internal("Failed to create chainstate read pool", e))?;

        Ok(Self::from_executor(
            PooledChainstateReads {
                pool,
                checkout_timeout,
                burnchain,
                read_only_call,
            },
            maximum_call_argument_bytes,
            txindex,
        ))
    }

    pub fn from_executor(
        executor: impl ChainstateReadExecutor + 'static,
        maximum_call_argument_bytes: u32,
        txindex: bool,
    ) -> Self {
        Self {
            executor: Arc::new(executor),
            maximum_call_argument_bytes,
            txindex,
        }
    }

    pub fn get_account(
        &self,
        principal: PrincipalData,
        tip: TipRequest,
        with_proof: bool,
    ) -> Result<AccountView, ApiError> {
        self.executor.get_account(principal, tip, with_proof)
    }

    pub fn get_nakamoto_block(
        &self,
        block_id: StacksBlockId,
    ) -> Result<NakamotoBlockStreamDescriptor, ApiError> {
        self.executor.get_nakamoto_block(block_id)
    }

    pub fn get_contract_source(
        &self,
        contract: QualifiedContractIdentifier,
        tip: TipRequest,
        with_proof: bool,
    ) -> Result<ContractSourceView, ApiError> {
        self.executor.get_contract_source(contract, tip, with_proof)
    }

    pub fn get_contract_interface(
        &self,
        contract: QualifiedContractIdentifier,
        tip: TipRequest,
    ) -> Result<ContractInterface, ApiError> {
        self.executor.get_contract_interface(contract, tip)
    }

    pub fn get_data_var(
        &self,
        contract: QualifiedContractIdentifier,
        name: ClarityName,
        tip: TipRequest,
        with_proof: bool,
    ) -> Result<ClarityValueView, ApiError> {
        self.executor.get_data_var(contract, name, tip, with_proof)
    }

    pub fn get_map_entry(
        &self,
        contract: QualifiedContractIdentifier,
        map: ClarityName,
        key: Value,
        tip: TipRequest,
        with_proof: bool,
    ) -> Result<ClarityValueView, ApiError> {
        self.executor
            .get_map_entry(contract, map, key, tip, with_proof)
    }

    pub fn get_constant(
        &self,
        contract: QualifiedContractIdentifier,
        name: ClarityName,
        tip: TipRequest,
    ) -> Result<ClarityValueView, ApiError> {
        self.executor.get_constant(contract, name, tip)
    }

    pub fn is_trait_implemented(
        &self,
        contract: QualifiedContractIdentifier,
        trait_contract: QualifiedContractIdentifier,
        trait_name: ClarityName,
        tip: TipRequest,
    ) -> Result<bool, ApiError> {
        self.executor
            .is_trait_implemented(contract, trait_contract, trait_name, tip)
    }

    pub fn get_clarity_metadata(
        &self,
        contract: QualifiedContractIdentifier,
        key: String,
        tip: TipRequest,
    ) -> Result<String, ApiError> {
        self.executor.get_clarity_metadata(contract, key, tip)
    }

    pub fn get_nakamoto_block_by_height(
        &self,
        height: u64,
        tip: TipRequest,
    ) -> Result<NakamotoBlockStreamDescriptor, ApiError> {
        self.executor.get_nakamoto_block_by_height(height, tip)
    }

    pub fn get_confirmed_transaction(
        &self,
        txid: Txid,
        tip: TipRequest,
    ) -> Result<ConfirmedTransactionView, ApiError> {
        if !self.txindex {
            return Err(ApiError::status(
                axum::http::StatusCode::NOT_IMPLEMENTED,
                ApiErrorCode::TransactionIndexDisabled,
                "Transaction indexing is not enabled",
            ));
        }
        self.executor.get_confirmed_transaction(txid, tip)
    }

    pub fn get_signer_block_count(
        &self,
        signer: Secp256k1PublicKey,
        reward_cycle: u64,
    ) -> Result<u64, ApiError> {
        self.executor.get_signer_block_count(signer, reward_cycle)
    }

    pub fn get_tenure_tip(&self, consensus_hash: ConsensusHash) -> Result<TenureTipView, ApiError> {
        self.executor.get_tenure_tip(consensus_hash)
    }

    pub fn get_pox_info(&self, tip: TipRequest) -> Result<RPCPoxInfoData, ApiError> {
        self.executor.get_pox_info(tip)
    }

    pub fn get_stacker_set(
        &self,
        reward_cycle: u64,
        tip: TipRequest,
    ) -> Result<RewardSet, ApiError> {
        self.executor.get_stacker_set(reward_cycle, tip)
    }

    pub fn get_sortitions(&self, query: SortitionQuery) -> Result<Vec<SortitionInfo>, ApiError> {
        self.executor.get_sortitions(query)
    }

    pub fn maximum_call_argument_bytes(&self) -> u32 {
        self.maximum_call_argument_bytes
    }

    pub fn call_read_only(
        &self,
        contract: QualifiedContractIdentifier,
        function: ClarityName,
        sender: PrincipalData,
        sponsor: Option<PrincipalData>,
        arguments: Vec<Value>,
        tip: TipRequest,
    ) -> Result<rpc_services::ReadOnlyCallView, ApiError> {
        self.executor
            .call_read_only(contract, function, sender, sponsor, arguments, tip)
    }

    pub fn get_headers(
        &self,
        quantity: u32,
        tip: TipRequest,
    ) -> Result<Vec<ExtendedStacksHeader>, ApiError> {
        self.executor.get_headers(quantity, tip)
    }

    pub fn get_tenure_blocks_page(
        &self,
        selector: TenureSelector,
        cursor: Option<StacksBlockId>,
        limit: usize,
    ) -> Result<TenureBlocksPage, ApiError> {
        self.executor
            .get_tenure_blocks_page(selector, cursor, limit)
    }

    pub fn get_tenure_fork_info(
        &self,
        start: ConsensusHash,
        end: ConsensusHash,
    ) -> Result<Vec<TenureForkingInfo>, ApiError> {
        self.executor.get_tenure_fork_info(start, end)
    }

    pub fn get_current_epoch(&self) -> Result<StacksEpoch, ApiError> {
        self.executor.get_current_epoch()
    }
}

impl ChainstateReadExecutor for PooledChainstateReads {
    fn get_account(
        &self,
        principal: PrincipalData,
        tip: TipRequest,
        with_proof: bool,
    ) -> Result<AccountView, ApiError> {
        let mut handles = self.checkout()?;
        let ChainstateReadHandles { chainstate, sortdb } = &mut *handles;
        // Read-only pooled handles do not maintain unconfirmed state; `tip=latest`
        // falls back to the canonical anchored tip in rpc_services when none exists.
        rpc_services::get_account(sortdb, chainstate, &principal, &tip, with_proof)
            .map_err(ApiError::from)
    }

    fn get_nakamoto_block(
        &self,
        block_id: StacksBlockId,
    ) -> Result<NakamotoBlockStreamDescriptor, ApiError> {
        let handles = self.checkout()?;
        rpc_services::get_nakamoto_block_stream(&handles.chainstate, block_id)
            .map_err(ApiError::from)
    }

    fn get_contract_source(
        &self,
        contract: QualifiedContractIdentifier,
        tip: TipRequest,
        with_proof: bool,
    ) -> Result<ContractSourceView, ApiError> {
        let mut handles = self.checkout()?;
        let ChainstateReadHandles { chainstate, sortdb } = &mut *handles;
        rpc_services::get_contract_source(sortdb, chainstate, &contract, &tip, with_proof)
            .map_err(ApiError::from)
    }

    fn get_contract_interface(
        &self,
        contract: QualifiedContractIdentifier,
        tip: TipRequest,
    ) -> Result<ContractInterface, ApiError> {
        let mut handles = self.checkout()?;
        let ChainstateReadHandles { chainstate, sortdb } = &mut *handles;
        rpc_services::get_contract_interface(sortdb, chainstate, &contract, &tip)
            .map_err(ApiError::from)
    }

    fn get_data_var(
        &self,
        contract: QualifiedContractIdentifier,
        name: ClarityName,
        tip: TipRequest,
        with_proof: bool,
    ) -> Result<ClarityValueView, ApiError> {
        let mut handles = self.checkout()?;
        let ChainstateReadHandles { chainstate, sortdb } = &mut *handles;
        rpc_services::get_data_var(sortdb, chainstate, &contract, &name, &tip, with_proof)
            .map_err(ApiError::from)
    }

    fn get_map_entry(
        &self,
        contract: QualifiedContractIdentifier,
        map: ClarityName,
        key: Value,
        tip: TipRequest,
        with_proof: bool,
    ) -> Result<ClarityValueView, ApiError> {
        let mut handles = self.checkout()?;
        let ChainstateReadHandles { chainstate, sortdb } = &mut *handles;
        rpc_services::get_map_entry(sortdb, chainstate, &contract, &map, &key, &tip, with_proof)
            .map_err(ApiError::from)
    }

    fn get_constant(
        &self,
        contract: QualifiedContractIdentifier,
        name: ClarityName,
        tip: TipRequest,
    ) -> Result<ClarityValueView, ApiError> {
        let mut handles = self.checkout()?;
        let ChainstateReadHandles { chainstate, sortdb } = &mut *handles;
        rpc_services::get_constant(sortdb, chainstate, &contract, &name, &tip)
            .map_err(ApiError::from)
    }

    fn is_trait_implemented(
        &self,
        contract: QualifiedContractIdentifier,
        trait_contract: QualifiedContractIdentifier,
        trait_name: ClarityName,
        tip: TipRequest,
    ) -> Result<bool, ApiError> {
        let mut handles = self.checkout()?;
        let ChainstateReadHandles { chainstate, sortdb } = &mut *handles;
        rpc_services::is_trait_implemented(
            sortdb,
            chainstate,
            &contract,
            trait_contract,
            trait_name,
            &tip,
        )
        .map_err(ApiError::from)
    }

    fn get_clarity_metadata(
        &self,
        contract: QualifiedContractIdentifier,
        key: String,
        tip: TipRequest,
    ) -> Result<String, ApiError> {
        let mut handles = self.checkout()?;
        let ChainstateReadHandles { chainstate, sortdb } = &mut *handles;
        rpc_services::get_clarity_metadata(sortdb, chainstate, &contract, &key, &tip)
            .map_err(ApiError::from)
    }

    fn get_nakamoto_block_by_height(
        &self,
        height: u64,
        tip: TipRequest,
    ) -> Result<NakamotoBlockStreamDescriptor, ApiError> {
        let mut handles = self.checkout()?;
        let ChainstateReadHandles { chainstate, sortdb } = &mut *handles;
        rpc_services::get_nakamoto_block_stream_by_height(sortdb, chainstate, height, &tip)
            .map_err(ApiError::from)
    }

    fn get_confirmed_transaction(
        &self,
        txid: Txid,
        tip: TipRequest,
    ) -> Result<ConfirmedTransactionView, ApiError> {
        let mut handles = self.checkout()?;
        let ChainstateReadHandles { chainstate, sortdb } = &mut *handles;
        rpc_services::get_confirmed_transaction(sortdb, chainstate, &txid, &tip)
            .map_err(ApiError::from)
    }

    fn get_signer_block_count(
        &self,
        signer: Secp256k1PublicKey,
        reward_cycle: u64,
    ) -> Result<u64, ApiError> {
        let handles = self.checkout()?;
        rpc_services::get_signer_block_count(&handles.chainstate, &signer, reward_cycle)
            .map_err(ApiError::from)
    }

    fn get_tenure_tip(&self, consensus_hash: ConsensusHash) -> Result<TenureTipView, ApiError> {
        let handles = self.checkout()?;
        rpc_services::get_tenure_tip(&handles.sortdb, &handles.chainstate, &consensus_hash)
            .map_err(ApiError::from)
    }

    fn get_pox_info(&self, tip: TipRequest) -> Result<RPCPoxInfoData, ApiError> {
        let mut handles = self.checkout()?;
        let ChainstateReadHandles { chainstate, sortdb } = &mut *handles;
        rpc_services::get_pox_info(sortdb, chainstate, &self.burnchain, &tip)
            .map_err(ApiError::from)
    }

    fn get_stacker_set(&self, reward_cycle: u64, tip: TipRequest) -> Result<RewardSet, ApiError> {
        let mut handles = self.checkout()?;
        let ChainstateReadHandles { chainstate, sortdb } = &mut *handles;
        rpc_services::get_stacker_set(sortdb, chainstate, &self.burnchain, reward_cycle, &tip)
            .map_err(ApiError::from)
    }

    fn get_sortitions(&self, query: SortitionQuery) -> Result<Vec<SortitionInfo>, ApiError> {
        let mut handles = self.checkout()?;
        let ChainstateReadHandles { chainstate, sortdb } = &mut *handles;
        rpc_services::get_sortitions(sortdb, chainstate, &query).map_err(ApiError::from)
    }

    fn call_read_only(
        &self,
        contract: QualifiedContractIdentifier,
        function: ClarityName,
        sender: PrincipalData,
        sponsor: Option<PrincipalData>,
        arguments: Vec<Value>,
        tip: TipRequest,
    ) -> Result<rpc_services::ReadOnlyCallView, ApiError> {
        let mut handles = self.checkout()?;
        let ChainstateReadHandles { chainstate, sortdb } = &mut *handles;
        rpc_services::call_read_only(
            sortdb,
            chainstate,
            &contract,
            &function,
            sender,
            sponsor,
            arguments,
            &tip,
            self.read_only_call.cost_limit.clone(),
            self.read_only_call.max_execution_time,
            self.read_only_call.max_memory_bytes,
        )
        .map_err(ApiError::from)
    }

    fn get_headers(
        &self,
        quantity: u32,
        tip: TipRequest,
    ) -> Result<Vec<ExtendedStacksHeader>, ApiError> {
        let mut handles = self.checkout()?;
        let ChainstateReadHandles { chainstate, sortdb } = &mut *handles;
        rpc_services::get_headers(sortdb, chainstate, quantity, &tip).map_err(ApiError::from)
    }

    fn get_tenure_blocks_page(
        &self,
        selector: TenureSelector,
        cursor: Option<StacksBlockId>,
        limit: usize,
    ) -> Result<TenureBlocksPage, ApiError> {
        let mut handles = self.checkout()?;
        let ChainstateReadHandles { chainstate, sortdb } = &mut *handles;
        rpc_services::get_tenure_blocks_page(sortdb, chainstate, &selector, cursor, limit)
            .map_err(ApiError::from)
    }

    fn get_tenure_fork_info(
        &self,
        start: ConsensusHash,
        end: ConsensusHash,
    ) -> Result<Vec<TenureForkingInfo>, ApiError> {
        let mut handles = self.checkout()?;
        let ChainstateReadHandles { chainstate, sortdb } = &mut *handles;
        rpc_services::get_tenure_fork_info(sortdb, chainstate, &start, &end).map_err(ApiError::from)
    }

    fn get_current_epoch(&self) -> Result<StacksEpoch, ApiError> {
        let handles = self.checkout()?;
        let tip =
            SortitionDB::get_canonical_burn_chain_tip(handles.sortdb.conn()).map_err(|e| {
                ApiError::from(RpcServiceError::internal(
                    "Failed to load canonical burnchain tip",
                    e,
                ))
            })?;
        SortitionDB::get_stacks_epoch(handles.sortdb.conn(), tip.block_height)
            .map_err(|e| {
                ApiError::from(RpcServiceError::internal(
                    "Failed to load current Stacks epoch",
                    e,
                ))
            })?
            .ok_or_else(|| {
                ApiError::internal(
                    ApiErrorCode::InternalError,
                    "Current Stacks epoch is unavailable",
                )
            })
    }
}

impl PooledChainstateReads {
    fn checkout(&self) -> Result<PooledConnection<ChainstateReadManager>, ApiError> {
        self.pool.get_timeout(self.checkout_timeout).map_err(|_| {
            ApiError::unavailable(
                ApiErrorCode::ReadQueueFull,
                "RPC chainstate read pool is busy",
            )
        })
    }
}

impl ManageConnection for ChainstateReadManager {
    type Connection = ChainstateReadHandles;
    type Error = ChainstateReadOpenError;

    fn connect(&self) -> Result<Self::Connection, Self::Error> {
        open_chainstate_read_handles(&self.spec).map_err(ChainstateReadOpenError::from)
    }

    fn is_valid(&self, _conn: &mut Self::Connection) -> Result<(), Self::Error> {
        Ok(())
    }

    fn has_broken(&self, _conn: &mut Self::Connection) -> bool {
        false
    }
}

#[derive(Debug)]
struct ChainstateReadOpenError(String);

impl From<RpcServiceError> for ChainstateReadOpenError {
    fn from(error: RpcServiceError) -> Self {
        Self(format!("{error:?}"))
    }
}

impl fmt::Display for ChainstateReadOpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ChainstateReadOpenError {}

fn open_chainstate_read_handles(
    spec: &ChainstateReadSpec,
) -> RpcServiceResult<ChainstateReadHandles> {
    let chainstate = StacksChainState::open_readonly(
        spec.mainnet,
        spec.chain_id,
        &spec.chainstate_path,
        spec.marf_opts.clone(),
    )
    .map_err(|e| RpcServiceError::internal("Failed to open RPC chainstate read handle", e))?;
    let sortdb = SortitionDB::open(
        &spec.sortition_db_path,
        false,
        spec.burnchain.pox_constants.clone(),
        spec.marf_opts.clone(),
    )
    .map_err(|e| RpcServiceError::internal("Failed to open RPC sortition read handle", e))?;

    Ok(ChainstateReadHandles { chainstate, sortdb })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use std::{fmt, thread};

    use r2d2::ManageConnection;

    use super::{READ_POOL_CHECKOUT_TIMEOUT, READ_POOL_STARTUP_TIMEOUT};
    use crate::server::app::read_pool::build_eager_pool;

    #[test]
    fn startup_timeout_is_distinct_from_checkout_timeout() {
        assert!(READ_POOL_STARTUP_TIMEOUT > READ_POOL_CHECKOUT_TIMEOUT);

        let pool = build_eager_pool(
            SlowManager {
                connect_delay: READ_POOL_CHECKOUT_TIMEOUT * 2,
            },
            1,
            READ_POOL_STARTUP_TIMEOUT,
        )
        .expect("startup timeout should allow slow initial connection opens");

        assert_eq!(pool.state().connections, 1);
        assert_eq!(pool.state().idle_connections, 1);
    }

    #[derive(Clone)]
    struct SlowManager {
        connect_delay: Duration,
    }

    impl ManageConnection for SlowManager {
        type Connection = ();
        type Error = SlowError;

        fn connect(&self) -> Result<Self::Connection, Self::Error> {
            thread::sleep(self.connect_delay);
            Ok(())
        }

        fn is_valid(&self, _conn: &mut Self::Connection) -> Result<(), Self::Error> {
            Ok(())
        }

        fn has_broken(&self, _conn: &mut Self::Connection) -> bool {
            false
        }
    }

    #[derive(Debug)]
    struct SlowError;

    impl fmt::Display for SlowError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("slow connection error")
        }
    }

    impl std::error::Error for SlowError {}
}
