use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use clarity::vm::types::PrincipalData;
use r2d2::{ManageConnection, Pool, PooledConnection};
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::stacks::db::StacksChainState;
use stacks::net::httpcore::TipRequest;
use stacks::net::rpc_services::{
    self, AccountView, NakamotoBlockStreamDescriptor, RpcServiceError, RpcServiceResult,
};
use stacks_common::types::chainstate::StacksBlockId;

use crate::config::ChainstateReadSpec;
use crate::error::{ApiError, ApiErrorCode};

const DEFAULT_READ_POOL_SIZE: u32 = 4;
const READ_POOL_CHECKOUT_TIMEOUT: Duration = Duration::from_millis(100);
const READ_POOL_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub struct ChainstateReadService {
    executor: Arc<dyn ChainstateReadExecutor>,
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
}

struct PooledChainstateReads {
    pool: Pool<ChainstateReadManager>,
    checkout_timeout: Duration,
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

        let manager = ChainstateReadManager { spec };
        let pool = build_eager_pool(manager, pool_size, startup_timeout)
            .map_err(|e| RpcServiceError::internal("Failed to create chainstate read pool", e))?;

        Ok(Self::from_executor(PooledChainstateReads {
            pool,
            checkout_timeout,
        }))
    }

    fn from_executor(executor: impl ChainstateReadExecutor + 'static) -> Self {
        Self {
            executor: Arc::new(executor),
        }
    }

    #[cfg(test)]
    pub fn test_from_executor(executor: impl ChainstateReadExecutor + 'static) -> Self {
        Self::from_executor(executor)
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

fn build_eager_pool<M>(
    manager: M,
    pool_size: u32,
    startup_timeout: Duration,
) -> Result<Pool<M>, r2d2::Error>
where
    M: ManageConnection,
{
    Pool::builder()
        .max_size(pool_size)
        .min_idle(Some(pool_size))
        .connection_timeout(startup_timeout)
        .idle_timeout(None)
        .max_lifetime(None)
        .test_on_check_out(false)
        .build(manager)
}

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
        spec.pox_constants.clone(),
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

    use super::{build_eager_pool, READ_POOL_CHECKOUT_TIMEOUT, READ_POOL_STARTUP_TIMEOUT};

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
