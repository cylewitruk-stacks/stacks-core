use std::fmt;
use std::path::Path;
use std::sync::Arc;

use r2d2::{ManageConnection, Pool, PooledConnection};
use rusqlite::OpenFlags;
use stacks::burnchains::Txid;
use stacks::core::mempool::MemPoolDB;
use stacks::net::rpc_services::{
    self, MempoolTransactionView, MempoolTransactionsPage, RpcServiceError, RpcServiceResult,
};
use stacks::util_lib::db::{sqlite_open, DBConn};

use super::read_pool::{build_lazy_pool, DEFAULT_READ_POOL_SIZE, READ_POOL_CHECKOUT_TIMEOUT};
use crate::config::MempoolReadSpec;
use crate::error::{ApiError, ApiErrorCode};

#[derive(Clone)]
pub struct MempoolReadService {
    executor: Arc<dyn MempoolReadExecutor>,
}

pub trait MempoolReadExecutor: Send + Sync {
    fn get_transaction(&self, txid: Txid) -> Result<MempoolTransactionView, ApiError>;

    fn get_transactions_page(
        &self,
        cursor: Option<Txid>,
        limit: u64,
    ) -> Result<MempoolTransactionsPage, ApiError>;
}

struct PooledMempoolReads {
    pool: Pool<MempoolReadManager>,
    db_path: String,
}

#[derive(Clone)]
struct MempoolReadManager {
    db_path: String,
}

impl MempoolReadService {
    pub fn open(spec: MempoolReadSpec) -> RpcServiceResult<Self> {
        let db_path = MemPoolDB::db_path(&spec.chainstate_path)
            .map_err(|e| RpcServiceError::internal("Failed to resolve mempool DB path", e))?;
        // The node-owned mempool DB may be created immediately after the Axum app is prepared.
        // A lazy pool avoids making first-boot startup depend on that thread ordering.
        let pool = build_lazy_pool(
            MempoolReadManager {
                db_path: db_path.clone(),
            },
            DEFAULT_READ_POOL_SIZE,
        );
        Ok(Self::from_executor(PooledMempoolReads { pool, db_path }))
    }

    fn from_executor(executor: impl MempoolReadExecutor + 'static) -> Self {
        Self {
            executor: Arc::new(executor),
        }
    }

    #[cfg(test)]
    pub fn test_from_executor(executor: impl MempoolReadExecutor + 'static) -> Self {
        Self::from_executor(executor)
    }

    pub fn get_transaction(&self, txid: Txid) -> Result<MempoolTransactionView, ApiError> {
        self.executor.get_transaction(txid)
    }

    pub fn get_transactions_page(
        &self,
        cursor: Option<Txid>,
        limit: u64,
    ) -> Result<MempoolTransactionsPage, ApiError> {
        self.executor.get_transactions_page(cursor, limit)
    }
}

impl MempoolReadExecutor for PooledMempoolReads {
    fn get_transaction(&self, txid: Txid) -> Result<MempoolTransactionView, ApiError> {
        let conn = self.checkout()?;
        rpc_services::get_mempool_transaction(&conn, &txid).map_err(ApiError::from)
    }

    fn get_transactions_page(
        &self,
        cursor: Option<Txid>,
        limit: u64,
    ) -> Result<MempoolTransactionsPage, ApiError> {
        let conn = self.checkout()?;
        rpc_services::get_mempool_transactions_page(&conn, cursor.as_ref(), limit)
            .map_err(ApiError::from)
    }
}

impl PooledMempoolReads {
    fn checkout(&self) -> Result<PooledConnection<MempoolReadManager>, ApiError> {
        if !Path::new(&self.db_path).is_file() {
            return Err(ApiError::unavailable(
                ApiErrorCode::MempoolUnavailable,
                "RPC mempool database is not ready",
            ));
        }

        self.pool
            .get_timeout(READ_POOL_CHECKOUT_TIMEOUT)
            .map_err(|_| {
                let state = self.pool.state();
                if state.connections == DEFAULT_READ_POOL_SIZE && state.idle_connections == 0 {
                    ApiError::unavailable(
                        ApiErrorCode::ReadQueueFull,
                        "RPC mempool read pool is busy",
                    )
                } else {
                    ApiError::unavailable(
                        ApiErrorCode::MempoolUnavailable,
                        "RPC mempool database is unavailable",
                    )
                }
            })
    }
}

impl ManageConnection for MempoolReadManager {
    type Connection = DBConn;
    type Error = MempoolReadOpenError;

    fn connect(&self) -> Result<Self::Connection, Self::Error> {
        sqlite_open(&self.db_path, OpenFlags::SQLITE_OPEN_READ_ONLY, true)
            .map_err(MempoolReadOpenError::from)
    }

    fn is_valid(&self, conn: &mut Self::Connection) -> Result<(), Self::Error> {
        conn.execute_batch("SELECT 1")
            .map_err(MempoolReadOpenError::from)
    }

    fn has_broken(&self, _conn: &mut Self::Connection) -> bool {
        false
    }
}

#[derive(Debug)]
struct MempoolReadOpenError(String);

impl From<rusqlite::Error> for MempoolReadOpenError {
    fn from(error: rusqlite::Error) -> Self {
        Self(error.to_string())
    }
}

impl fmt::Display for MempoolReadOpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for MempoolReadOpenError {}

#[cfg(test)]
mod tests {
    use stacks::burnchains::Txid;

    use super::MempoolReadService;
    use crate::config::MempoolReadSpec;
    use crate::error::{ApiError, ApiErrorCode};

    #[test]
    fn missing_database_is_not_reported_as_pool_saturation() {
        let chainstate_path = format!("/tmp/stacks-rpc-missing-mempool-{}", std::process::id());
        let service = MempoolReadService::open(MempoolReadSpec { chainstate_path }).unwrap();

        assert!(matches!(
            service.get_transaction(Txid([0; 32])),
            Err(ApiError::Unavailable {
                code: ApiErrorCode::MempoolUnavailable,
                ..
            })
        ));
    }
}
