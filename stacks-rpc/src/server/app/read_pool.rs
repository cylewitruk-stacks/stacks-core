use std::time::Duration;

use r2d2::{ManageConnection, Pool};

pub const DEFAULT_READ_POOL_SIZE: u32 = 4;
pub const READ_POOL_CHECKOUT_TIMEOUT: Duration = Duration::from_millis(100);
pub const READ_POOL_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

pub fn build_eager_pool<M>(
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

pub fn build_lazy_pool<M>(manager: M, pool_size: u32) -> Pool<M>
where
    M: ManageConnection,
{
    Pool::builder()
        .max_size(pool_size)
        .min_idle(Some(0))
        .idle_timeout(None)
        .max_lifetime(None)
        .test_on_check_out(false)
        .error_handler(Box::new(r2d2::NopErrorHandler))
        .build_unchecked(manager)
}
