use std::io;
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use axum::Router;

pub fn spawn(
    bind_addr: SocketAddr,
    app: Router,
    shutdown_signal: Option<Arc<AtomicBool>>,
) -> io::Result<JoinHandle<()>> {
    let listener = TcpListener::bind(bind_addr)?;
    listener.set_nonblocking(true)?;

    thread::Builder::new()
        .name(format!("axum-rpc:{bind_addr}"))
        .spawn(move || {
            let runtime = match tokio::runtime::Runtime::new() {
                Ok(runtime) => runtime,
                Err(e) => {
                    error!("Failed to create Axum RPC runtime: {e}");
                    return;
                }
            };

            runtime.block_on(async move {
                let listener = match tokio::net::TcpListener::from_std(listener) {
                    Ok(listener) => listener,
                    Err(e) => {
                        error!("Failed to adopt Axum RPC listener on {bind_addr}: {e}");
                        return;
                    }
                };
                info!("Start experimental Axum RPC server on: {bind_addr}");

                let server = axum::serve(listener, app)
                    .with_graceful_shutdown(wait_for_shutdown(shutdown_signal));
                if let Err(e) = server.await {
                    error!("Axum RPC server failed: {e}");
                }
            });
        })
}

async fn wait_for_shutdown(shutdown_signal: Option<Arc<AtomicBool>>) {
    let Some(shutdown_signal) = shutdown_signal else {
        std::future::pending::<()>().await;
        return;
    };

    let _ = tokio::task::spawn_blocking(move || {
        while shutdown_signal.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(100));
        }
    })
    .await;
    info!("Axum RPC shutdown signal received");
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use axum::Router;

    use super::spawn;

    #[test]
    fn spawn_returns_bind_errors_synchronously() {
        let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = occupied.local_addr().unwrap();

        assert!(spawn(addr, Router::new(), None).is_err());
    }

    #[test]
    fn server_thread_exits_on_shutdown_signal() {
        let addr = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let shutdown_signal = Arc::new(AtomicBool::new(true));
        let server = spawn(addr, Router::new(), Some(shutdown_signal.clone())).unwrap();

        shutdown_signal.store(false, Ordering::SeqCst);
        server.join().unwrap();
    }
}
