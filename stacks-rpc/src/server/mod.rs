use std::io;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread::JoinHandle;

use stacks::net::rpc_bridge::{rpc_bridge, RpcEndpoints, RpcNodeHandle};
use stacks::net::rpc_services::RpcServiceResult;

use crate::config::AxumRpcConfig;

mod app;
mod runtime;

pub struct PreparedAxumRpcServer {
    bind_addr: SocketAddr,
    node: RpcNodeHandle,
    app: app::RpcApplication,
    shutdown_signal: Option<Arc<AtomicBool>>,
}

impl PreparedAxumRpcServer {
    pub fn spawn(self) -> io::Result<JoinHandle<()>> {
        runtime::spawn(
            self.bind_addr,
            self.app.router(self.node),
            self.shutdown_signal,
        )
    }
}

pub fn prepare_axum_rpc_server(
    config: AxumRpcConfig,
) -> RpcServiceResult<(PreparedAxumRpcServer, RpcEndpoints)> {
    let (node, endpoints) = rpc_bridge();
    let app = app::RpcApplication::open(config.chainstate_read, config.auth_token)?;
    Ok((
        PreparedAxumRpcServer {
            bind_addr: config.bind_addr,
            node,
            app,
            shutdown_signal: config.shutdown_signal,
        },
        endpoints,
    ))
}
