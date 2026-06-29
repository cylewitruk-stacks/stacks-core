use std::io;
use std::net::SocketAddr;
use std::thread::{self, JoinHandle};

use stacks::net::rpc_domains::{domain_channels, RpcDomainChannels, RpcDomainReceivers};
use stacks::net::rpc_services::RpcServiceResult;

use crate::chainstate_read::ChainstateReadService;
use crate::config::AxumRpcConfig;
use crate::routes::router;

pub struct PreparedAxumRpcServer {
    bind_addr: SocketAddr,
    channels: RpcDomainChannels,
    chainstate_reads: ChainstateReadService,
    auth_token: Option<String>,
}

impl PreparedAxumRpcServer {
    pub fn spawn(self) {
        if let Err(e) = spawn_axum_rpc_server(
            self.bind_addr,
            self.channels,
            self.chainstate_reads,
            self.auth_token,
        ) {
            warn!("Failed to spawn experimental Axum RPC server: {e}");
        }
    }
}

pub fn prepare_axum_rpc_server(
    config: AxumRpcConfig,
) -> RpcServiceResult<(PreparedAxumRpcServer, RpcDomainReceivers)> {
    let chainstate_reads = ChainstateReadService::open(config.chainstate_read)?;
    let (channels, receivers) = domain_channels();
    Ok((
        PreparedAxumRpcServer {
            bind_addr: config.bind_addr,
            channels,
            chainstate_reads,
            auth_token: config.auth_token,
        },
        receivers,
    ))
}

pub fn spawn_axum_rpc_server(
    bind_addr: SocketAddr,
    domains: RpcDomainChannels,
    chainstate_reads: ChainstateReadService,
    auth_token: Option<String>,
) -> io::Result<JoinHandle<()>> {
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
                let listener = match tokio::net::TcpListener::bind(bind_addr).await {
                    Ok(listener) => listener,
                    Err(e) => {
                        error!("Failed to bind Axum RPC server on {bind_addr}: {e}");
                        return;
                    }
                };
                info!("Start experimental Axum RPC server on: {bind_addr}");

                if let Err(e) =
                    axum::serve(listener, router(domains, chainstate_reads, auth_token)).await
                {
                    error!("Axum RPC server failed: {e}");
                }
            });
        })
}
