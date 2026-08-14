// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2024 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::net::SocketAddr;
use std::thread;
use std::time::{Duration, Instant};

use clarity::util::hash::to_hex;
use clarity::util::secp256k1::Secp256k1PublicKey;
use libsigner::VERSION_STRING;
use stacks_common::{debug, error, info, warn};
use tiny_http::{Response as HttpResponse, Server as HttpServer};

use super::actions::{update_reward_cycle, update_signer_stx_balance};
use crate::client::{ClientError, StacksClient};
use crate::config::{GlobalConfig, Network};
use crate::monitoring::actions::{update_signer_nonce, update_stacks_tip_height};
use crate::monitoring::prometheus::gather_metrics_string;

/// Chain height is cheap, operationally important, and changes much more
/// frequently than reward-set/account metadata. Keep it close to the actor
/// agent's scrape cadence without multiplying the slower RPC load.
const NODE_TIP_POLL_INTERVAL: Duration = Duration::from_secs(10);
const ACCOUNT_METADATA_POLL_INTERVAL: Duration = Duration::from_secs(60);
/// Monitoring must continue serving its last known-good snapshot while its
/// companion is paused or unreachable.
const MONITORING_RPC_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(thiserror::Error, Debug)]
#[allow(clippy::large_enum_variant)]
/// Monitoring server errors
pub enum MonitoringError {
    /// Already bound to an address
    #[error("Already bound to an address")]
    AlreadyBound,
    /// Server terminated
    #[error("Server terminated")]
    Terminated,
    /// No endpoint configured
    #[error("Prometheus endpoint not configured.")]
    EndpointNotConfigured,
    /// Error fetching metrics from stacks node
    #[error("Error fetching data from stacks node: {0}")]
    FetchError(#[from] ClientError),
}

/// Metrics and monitoring server
pub struct MonitoringServer {
    http_server: HttpServer,
    local_addr: SocketAddr,
    network: Network,
    public_key: Secp256k1PublicKey,
    stx_address: String,
    stacks_node_client: reqwest::blocking::Client,
    stacks_node_origin: String,
}

impl MonitoringServer {
    pub fn new(
        http_server: HttpServer,
        local_addr: SocketAddr,
        network: Network,
        public_key: Secp256k1PublicKey,
        stx_address: String,
        stacks_node_origin: String,
        stacks_node_client: reqwest::blocking::Client,
    ) -> Self {
        Self {
            http_server,
            local_addr,
            network,
            public_key,
            stx_address,
            stacks_node_client,
            stacks_node_origin,
        }
    }

    /// Start and run the metrics server
    pub fn start(config: &GlobalConfig) -> Result<(), MonitoringError> {
        let Some(endpoint) = config.metrics_endpoint else {
            return Err(MonitoringError::EndpointNotConfigured);
        };
        let stacks_client =
            StacksClient::from(config).with_request_timeout(MONITORING_RPC_REQUEST_TIMEOUT)?;
        let stacks_node_client = reqwest::blocking::Client::builder()
            .timeout(MONITORING_RPC_REQUEST_TIMEOUT)
            .build()
            .map_err(ClientError::from)?;
        let http_server = HttpServer::http(endpoint).map_err(|_| MonitoringError::AlreadyBound)?;
        let public_key = Secp256k1PublicKey::from_private(&config.stacks_private_key);
        let stx_address = stacks_client.get_signer_address().to_string();
        let mut server = MonitoringServer::new(
            http_server,
            endpoint,
            config.network.clone(),
            public_key,
            stx_address,
            format!("http://{}", config.node_host),
            stacks_node_client,
        );
        if let Err(e) = update_metrics(&stacks_client) {
            warn!(
                "Monitoring: Error updating metrics when starting server: {:?}",
                e
            );
        };
        start_metrics_refresher(stacks_client);
        server.main_loop()
    }

    // /// Start and run the metrics server
    // pub fn run(endpoint: SocketAddr, stacks_client: StacksClient) -> Result<(), MonitoringError> {
    //     let http_server = HttpServer::http(endpoint).map_err(|_| MonitoringError::AlreadyBound)?;
    //     let mut server = PrometheusMetrics::new(http_server, endpoint, stacks_client);
    //     server.main_loop()
    // }

    /// Main listener loop of metrics server
    pub fn main_loop(&mut self) -> Result<(), MonitoringError> {
        info!("{}: Starting Prometheus metrics server", self);
        loop {
            let request = match self.http_server.recv() {
                Ok(request) => request,
                Err(err) => {
                    error!("Monitoring: Error receiving request: {:?}", err);
                    return Err(MonitoringError::Terminated);
                }
            };

            debug!("{}: received request {}", self, request.url());

            if request.url() == "/metrics" {
                let response = HttpResponse::from_string(gather_metrics_string());
                request.respond(response).expect("Failed to send response");
                continue;
            }

            if request.url() == "/info" {
                request
                    .respond(HttpResponse::from_string(self.get_info_response()))
                    .expect("Failed to respond to request");
                continue;
            }

            // return 200 OK for "/"
            if request.url() == "/" {
                request
                    .respond(HttpResponse::from_string("OK"))
                    .expect("Failed to respond to request");
                continue;
            }

            // Run heartbeat check to test connection to the node
            if request.url() == "/heartbeat" {
                let (msg, status) = if self.heartbeat() {
                    ("OK", 200)
                } else {
                    ("Failed", 500)
                };
                request
                    .respond(HttpResponse::from_string(msg).with_status_code(status))
                    .expect("Failed to respond to request");
                continue;
            }

            // unknown request, return 404
            request
                .respond(HttpResponse::from_string("Not Found").with_status_code(404))
                .expect("Failed to respond to request");
        }
    }

    /// Build a JSON response for non-metrics requests
    fn get_info_response(&self) -> String {
        // let public_key = Secp256k1PublicKey::from_private(&self.stacks_client.publ);
        serde_json::to_string(&serde_json::json!({
            "signerPublicKey": to_hex(&self.public_key.to_bytes_compressed()),
            "network": self.network.to_string(),
            "stxAddress": self.stx_address,
            "version": VERSION_STRING.to_string(),
        }))
        .expect("Failed to serialize JSON")
    }

    /// Poll the Stacks node's `v2/info` endpoint to validate the connection
    fn heartbeat(&self) -> bool {
        let url = format!("{}/v2/info", self.stacks_node_origin);
        let response = self.stacks_node_client.get(url).send();
        match response {
            Ok(response) => {
                if response.status().is_success() {
                    true
                } else {
                    warn!(
                        "Monitoring: Heartbeat failed with status: {}",
                        response.status()
                    );
                    false
                }
            }
            Err(err) => {
                warn!("Monitoring: Heartbeat failed with error: {:?}", err);
                false
            }
        }
    }
}

/// Keep collection isolated from HTTP serving. A stalled companion may delay a
/// refresh up to the bounded RPC timeout, but it must never delay a federation
/// scrape of the last known-good process metrics.
fn start_metrics_refresher(stacks_client: StacksClient) {
    thread::Builder::new()
        .name("signer_metrics_refresh".to_owned())
        .spawn(move || {
            let mut last_node_tip_poll = Instant::now();
            let mut last_account_metadata_poll = Instant::now();
            loop {
                let now = Instant::now();
                if now.duration_since(last_node_tip_poll) >= NODE_TIP_POLL_INTERVAL {
                    last_node_tip_poll = now;
                    if let Err(error) = update_node_tip(&stacks_client) {
                        error!("Monitoring: Error refreshing node-tip metrics: {error:?}");
                    }
                }
                if now.duration_since(last_account_metadata_poll) >= ACCOUNT_METADATA_POLL_INTERVAL
                {
                    last_account_metadata_poll = now;
                    if let Err(error) = update_account_metadata(&stacks_client) {
                        error!("Monitoring: Error refreshing account metrics: {error:?}");
                    }
                }
                thread::sleep(Duration::from_millis(250));
            }
        })
        .expect("Failed to start signer metrics refresh thread");
}

/// Populate all companion-derived gauges once before the independent refresher
/// starts. Errors leave their previous/default value in place.
fn update_metrics(stacks_client: &StacksClient) -> Result<(), MonitoringError> {
    debug!("Updating signer companion-derived metrics");
    update_node_tip(stacks_client)?;
    update_account_metadata(stacks_client)
}

fn update_node_tip(stacks_client: &StacksClient) -> Result<(), MonitoringError> {
    let peer_info = stacks_client.get_peer_info()?;
    if let Ok(height) = i64::try_from(peer_info.stacks_tip_height) {
        update_stacks_tip_height(height);
    } else {
        warn!(
            "Failed to parse stacks tip height: {}",
            peer_info.stacks_tip_height
        );
    }
    Ok(())
}

fn update_account_metadata(stacks_client: &StacksClient) -> Result<(), MonitoringError> {
    let pox_info = stacks_client.get_pox_data()?;
    if let Ok(reward_cycle) = i64::try_from(pox_info.reward_cycle_id) {
        update_reward_cycle(reward_cycle);
    }
    let signer_stx_addr = stacks_client.get_signer_address();
    let account_entry = stacks_client.get_account_entry(signer_stx_addr)?;
    let balance = i64::from_str_radix(&account_entry.balance[2..], 16).map_err(|e| {
        MonitoringError::FetchError(ClientError::MalformedClarityValue(format!(
            "Failed to parse balance: {} with err: {}",
            &account_entry.balance, e,
        )))
    })?;
    update_signer_nonce(account_entry.nonce);
    update_signer_stx_balance(balance);
    Ok(())
}

impl std::fmt::Display for MonitoringServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signer monitoring server ({})", self.local_addr)
    }
}
