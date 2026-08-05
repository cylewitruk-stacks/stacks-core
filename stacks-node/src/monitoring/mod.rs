#![allow(unused_variables)]

use stacks::burnchains::BurnchainSigner;
use stacks_common::types::StacksEpochId;

use crate::{BitcoinRegtestController, Keychain};

#[cfg(feature = "monitoring_prom")]
mod prometheus;

#[derive(Debug)]
pub enum MonitoringError {
    #[cfg(feature = "monitoring_prom")]
    AlreadyBound,
    #[cfg(feature = "monitoring_prom")]
    UnableToGetAddress,
}

#[cfg(feature = "monitoring_prom")]
pub fn start_serving_monitoring_metrics(bind_address: String) -> Result<(), MonitoringError> {
    prometheus::start_serving_prometheus_metrics(bind_address)
}

#[cfg(not(feature = "monitoring_prom"))]
pub fn start_serving_monitoring_metrics(bind_address: String) -> Result<(), MonitoringError> {
    warn!("Attempted to start monitoring service at bind_address = {bind_address}, but stacks-node was built without `monitoring_prom` feature.");
    Ok(())
}

/// Report the miner's Epoch 2.1 burnchain address through the monitoring subsystem.
pub fn set_burnchain_signer(keychain: &Keychain, controller: &BitcoinRegtestController) {
    let public_key = keychain.get_pub_key();
    let miner_address = controller.get_miner_address(StacksEpochId::Epoch21, &public_key);
    let signer = BurnchainSigner(miner_address.to_string());

    let _ = stacks::monitoring::set_burnchain_signer(signer).map_err(|error| {
        warn!("Failed to set global burnchain signer: {error:?}");
        error
    });
}
