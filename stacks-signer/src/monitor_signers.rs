// Copyright (C) 2020-2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Native signer liveness monitoring. This deliberately consumes the node's
//! protected authenticated-network observation view instead of signer
//! StackerDB slots.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use clarity::types::chainstate::{StacksAddress, StacksPrivateKey, StacksPublicKey};
use clarity::util::sleep_ms;
use stacks_common::{info, warn};

use crate::cli::MonitorSignersArgs;
use crate::client::{ClientError, NativeSignerObservation, StacksClient};

/// Polls authenticated native signer observations and reports liveness gaps.
pub struct SignerMonitor {
    stacks_client: StacksClient,
    cycle_state: RewardCycleState,
    args: MonitorSignersArgs,
}

/// Cached reward-set material used to attribute authenticated observations.
#[derive(Debug, Default, Clone)]
pub struct RewardCycleState {
    signers_keys: HashMap<StacksAddress, StacksPublicKey>,
    signer_by_key: HashMap<Vec<u8>, StacksAddress>,
    signers_weights: HashMap<StacksAddress, u32>,
    reward_cycle: Option<u64>,
}

impl SignerMonitor {
    /// Connect to the configured node and construct a native signer monitor.
    pub fn new(args: MonitorSignersArgs) -> Self {
        url::Url::parse(&format!("http://{}", args.host)).expect("Failed to parse node host");
        let stacks_client = StacksClient::try_from_host(
            &StacksPrivateKey::random(),
            args.host.clone(),
            args.auth_token.clone(),
        )
        .expect("Failed to connect to provided host");
        Self {
            stacks_client,
            cycle_state: RewardCycleState::default(),
            args,
        }
    }

    fn refresh_state(&mut self) -> Result<bool, ClientError> {
        let reward_cycle = self
            .stacks_client
            .get_current_reward_cycle_info()?
            .reward_cycle;
        if Some(reward_cycle) == self.cycle_state.reward_cycle {
            return Ok(false);
        }

        let entries = self
            .stacks_client
            .get_reward_set_signers(reward_cycle)?
            .unwrap_or_else(|| panic!("No signers found for reward cycle {reward_cycle}"));
        self.cycle_state = RewardCycleState {
            reward_cycle: Some(reward_cycle),
            ..RewardCycleState::default()
        };
        for entry in entries {
            let public_key = StacksPublicKey::from_slice(&entry.signing_key)
                .expect("node returned an invalid reward-set signer key");
            let address = StacksAddress::p2pkh(self.stacks_client.mainnet, &public_key);
            self.cycle_state
                .signer_by_key
                .insert(entry.signing_key.to_vec(), address.clone());
            self.cycle_state
                .signers_weights
                .insert(address.clone(), entry.weight);
            self.cycle_state.signers_keys.insert(address, public_key);
        }
        Ok(true)
    }

    fn print_missing_signers(&self, missing: &[StacksAddress]) {
        if missing.is_empty() {
            return;
        }
        let missing_weight = missing
            .iter()
            .filter_map(|address| self.cycle_state.signers_weights.get(address))
            .sum::<u32>();
        let total_weight = self.cycle_state.signers_weights.values().sum::<u32>();
        let percentage = if total_weight == 0 {
            0.0
        } else {
            f64::from(missing_weight) / f64::from(total_weight) * 100.0
        };
        warn!(
            "Missing native BlockResponse observations for {} of {} signers ({percentage:.2}% weight, {missing_weight}/{total_weight})",
            missing.len(),
            self.cycle_state.signers_keys.len();
            "signer_addresses" => missing.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "),
        );
    }

    fn print_stale_signers(&self, stale: &[StacksAddress]) {
        if stale.is_empty() {
            return;
        }
        warn!(
            "No authenticated native BlockResponse from {} of {} signers in over {} seconds",
            stale.len(),
            self.cycle_state.signers_keys.len(),
            self.args.max_age;
            "signer_addresses" => stale.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "),
        );
    }

    fn print_unexpected_messages(
        &self,
        unexpected: &HashMap<StacksAddress, NativeSignerObservation>,
    ) {
        if unexpected.is_empty() {
            return;
        }
        warn!(
            "Observed authenticated same-sequence equivocation from {} signer(s)",
            unexpected.len();
            "observations" => unexpected.iter().map(|(address, observation)| format!(
                "address={address},peer_id={},sequence={}",
                observation.peer_id, observation.sequence
            )).collect::<Vec<_>>().join(";"),
        );
    }

    /// Poll forever, preserving missing, stale, and equivocation reporting.
    pub fn start(&mut self) -> Result<(), ClientError> {
        self.refresh_state()?;
        info!(
            "Monitoring authenticated native signer observations";
            "interval_secs" => self.args.interval,
            "max_age_secs" => self.args.max_age,
            "reward_cycle" => self.cycle_state.reward_cycle.unwrap_or_default(),
            "signer_count" => self.cycle_state.signers_keys.len(),
        );

        loop {
            if self.refresh_state()? {
                info!(
                    "Updated native signer monitoring reward set";
                    "reward_cycle" => self.cycle_state.reward_cycle.unwrap_or_default(),
                    "signer_count" => self.cycle_state.signers_keys.len(),
                );
            }

            let diagnostics = self.stacks_client.get_native_network_diagnostics()?;
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            let max_age_ms = u128::from(self.args.max_age).saturating_mul(1000);
            if diagnostics
                .snapshot_generated_unix_ms
                .is_none_or(|generated| now_ms.saturating_sub(generated) > max_age_ms)
            {
                warn!("Native signer companion observation is stale or missing");
            }

            let reward_cycle = self.cycle_state.reward_cycle.expect("reward cycle is set");
            let mut responses = HashMap::new();
            let mut unexpected = HashMap::new();
            for observation in diagnostics.signer_observations {
                // v1 lane 2 is BlockResponse. Other lanes have independent
                // liveness semantics and must not hide a missing response.
                if observation.reward_cycle != reward_cycle || observation.lane != 2 {
                    continue;
                }
                let Some(address) = self
                    .cycle_state
                    .signer_by_key
                    .get(&observation.signer_public_key)
                    .cloned()
                else {
                    continue;
                };
                if observation.equivocation {
                    unexpected.insert(address, observation.clone());
                }
                responses.insert(observation.signer_public_key.clone(), observation);
            }

            let mut missing = Vec::new();
            let mut stale = Vec::new();
            for (key, address) in &self.cycle_state.signer_by_key {
                match responses.get(key) {
                    None => missing.push(address.clone()),
                    Some(observation)
                        if now_ms.saturating_sub(observation.last_seen_unix_ms) > max_age_ms =>
                    {
                        stale.push(address.clone());
                    }
                    Some(_) => {}
                }
            }

            if missing.is_empty() && stale.is_empty() && unexpected.is_empty() {
                info!(
                    "All {} signers have fresh authenticated native BlockResponse observations",
                    self.cycle_state.signers_keys.len()
                );
            } else {
                self.print_missing_signers(&missing);
                self.print_stale_signers(&stale);
                self.print_unexpected_messages(&unexpected);
            }
            sleep_ms(self.args.interval.saturating_mul(1000));
        }
    }
}
