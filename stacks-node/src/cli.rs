// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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

//! Command-line interface for `stacks-node`.
//!
//! `clap` owns syntax errors, `--help` and `--version`; every handler here returns
//! [`CliError`] so that `main` is the only place that renders errors and picks an exit code.

use std::collections::HashMap;
use std::sync::LazyLock;

use clap::{Args, Parser, Subcommand};
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::operations::leader_block_commit::RewardSetInfo;
use stacks::chainstate::coordinator::{get_next_recipients, OnChainRewardSetProvider};
use stacks::chainstate::stacks::db::blocks::DummyEventDispatcher;
use stacks::chainstate::stacks::db::StacksChainState;
use stacks::config::chain_data::MinerStats;
use stacks_common::alloc_tracker::tracking_allocator_installed;
use stacks_common::util::hash::hex_bytes;

use crate::node::{BlockMinerThread, NodeRunner, TipCandidate};
use crate::{version, Config, ConfigFile, EventDispatcher, Keychain, BIN_NAME};

/// A failure in a command handler. Argument syntax errors are reported by `clap` instead.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("Invalid config file: {0}")]
    ConfigFile(String),
    #[error("Invalid config: {0}")]
    Config(String),
    #[error("{0}")]
    Message(String),
}

/// `clap` renders `--version` as `<bin name> <version>`, so hand it the banner with the leading
/// binary name stripped. It also wants a `&'static str`, but the banner is built at runtime.
static CLAP_VERSION: LazyLock<String> = LazyLock::new(|| {
    let banner = version();
    banner
        .strip_prefix(&format!("{BIN_NAME} "))
        .unwrap_or(&banner)
        .to_string()
});

/// Run a stacks-node.
#[derive(Parser, Debug)]
#[command(name = BIN_NAME, version = CLAP_VERSION.as_str(), about, long_about = None)]
#[command(arg_required_else_help = true)]
pub struct Cli {
    /// Do not attempt to mine until the Stacks chain has synced to this block height.
    #[arg(long, global = true, value_name = "HEIGHT")]
    pub mine_at_height: Option<u64>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Start a node, either from a config of your own or on one of the public networks.
    Start(StartArgs),

    /// Validate a config file without starting up the node.
    CheckConfig(ConfigArgs),

    /// [DEPRECATED] Use `start --mainnet`.
    Mainnet,

    /// [DEPRECATED] Use `start --testnet`.
    Testnet,

    /// Display information about the current version and our release cycle.
    Version,

    /// Output the associated secret key for a burnchain signer created with a given seed.
    KeyForSeed(KeyForSeedArgs),

    /// Print the Stacks chain tip that the miner would build on.
    PickBestTip(PickBestTipArgs),

    /// Print the amount this miner would spend on its next block-commit.
    GetSpendAmount(GetSpendAmountArgs),
}

/// The network is selected by exactly one of a config file or a public-network flag. Omitting all
/// three joins mainnet.
#[derive(Args, Debug)]
#[group(required = false, multiple = false)]
pub struct StartArgs {
    /// Path of the config file. Can be used for joining a network, starting a new chain, etc.
    #[arg(long, short, value_name = "PATH")]
    pub config: Option<String>,

    /// Join and stream blocks from the public mainnet. This is the default.
    #[arg(long)]
    pub mainnet: bool,

    /// Join and stream blocks from the public testnet, relying on Bitcoin Testnet.
    #[arg(long)]
    pub testnet: bool,
}

impl StartArgs {
    fn into_config_file(self) -> Result<ConfigFile, CliError> {
        match (self.config, self.testnet) {
            (Some(config_path), _) => load_config_file(&config_path),
            (None, true) => Ok(ConfigFile::xenon()),
            // `--mainnet` and "no network selected" resolve the same way.
            (None, false) => Ok(ConfigFile::mainnet()),
        }
    }
}

#[derive(Args, Debug)]
pub struct ConfigArgs {
    /// Path of the config file.
    #[arg(long, short, value_name = "PATH")]
    pub config: String,
}

/// The seed may come from a config file *or* directly off the command line, but not both.
#[derive(Args, Debug)]
#[group(required = true, multiple = false)]
pub struct KeyForSeedArgs {
    /// Path of the config file to read `node.seed` from.
    #[arg(long, short, value_name = "PATH")]
    pub config: Option<String>,

    /// Hex-encoded seed.
    #[arg(value_name = "SEED_HEX")]
    pub seed: Option<String>,
}

#[derive(Args, Debug)]
pub struct PickBestTipArgs {
    /// Path of the config file.
    #[arg(long, short, value_name = "PATH")]
    pub config: String,

    /// Only consider tips at or below this Stacks block height.
    #[arg(long, value_name = "HEIGHT")]
    pub at_stacks_height: Option<u64>,
}

#[derive(Args, Debug)]
pub struct GetSpendAmountArgs {
    /// Path of the config file.
    #[arg(long, short, value_name = "PATH")]
    pub config: String,

    /// Compute the spend as of this Bitcoin block height.
    #[arg(long = "at-bitcoin-height", value_name = "HEIGHT")]
    pub at_burnchain_height: Option<u64>,
}

impl Cli {
    /// Dispatch the parsed command. Returns once the node shuts down for the long-running
    /// subcommands.
    pub fn run(self) -> Result<(), CliError> {
        if let Some(mine_at_height) = self.mine_at_height {
            info!("Will begin mining once Stacks chain has synced to height >= {mine_at_height}");
        }

        let config_file = match self.command {
            Command::Start(args) => args.into_config_file()?,
            Command::CheckConfig(args) => return check_config(&args.config),
            Command::Mainnet => {
                warn!("The `mainnet` subcommand is deprecated; use `start --mainnet` instead");
                ConfigFile::mainnet()
            }
            Command::Testnet => {
                warn!("The `testnet` subcommand is deprecated; use `start --testnet` instead");
                ConfigFile::xenon()
            }
            Command::Version => {
                println!("{}", version());
                return Ok(());
            }
            Command::KeyForSeed(args) => return key_for_seed(args),
            Command::PickBestTip(args) => return pick_best_tip(args),
            Command::GetSpendAmount(args) => return get_spend_amount(args, self.mine_at_height),
        };

        run_node(config_file)
    }
}

fn load_config_file(config_path: &str) -> Result<ConfigFile, CliError> {
    info!("Loading config at path {config_path}");
    ConfigFile::from_path(config_path).map_err(|error| CliError::ConfigFile(error.to_string()))
}

fn load_node_config(config_path: &str) -> Result<Config, CliError> {
    Config::from_config_file(load_config_file(config_path)?, true)
        .map_err(|error| CliError::Config(error.to_string()))
}

/// Implementation of the `check-config` subcommand.
fn check_config(config_path: &str) -> Result<(), CliError> {
    let config_file = load_config_file(config_path)?;
    debug!("Loaded config file: {config_file:?}");
    Config::from_config_file(config_file, true)
        .map_err(|error| CliError::Config(error.to_string()))?;
    info!("Loaded config!");
    Ok(())
}

/// Implementation of the `key-for-seed` subcommand.
fn key_for_seed(args: KeyForSeedArgs) -> Result<(), CliError> {
    let seed = match (args.config, args.seed) {
        (Some(config_path), _) => load_node_config(&config_path)?.node.seed,
        (None, Some(seed_hex)) => hex_bytes(&seed_hex)
            .map_err(|error| CliError::Message(format!("Seed should be a hex string: {error}")))?,
        (None, None) => {
            return Err(CliError::Message(
                "`key-for-seed` must be passed either a config file via `--config` or a hex seed"
                    .into(),
            ))
        }
    };

    let keychain = Keychain::default(seed);
    println!(
        "Hex formatted secret key: {}",
        keychain.generate_op_signer().get_secret_key_as_hex()
    );
    println!(
        "WIF formatted secret key: {}",
        keychain.generate_op_signer().get_secret_key_as_wif()
    );
    Ok(())
}

/// Implementation of the `pick-best-tip` subcommand.
fn pick_best_tip(args: PickBestTipArgs) -> Result<(), CliError> {
    let config = load_node_config(&args.config)?;
    let burn_db_path = config.get_burn_db_file_path();
    let stacks_chainstate_path = config.get_chainstate_path_str();
    let burnchain = config.get_burnchain();
    let (mut chainstate, _) = StacksChainState::open(
        config.is_mainnet(),
        config.burnchain.chain_id,
        &stacks_chainstate_path,
        Some(config.node.get_marf_opts()),
    )
    .unwrap();
    let mut sortdb = SortitionDB::open(
        &burn_db_path,
        false,
        burnchain.pox_constants,
        Some(config.node.get_marf_opts()),
    )
    .unwrap();

    let max_depth = config.miner.max_reorg_depth;

    // There could be more than one possible chain tip. Go find them.
    let stacks_tips = BlockMinerThread::load_candidate_tips(
        &mut sortdb,
        &mut chainstate,
        max_depth,
        args.at_stacks_height,
    );

    let best_tip: TipCandidate =
        BlockMinerThread::inner_pick_best_tip(stacks_tips, HashMap::new()).unwrap();
    println!("Best tip is {best_tip:?}");
    Ok(())
}

/// Implementation of the `get-spend-amount` subcommand.
#[allow(clippy::incompatible_msrv)]
fn get_spend_amount(args: GetSpendAmountArgs, mine_start: Option<u64>) -> Result<(), CliError> {
    let at_burnchain_height = args.at_burnchain_height;
    let config = load_node_config(&args.config)?;
    let keychain = Keychain::default(config.node.seed.clone());
    let burn_db_path = config.get_burn_db_file_path();
    let stacks_chainstate_path = config.get_chainstate_path_str();
    let burnchain = config.get_burnchain();
    let (mut chainstate, _) = StacksChainState::open(
        config.is_mainnet(),
        config.burnchain.chain_id,
        &stacks_chainstate_path,
        Some(config.node.get_marf_opts()),
    )
    .unwrap();
    let mut sortdb = SortitionDB::open(
        &burn_db_path,
        true,
        burnchain.pox_constants.clone(),
        Some(config.node.get_marf_opts()),
    )
    .unwrap();
    let tip = if let Some(at_burnchain_height) = at_burnchain_height {
        let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
        let ih = sortdb.index_handle(&tip.sortition_id);
        ih.get_block_snapshot_by_height(at_burnchain_height)
            .unwrap()
            .unwrap()
    } else {
        SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap()
    };

    let no_dispatcher: Option<&DummyEventDispatcher> = None;
    let recipients = get_next_recipients(
        &tip,
        &mut chainstate,
        &mut sortdb,
        &burnchain,
        &OnChainRewardSetProvider(no_dispatcher),
    )
    .unwrap();

    let commit_outs = RewardSetInfo::commit_outs_for(
        recipients,
        burnchain.is_in_prepare_phase(tip.block_height + 1),
        config.is_mainnet(),
    );

    let spend_amount = BlockMinerThread::get_mining_spend_amount(
        &config,
        &keychain,
        &burnchain,
        &sortdb,
        &commit_outs,
        mine_start.unwrap_or(tip.block_height),
        at_burnchain_height,
        |burn_block_height| {
            let sortdb = SortitionDB::open(
                &burn_db_path,
                true,
                burnchain.pox_constants.clone(),
                Some(config.node.get_marf_opts()),
            )
            .unwrap();
            let Some(miner_stats) = config.get_miner_stats() else {
                return 0.0;
            };
            let Ok(active_miners_and_commits) =
                MinerStats::get_active_miners(&sortdb, Some(burn_block_height))
                    .inspect_err(|e| warn!("Failed to get active miners: {e:?}"))
            else {
                return 0.0;
            };
            if active_miners_and_commits.is_empty() {
                warn!("No active miners detected; using config file burn_fee_cap");
                return 0.0;
            }

            let active_miners: Vec<_> = active_miners_and_commits
                .iter()
                .map(|(miner, _cmt)| miner.as_str())
                .collect();

            info!("Active miners: {active_miners:?}");

            let Ok(unconfirmed_block_commits) = miner_stats
                .get_unconfirmed_commits(burn_block_height + 1, &active_miners)
                .inspect_err(|e| warn!("Failed to find unconfirmed block-commits: {e}"))
            else {
                return 0.0;
            };

            let unconfirmed_miners_and_amounts: Vec<(String, u64)> = unconfirmed_block_commits
                .iter()
                .map(|cmt| (format!("{}", &cmt.apparent_sender), cmt.burn_fee))
                .collect();

            info!("Found unconfirmed block-commits: {unconfirmed_miners_and_amounts:?}");

            let (spend_dist, _total_spend) = MinerStats::get_spend_distribution(
                &active_miners_and_commits,
                &unconfirmed_block_commits,
                &commit_outs,
            );
            let win_probs = if config.miner.fast_rampup {
                // look at spends 6+ blocks in the future
                MinerStats::get_future_win_distribution(
                    &active_miners_and_commits,
                    &unconfirmed_block_commits,
                    &commit_outs,
                )
            } else {
                // look at the current spends
                let Ok(unconfirmed_burn_dist) = miner_stats
                    .get_unconfirmed_burn_distribution(
                        &burnchain,
                        &sortdb,
                        &active_miners_and_commits,
                        unconfirmed_block_commits,
                        &commit_outs,
                        at_burnchain_height,
                    )
                    .inspect_err(|e| warn!("Failed to get unconfirmed burn distribution: {e:?}"))
                else {
                    return 0.0;
                };

                MinerStats::burn_dist_to_prob_dist(&unconfirmed_burn_dist)
            };

            info!("Unconfirmed spend distribution: {spend_dist:?}");
            info!(
                "Unconfirmed win probabilities (fast_rampup={}): {win_probs:?}",
                config.miner.fast_rampup
            );

            let miner_addrs = BlockMinerThread::get_miner_addrs(&config, &keychain);
            let win_prob = miner_addrs
                .iter()
                .find_map(|x| win_probs.get(x))
                .copied()
                .unwrap_or(0.0);

            info!(
                "This miner's win probability at {} is {win_prob}",
                tip.block_height
            );
            win_prob
        },
        |_burn_block_height, _win_prob| {},
    );

    println!("Will spend {spend_amount}");
    Ok(())
}

/// Boot the node from an already-resolved config file. Blocks until shutdown.
fn run_node(config_file: ConfigFile) -> Result<(), CliError> {
    let conf = Config::from_config_file(config_file, true)
        .map_err(|error| CliError::Config(error.to_string()))?;

    debug!("node configuration {:?}", &conf.node);
    debug!("burnchain configuration {:?}", &conf.burnchain);
    debug!("connection configuration {:?}", &conf.connection_options);

    send_pending_event_payloads(&conf);

    NodeRunner::validate_mode(&conf.burnchain.mode).map_err(CliError::Message)?;

    if (conf.miner.max_assembly_mem_bytes > 0
        || conf.connection_options.block_proposal_max_tx_mem_bytes > 0
        || conf.connection_options.read_only_call_max_mem_bytes > 0)
        && !tracking_allocator_installed()
    {
        return Err(CliError::Message(
            "Tracking allocator must be installed to set a memory limit".into(),
        ));
    }

    let mut node_runner = NodeRunner::new(conf).map_err(CliError::Message)?;
    node_runner.start(None, 0);
    Ok(())
}

/// If the previous session was terminated before all the pending events had been sent,
/// the DB will still contain them. Work through that before doing anything new.
/// Pending events for observers that are no longer registered will be discarded.
fn send_pending_event_payloads(conf: &Config) {
    // This dispatcher gets a queue size of 0 to ensure that it blocks. Technically
    // process_pending_payloads() always blocks; this is just an additional safeguard.
    let mut event_dispatcher =
        EventDispatcher::new_with_custom_queue_size(conf.get_working_dir(), 0);
    for observer in &conf.events_observers {
        event_dispatcher.register_observer(observer);
    }
    event_dispatcher.process_pending_payloads();
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use clap::error::ErrorKind;
    use clap::CommandFactory as _;

    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(args)
    }

    fn parse_err(args: &[&str]) -> ErrorKind {
        parse(args).expect_err("expected a parse failure").kind()
    }

    #[test]
    fn verify_cli_structure() {
        Cli::command().debug_assert();
    }

    #[test]
    fn bare_invocation_is_a_usage_error() {
        assert_eq!(
            parse_err(&["stacks-node"]),
            ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        );
    }

    #[test]
    fn unknown_subcommand_is_rejected() {
        assert_eq!(
            parse_err(&["stacks-node", "replay-mock-mining"]),
            ErrorKind::InvalidSubcommand
        );
    }

    #[test]
    fn unknown_flag_is_rejected() {
        // pico-args silently discarded these
        assert_eq!(
            parse_err(&[
                "stacks-node",
                "start",
                "--config",
                "c.toml",
                "--mine-at-heigth",
                "1"
            ]),
            ErrorKind::UnknownArgument
        );
    }

    #[test]
    fn help_and_version_flags_are_available() {
        assert_eq!(
            parse_err(&["stacks-node", "--help"]),
            ErrorKind::DisplayHelp
        );
        assert_eq!(
            parse_err(&["stacks-node", "--version"]),
            ErrorKind::DisplayVersion
        );
        assert_eq!(
            parse_err(&["stacks-node", "start", "--help"]),
            ErrorKind::DisplayHelp
        );
    }

    /// `start` selects a network with at most one of `--config`, `--mainnet` or `--testnet`.
    #[test]
    fn start_network_sources_are_mutually_exclusive() {
        for argv in [
            &["stacks-node", "start", "--config", "c.toml", "--mainnet"][..],
            &["stacks-node", "start", "--config", "c.toml", "--testnet"][..],
            &["stacks-node", "start", "--mainnet", "--testnet"][..],
        ] {
            assert_eq!(
                parse_err(argv),
                ErrorKind::ArgumentConflict,
                "expected a conflict for {argv:?}"
            );
        }
    }

    /// Bare `start` joins mainnet, matching the deprecated `mainnet` subcommand.
    #[test]
    fn start_defaults_to_mainnet() {
        for argv in [
            &["stacks-node", "start"][..],
            &["stacks-node", "start", "--mainnet"][..],
        ] {
            let Command::Start(args) = parse(argv).unwrap().command else {
                panic!("expected Start for {argv:?}");
            };
            assert!(args.config.is_none());
            assert!(!args.testnet);
        }
    }

    #[test]
    fn config_flag_has_a_short_form() {
        let Command::Start(args) = parse(&["stacks-node", "start", "-c", "c.toml"])
            .unwrap()
            .command
        else {
            panic!("expected Start");
        };
        assert_eq!(args.config.as_deref(), Some("c.toml"));
    }

    /// `clap` prepends the binary name, so `CLAP_VERSION` must not carry it too.
    #[test]
    fn rendered_version_matches_the_version_subcommand() {
        assert_eq!(
            Cli::command().render_version().trim_end(),
            version(),
            "`--version` must render exactly what the `version` subcommand prints"
        );
    }

    #[test]
    fn check_config_requires_config() {
        assert_eq!(
            parse_err(&["stacks-node", "check-config"]),
            ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn every_subcommand_parses() {
        let cases: Vec<(&[&str], fn(&Command) -> bool)> = vec![
            // Deprecated, but still accepted.
            (&["stacks-node", "mainnet"], |c| {
                matches!(c, Command::Mainnet)
            }),
            (&["stacks-node", "testnet"], |c| {
                matches!(c, Command::Testnet)
            }),
            (&["stacks-node", "version"], |c| {
                matches!(c, Command::Version)
            }),
            (
                &["stacks-node", "start", "--config", "c.toml"],
                |c| matches!(c, Command::Start(a) if a.config.as_deref() == Some("c.toml")),
            ),
            (
                &["stacks-node", "start", "--testnet"],
                |c| matches!(c, Command::Start(a) if a.testnet),
            ),
            (
                &["stacks-node", "check-config", "--config", "c.toml"],
                |c| matches!(c, Command::CheckConfig(a) if a.config == "c.toml"),
            ),
            (
                &["stacks-node", "key-for-seed", "aabbcc"],
                |c| matches!(c, Command::KeyForSeed(a) if a.seed.as_deref() == Some("aabbcc")),
            ),
            (
                &[
                    "stacks-node",
                    "pick-best-tip",
                    "--config",
                    "c.toml",
                    "--at-stacks-height",
                    "7",
                ],
                |c| matches!(c, Command::PickBestTip(a) if a.at_stacks_height == Some(7)),
            ),
            (
                &[
                    "stacks-node",
                    "get-spend-amount",
                    "--config",
                    "c.toml",
                    "--at-bitcoin-height",
                    "9",
                ],
                |c| matches!(c, Command::GetSpendAmount(a) if a.at_burnchain_height == Some(9)),
            ),
        ];

        for (argv, check) in cases {
            let cli = parse(argv).unwrap_or_else(|e| panic!("failed to parse {argv:?}: {e}"));
            assert!(check(&cli.command), "unexpected command for {argv:?}");
        }
    }

    #[test]
    fn mine_at_height_is_accepted_on_either_side_of_the_subcommand() {
        // pico-args was position-insensitive; `--mine-at-height` is documented in the
        // changelog as a root-level flag, so both forms must keep working.
        for argv in [
            [
                "stacks-node",
                "--mine-at-height",
                "42",
                "start",
                "--config",
                "c.toml",
            ],
            [
                "stacks-node",
                "start",
                "--config",
                "c.toml",
                "--mine-at-height",
                "42",
            ],
        ] {
            let cli = parse(&argv).unwrap_or_else(|e| panic!("failed to parse {argv:?}: {e}"));
            assert_eq!(cli.mine_at_height, Some(42));
        }
    }

    #[test]
    fn key_for_seed_sources_are_mutually_exclusive() {
        assert!(parse(&["stacks-node", "key-for-seed", "--config", "c.toml"]).is_ok());
        assert!(parse(&["stacks-node", "key-for-seed", "aabbcc"]).is_ok());
        assert_eq!(
            parse_err(&["stacks-node", "key-for-seed"]),
            ErrorKind::MissingRequiredArgument
        );
        assert_eq!(
            parse_err(&[
                "stacks-node",
                "key-for-seed",
                "--config",
                "c.toml",
                "aabbcc"
            ]),
            ErrorKind::ArgumentConflict
        );
    }

    #[test]
    fn reports_missing_burnchain_mode() {
        let mut config_file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            config_file,
            "[node]\nworking_dir = \"/tmp/stacks-node-config-loader-test\""
        )
        .unwrap();

        let error = load_node_config(config_file.path().to_str().unwrap())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("Setting burnchain.mode is required"),
            "unexpected configuration error: {error}"
        );
    }

    #[test]
    fn reports_missing_config_file() {
        let error = load_node_config("/nonexistent/stacks-node-config.toml")
            .unwrap_err()
            .to_string();
        assert!(
            error.starts_with("Invalid config file:"),
            "unexpected configuration error: {error}"
        );
    }
}
