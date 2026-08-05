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

#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate stacks_common;

extern crate clarity;
extern crate stacks;

#[allow(unused_imports)]
#[macro_use(o, slog_log, slog_trace, slog_debug, slog_info, slog_warn, slog_error)]
extern crate slog;

pub use stacks_common::util;

mod monitoring;

mod burnchains;
mod cli;
mod event_dispatcher;
mod genesis_data;
mod keychain;
mod node;
mod operations;
mod syncctl;

use std::panic;
use std::process::{self, ExitCode};

use backtrace::Backtrace;
use clap::Parser as _;
pub use stacks::config::{Config, ConfigFile};
use stacks_common::alloc_tracker::TrackingAllocator;
#[cfg(not(any(target_os = "macos", target_os = "windows", target_arch = "arm")))]
use tikv_jemallocator::Jemalloc;

pub use self::burnchains::{BitcoinRegtestController, BurnchainTip};
pub use self::event_dispatcher::EventDispatcher;
pub use self::keychain::Keychain;
use crate::cli::Cli;

#[cfg(not(any(target_os = "macos", target_os = "windows", target_arch = "arm")))]
#[global_allocator]
static GLOBAL: TrackingAllocator<Jemalloc> = TrackingAllocator { inner: Jemalloc };

#[cfg(any(target_os = "macos", target_os = "windows", target_arch = "arm"))]
#[global_allocator]
static GLOBAL: TrackingAllocator<std::alloc::System> = TrackingAllocator {
    inner: std::alloc::System,
};

fn install_panic_hook() {
    panic::set_hook(Box::new(|panic_info| {
        error!("Process abort due to thread panic: {panic_info}");
        let bt = Backtrace::new();
        error!("Panic backtrace: {bt:?}");

        // force a core dump
        #[cfg(unix)]
        {
            let pid = process::id();
            eprintln!("Dumping core for pid {}", std::process::id());

            use libc::{kill, SIGQUIT};

            // *should* trigger a core dump, if you run `ulimit -c unlimited` first!
            unsafe { kill(pid.try_into().unwrap(), SIGQUIT) };
        }

        // just in case
        process::exit(1);
    }));
}

/// Name this binary reports in `--help`, `--version` and its version banner.
const BIN_NAME: &str = "stacks-node";

fn version() -> String {
    stacks::version_string(BIN_NAME, option_env!("STACKS_NODE_VERSION"))
}

fn main() -> ExitCode {
    // Parse before installing the hook: a bad command line is a usage error, not a crash worth
    // dumping core over.
    let cli = Cli::parse();
    install_panic_hook();

    info!("{}", version());

    match cli.run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            warn!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
pub mod tests;
