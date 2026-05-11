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

mod cli;
mod types;
mod util;

use clap::Parser;
use cli::{Cli, Command};

use crate::cli::CliCtx;

fn main() {
    let cli = Cli::parse();

    // `trim-history` is the only subcommand that mutates the DB and
    // opens its own writable [`MARF`] handle internally. Skip the
    // read-only [`CliCtx`] so we don't hold a stale `Connection`
    // against the path while the MARF's writable open path runs
    // recovery and the SQL trim flip.
    if let Command::TrimHistory(args) = cli.command {
        cli::trim_history_exec(&cli.db, args);
        return;
    }

    let ctx = CliCtx::new(&cli.db);
    cli.exec(&ctx);
}
