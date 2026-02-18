// Copyright (C) 2026 Stacks Open Internet Foundation
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

mod allocator;
mod node_alloc;
mod read;
mod write;

/// Print usage/help for the `marf-alloc` harness.
#[rustfmt::skip]
fn print_usage() {
    println!("marf-alloc: MARF allocation/timing profilers");
    println!();
    println!("Usage:");
    println!("  cargo bench -p stackslib --bench marf-alloc -- <subcommand> [--help]");
    println!();
    println!("Subcommands:");
    println!("  node-alloc    Node micro-allocation profile");
    println!("  read          Read-heavy MARF::get profile");
    println!("  write         Write workflow profile");
}

/// Main entry point for the `marf-alloc` harness, which dispatches to the appropriate subcommand
fn main() {
    // SAFETY: This is the first thing we do in the process, before any
    // potential threads are spawned or any FFI into C libraries that might read
    // the environment.
    unsafe {
        std::env::set_var("STACKS_LOG_CRITONLY", "1");
    }

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage();
        return;
    }

    let cmd = args[1].as_str();
    let sub_args = &args[2..];

    match cmd {
        "node-alloc" => node_alloc::run(sub_args),
        "read" => read::run(sub_args),
        "write" => write::run(sub_args),
        "-h" | "--help" | "help" => print_usage(),
        _ => {
            eprintln!("Unknown subcommand: {cmd}");
            print_usage();
            std::process::exit(2);
        }
    }
}
