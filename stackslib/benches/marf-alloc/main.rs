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
mod read_backptr;
mod utils;
mod write;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputMode {
    Summary,
    Raw,
}

impl OutputMode {
    fn is_raw(self) -> bool {
        matches!(self, Self::Raw)
    }
}

#[derive(Clone, Debug)]
struct SummaryLine {
    pub name: String,
    pub total_ms: f64,
    pub alloc_count: u64,
    pub alloc_bytes: u64,
}

#[derive(Clone, Debug)]
struct Summary {
    pub title: &'static str,
    pub lines: Vec<SummaryLine>,
}

impl Summary {
    fn new(title: &'static str, capacity: usize) -> Self {
        Self {
            title,
            lines: Vec::with_capacity(capacity),
        }
    }

    fn push_line(
        &mut self,
        name: impl Into<String>,
        total_ms: f64,
        alloc_count: u64,
        alloc_bytes: u64,
    ) {
        self.lines.push(SummaryLine {
            name: name.into(),
            total_ms,
            alloc_count,
            alloc_bytes,
        });
    }
}

fn parse_output_mode() -> OutputMode {
    match std::env::var("MARF_ALLOC_OUTPUT").ok().as_deref() {
        Some("raw") => OutputMode::Raw,
        _ => OutputMode::Summary,
    }
}

fn print_summary(summary: &Summary) {
    println!("summary\tbenchmark\tname\ttotal_ms\talloc_count\talloc_bytes");
    for line in &summary.lines {
        println!(
            "summary\t{}\t{}\t{:.3}\t{}\t{}",
            summary.title, line.name, line.total_ms, line.alloc_count, line.alloc_bytes
        );
    }
}

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
    println!("  read-backptr  Focused deep backpointer-walk MARF::get profile");
    println!("  write         Write workflow profile");
    println!();
    println!("Environment variables:");
    println!("  MARF_ALLOC_OUTPUT");
    println!("                output mode [default: summary]");
    println!("                  - 'summary': emit unified summary rows only");
    println!("                  - 'raw': emit detailed benchmark output + unified summary rows");
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
    let output_mode = parse_output_mode();

    let summary = match cmd {
        "node-alloc" => node_alloc::run(sub_args, output_mode),
        "read" => read::run(sub_args, output_mode),
        "read-backptr" => read_backptr::run(sub_args, output_mode),
        "write" => write::run(sub_args, output_mode),
        "-h" | "--help" | "help" => {
            print_usage();
            None
        }
        _ => {
            eprintln!("Unknown subcommand: {cmd}");
            print_usage();
            std::process::exit(2);
        }
    };

    if let Some(summary) = summary {
        print_summary(&summary);
    }
}
