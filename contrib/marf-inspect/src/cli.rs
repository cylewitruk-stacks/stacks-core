mod blocks;
mod levels;
mod manifest;
mod node;
mod plan;
mod trie;
mod walk;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
pub use levels::LevelsArgs;
pub use manifest::ManifestArgs;
pub use node::NodeArgs;
pub use plan::PlanArgs;
use rusqlite::{Connection, OpenFlags};
pub use trie::TrieArgs;
pub use walk::WalkArgs;

#[derive(Parser)]
#[command(name = "marf-inspect", about = "Inspect MARF trie databases")]
pub struct Cli {
    /// Path to the marf.sqlite database file.
    #[arg(long, short)]
    pub db: PathBuf,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// List all blocks with their blob offset, length, and whether they use external storage.
    Blocks,

    /// BFS dump of a block's trie showing per-node details.
    Trie(TrieArgs),

    /// Inspect a single node at a given byte offset within a block's blob.
    Node(NodeArgs),

    /// Inspect a pending squash-promotion plan file and its rewrite witnesses.
    Plan(PlanArgs),

    /// Show a compressed serialization manifest for a block's trie.
    /// Lists each node in BFS order with: type, Normal/Patch, patch base, diff count, size.
    Manifest(ManifestArgs),

    /// Walk the MARF trie for a given block and key, using the full MARF read API.
    /// This exercises the exact same code path as `get_block_height_of`.
    Walk(WalkArgs),

    /// List squash levels with their on-disk trailer metadata (mode, root hashes counts, etc.).
    Levels(LevelsArgs),
}

pub struct CliCtx {
    db_path: PathBuf,
    db: Connection,
    blobs_path: Option<PathBuf>,
}

impl CliCtx {
    pub fn new(db_path: &PathBuf) -> Self {
        let db = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap_or_else(|e| {
                eprintln!("Failed to open {:?}: {e}", db_path);
                std::process::exit(1);
            });

        // Detect external blobs file.
        let blobs_path = {
            let mut p = db_path.clone();
            let name = db_path.file_name().unwrap().to_string_lossy().to_string();
            p.set_file_name(format!("{name}.blobs"));
            p
        };
        let has_external_blobs = blobs_path.exists();

        Self {
            db_path: db_path.clone(),
            db,
            blobs_path: if has_external_blobs {
                Some(blobs_path)
            } else {
                None
            },
        }
    }

    pub fn db_path(&self) -> &PathBuf {
        &self.db_path
    }

    pub fn db(&self) -> &Connection {
        &self.db
    }

    pub fn blobs_path(&self) -> Option<&PathBuf> {
        self.blobs_path.as_ref()
    }
}

impl Cli {
    pub fn exec(self, ctx: &CliCtx) {
        match self.command {
            Command::Blocks => blocks::exec(ctx),
            Command::Trie(args) => trie::exec(ctx, args),
            Command::Node(args) => node::exec(ctx, args),
            Command::Plan(args) => plan::exec(ctx, args),
            Command::Manifest(args) => manifest::exec(ctx, args),
            Command::Walk(args) => walk::exec(ctx, args),
            Command::Levels(args) => levels::exec(ctx, args),
        }
    }
}
