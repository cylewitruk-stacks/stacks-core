use clap::{Args, Subcommand};

use crate::BenchKind;
use crate::runner::{BenchEnvOverrides, BenchRunRequest};

#[derive(Debug, Subcommand)]
pub enum BenchTarget {
    #[command(about = "Run all bench types")]
    All(AllArgs),
    #[command(name = "node-alloc", about = "Run node-alloc bench")]
    NodeAlloc(NodeAllocArgs),
    #[command(about = "Run read bench")]
    Read(ReadArgs),
    #[command(about = "Run write bench")]
    Write(WriteArgs),
}

impl BenchTarget {
    pub fn into_requests(self) -> Vec<BenchRunRequest> {
        match self {
            Self::All(args) => vec![
                BenchRunRequest::new(
                    BenchKind::NodeAlloc,
                    BenchEnvOverrides {
                        iters: args.iters,
                        ..Default::default()
                    },
                ),
                BenchRunRequest::new(
                    BenchKind::Read,
                    BenchEnvOverrides {
                        iters: args.iters,
                        rounds: args.rounds,
                        chain_len: args.chain_len,
                        read_proofs: Some(args.proofs),
                        keys_per_block: args.keys_per_block,
                        depths: args.depths.clone(),
                        cache_strategies: args.cache_strategies.clone(),
                        sqlite_wal_autocheckpoint: args.sqlite_wal_autocheckpoint,
                        sqlite_wal_checkpoint_mode: args.sqlite_wal_checkpoint_mode.clone(),
                        ..Default::default()
                    },
                ),
                BenchRunRequest::new(
                    BenchKind::Write,
                    BenchEnvOverrides {
                        iters: args.iters,
                        rounds: args.rounds,
                        key_updates: args.key_updates,
                        write_depths: args.write_depths.clone(),
                        sqlite_wal_autocheckpoint: args.sqlite_wal_autocheckpoint,
                        sqlite_wal_checkpoint_mode: args.sqlite_wal_checkpoint_mode.clone(),
                        key_search_max_tries: args.key_search_max_tries,
                        ..Default::default()
                    },
                ),
            ],
            Self::NodeAlloc(args) => vec![BenchRunRequest::new(
                BenchKind::NodeAlloc,
                BenchEnvOverrides {
                    iters: args.iters,
                    ..Default::default()
                },
            )],
            Self::Read(args) => vec![BenchRunRequest::new(
                BenchKind::Read,
                BenchEnvOverrides {
                    iters: args.iters,
                    rounds: args.rounds,
                    chain_len: args.chain_len,
                    read_proofs: Some(args.proofs),
                    keys_per_block: args.keys_per_block,
                    depths: args.depths,
                    cache_strategies: args.cache_strategies,
                    sqlite_wal_autocheckpoint: args.sqlite_wal_autocheckpoint,
                    sqlite_wal_checkpoint_mode: args.sqlite_wal_checkpoint_mode,
                    ..Default::default()
                },
            )],
            Self::Write(args) => vec![BenchRunRequest::new(
                BenchKind::Write,
                BenchEnvOverrides {
                    iters: args.iters,
                    rounds: args.rounds,
                    key_updates: args.key_updates,
                    write_depths: args.write_depths,
                    sqlite_wal_autocheckpoint: args.sqlite_wal_autocheckpoint,
                    sqlite_wal_checkpoint_mode: args.sqlite_wal_checkpoint_mode,
                    key_search_max_tries: args.key_search_max_tries,
                    ..Default::default()
                },
            )],
        }
    }
}

#[derive(Debug, Args)]
pub struct AllArgs {
    #[arg(long, help = "Set ITERS for benches that use per-case pub count")]
    iters: Option<usize>,

    #[arg(
        long,
        help = "Set ROUNDS for benches that use repeated case/workflow runs"
    )]
    rounds: Option<usize>,

    #[arg(long, help = "Set CHAIN_LEN for read fixture length")]
    chain_len: Option<u32>,

    #[arg(long, help = "Enable proofed reads (MARF::get_with_proof) for read")]
    proofs: bool,

    #[arg(
        long,
        help = "Set KEYS_PER_BLOCK additional noise/bulk keys per block for read"
    )]
    keys_per_block: Option<u32>,

    #[arg(
        long,
        help = "Set DEPTHS as comma-separated values (for example: 32,128,256)"
    )]
    depths: Option<String>,

    #[arg(
        long,
        help = "Set CACHE_STRATEGIES as comma-separated values (for example: noop,node256)"
    )]
    cache_strategies: Option<String>,

    #[arg(
        long,
        help = "Set KEY_SEARCH_MAX_TRIES for write promotion-key search budget"
    )]
    key_search_max_tries: Option<usize>,

    #[arg(
        long,
        help = "Set WRITE_DEPTHS as comma-separated values (for example: 1,64,1024)"
    )]
    write_depths: Option<String>,

    #[arg(
        long,
        help = "Set KEY_UPDATES percent (0-100) for write update share of total writes"
    )]
    key_updates: Option<usize>,

    #[arg(
        long,
        help = "Set SQLITE_WAL_AUTOCHECKPOINT page threshold for read/write benchmark SQLite connection"
    )]
    sqlite_wal_autocheckpoint: Option<usize>,

    #[arg(
        long,
        help = "Set SQLITE_WAL_CHECKPOINT_MODE for post-setup checkpoint when SQLITE_WAL_AUTOCHECKPOINT=0 (PASSIVE|FULL|RESTART|TRUNCATE)"
    )]
    sqlite_wal_checkpoint_mode: Option<String>,
}

#[derive(Debug, Args)]
pub struct NodeAllocArgs {
    #[arg(long, help = "Set ITERS for node-alloc case pub count")]
    iters: Option<usize>,
}

#[derive(Debug, Args)]
pub struct ReadArgs {
    #[arg(long, help = "Set CHAIN_LEN for read fixture length")]
    chain_len: Option<u32>,

    #[arg(long, help = "Set ITERS for read per-case pub count")]
    iters: Option<usize>,

    #[arg(long, help = "Set ROUNDS for read repeated case runs")]
    rounds: Option<usize>,

    #[arg(long, help = "Enable proofed reads (MARF::get_with_proof)")]
    proofs: bool,

    #[arg(
        long,
        help = "Set KEYS_PER_BLOCK additional noise/bulk keys per block for read"
    )]
    keys_per_block: Option<u32>,

    #[arg(
        long,
        help = "Set DEPTHS as comma-separated values (for example: 32,128,256)"
    )]
    depths: Option<String>,

    #[arg(
        long,
        help = "Set CACHE_STRATEGIES as comma-separated values (for example: noop,node256)"
    )]
    cache_strategies: Option<String>,

    #[arg(
        long,
        help = "Set SQLITE_WAL_AUTOCHECKPOINT page threshold for read benchmark SQLite connection"
    )]
    sqlite_wal_autocheckpoint: Option<usize>,

    #[arg(
        long,
        help = "Set SQLITE_WAL_CHECKPOINT_MODE for post-setup checkpoint when SQLITE_WAL_AUTOCHECKPOINT=0 (PASSIVE|FULL|RESTART|TRUNCATE)"
    )]
    sqlite_wal_checkpoint_mode: Option<String>,
}

#[derive(Debug, Args)]
pub struct WriteArgs {
    #[arg(long, help = "Set ITERS for write inserted keys per workflow round")]
    iters: Option<usize>,

    #[arg(long, help = "Set ROUNDS for write repeated workflow runs")]
    rounds: Option<usize>,

    #[arg(
        long,
        help = "Set WRITE_DEPTHS as comma-separated values (for example: 1,64,1024)"
    )]
    write_depths: Option<String>,

    #[arg(
        long,
        help = "Set KEY_UPDATES percent (0-100) for write update share of total writes"
    )]
    key_updates: Option<usize>,

    #[arg(
        long,
        help = "Set SQLITE_WAL_AUTOCHECKPOINT page threshold for write benchmark SQLite connection"
    )]
    sqlite_wal_autocheckpoint: Option<usize>,

    #[arg(
        long,
        help = "Set SQLITE_WAL_CHECKPOINT_MODE for post-setup checkpoint when SQLITE_WAL_AUTOCHECKPOINT=0 (PASSIVE|FULL|RESTART|TRUNCATE)"
    )]
    sqlite_wal_checkpoint_mode: Option<String>,

    #[arg(
        long,
        help = "Set KEY_SEARCH_MAX_TRIES for write promotion-key search budget"
    )]
    key_search_max_tries: Option<usize>,
}
