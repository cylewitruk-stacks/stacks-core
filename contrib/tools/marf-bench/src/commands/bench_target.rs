use clap::{Args, Subcommand};

use crate::BenchKind;
use crate::runner::{BenchEnvOverrides, BenchRunRequest};

#[derive(Debug, Subcommand)]
pub(crate) enum BenchTarget {
    #[command(about = "Run all bench types")]
    All(AllArgs),
    #[command(name = "node-alloc", about = "Run node-alloc bench")]
    NodeAlloc(NodeAllocArgs),
    #[command(about = "Run read bench")]
    Read(ReadArgs),
    #[command(name = "read-proof", about = "Run read-proof bench")]
    ReadProof(ReadArgs),
    #[command(name = "read-backptr", about = "Run read-backptr bench")]
    ReadBackptr(ReadBackptrArgs),
    #[command(name = "read-backptr-proof", about = "Run read-backptr-proof bench")]
    ReadBackptrProof(ReadBackptrArgs),
    #[command(about = "Run write bench")]
    Write(WriteArgs),
}

impl BenchTarget {
    pub(crate) fn into_requests(self) -> Vec<BenchRunRequest> {
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
                        keys_per_block: args.keys_per_block,
                        depths: args.depths.clone(),
                        cache_strategies: args.cache_strategies.clone(),
                        ..Default::default()
                    },
                ),
                BenchRunRequest::new(
                    BenchKind::ReadBackptr,
                    BenchEnvOverrides {
                        iters: args.iters,
                        rounds: args.rounds,
                        chain_len: args.chain_len,
                        depths: args.depths.clone(),
                        cache_strategies: args.cache_strategies.clone(),
                        ..Default::default()
                    },
                ),
                BenchRunRequest::new(
                    BenchKind::ReadProof,
                    BenchEnvOverrides {
                        iters: args.iters,
                        rounds: args.rounds,
                        chain_len: args.chain_len,
                        keys_per_block: args.keys_per_block,
                        depths: args.depths.clone(),
                        cache_strategies: args.cache_strategies.clone(),
                        ..Default::default()
                    },
                ),
                BenchRunRequest::new(
                    BenchKind::ReadBackptrProof,
                    BenchEnvOverrides {
                        iters: args.iters,
                        rounds: args.rounds,
                        chain_len: args.chain_len,
                        depths: args.depths.clone(),
                        cache_strategies: args.cache_strategies.clone(),
                        ..Default::default()
                    },
                ),
                BenchRunRequest::new(
                    BenchKind::Write,
                    BenchEnvOverrides {
                        rounds: args.rounds,
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
                    keys_per_block: args.keys_per_block,
                    depths: args.depths,
                    cache_strategies: args.cache_strategies,
                    ..Default::default()
                },
            )],
            Self::ReadProof(args) => vec![BenchRunRequest::new(
                BenchKind::ReadProof,
                BenchEnvOverrides {
                    iters: args.iters,
                    rounds: args.rounds,
                    chain_len: args.chain_len,
                    keys_per_block: args.keys_per_block,
                    depths: args.depths,
                    cache_strategies: args.cache_strategies,
                    ..Default::default()
                },
            )],
            Self::ReadBackptr(args) => vec![BenchRunRequest::new(
                BenchKind::ReadBackptr,
                BenchEnvOverrides {
                    iters: args.iters,
                    rounds: args.rounds,
                    chain_len: args.chain_len,
                    depths: args.depths,
                    cache_strategies: args.cache_strategies,
                    ..Default::default()
                },
            )],
            Self::ReadBackptrProof(args) => vec![BenchRunRequest::new(
                BenchKind::ReadBackptrProof,
                BenchEnvOverrides {
                    iters: args.iters,
                    rounds: args.rounds,
                    chain_len: args.chain_len,
                    depths: args.depths,
                    cache_strategies: args.cache_strategies,
                    ..Default::default()
                },
            )],
            Self::Write(args) => vec![BenchRunRequest::new(
                BenchKind::Write,
                BenchEnvOverrides {
                    rounds: args.rounds,
                    key_search_max_tries: args.key_search_max_tries,
                    ..Default::default()
                },
            )],
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct AllArgs {
    #[arg(long, help = "Set ITERS for benches that use per-case iteration count")]
    iters: Option<usize>,

    #[arg(
        long,
        help = "Set ROUNDS for benches that use repeated case/workflow runs"
    )]
    rounds: Option<usize>,

    #[arg(
        long,
        help = "Set CHAIN_LEN for read/read-proof/read-backptr/read-backptr-proof fixture length"
    )]
    chain_len: Option<u32>,

    #[arg(long, help = "Set KEYS_PER_BLOCK for read fixture density")]
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
}

#[derive(Debug, Args)]
pub(crate) struct NodeAllocArgs {
    #[arg(long, help = "Set ITERS for node-alloc case iteration count")]
    iters: Option<usize>,
}

#[derive(Debug, Args)]
pub(crate) struct ReadArgs {
    #[arg(long, help = "Set CHAIN_LEN for read fixture length")]
    chain_len: Option<u32>,

    #[arg(long, help = "Set ITERS for read per-case iteration count")]
    iters: Option<usize>,

    #[arg(long, help = "Set ROUNDS for read repeated case runs")]
    rounds: Option<usize>,

    #[arg(long, help = "Set KEYS_PER_BLOCK for read fixture density")]
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
}

#[derive(Debug, Args)]
pub(crate) struct ReadBackptrArgs {
    #[arg(long, help = "Set CHAIN_LEN for read-backptr fixture length")]
    chain_len: Option<u32>,

    #[arg(long, help = "Set ITERS for read-backptr per-case iteration count")]
    iters: Option<usize>,

    #[arg(long, help = "Set ROUNDS for read-backptr repeated case runs")]
    rounds: Option<usize>,

    #[arg(
        long,
        help = "Set DEPTHS as comma-separated values (for example: 256,768,1536)"
    )]
    depths: Option<String>,

    #[arg(
        long,
        help = "Set CACHE_STRATEGIES as comma-separated values (for example: noop,node256)"
    )]
    cache_strategies: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct WriteArgs {
    #[arg(long, help = "Set ROUNDS for write repeated workflow runs")]
    rounds: Option<usize>,

    #[arg(
        long,
        help = "Set KEY_SEARCH_MAX_TRIES for write promotion-key search budget"
    )]
    key_search_max_tries: Option<usize>,
}
