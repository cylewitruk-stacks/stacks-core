//! Quarantined temporary compatibility boundary between signed StackerDB
//! chunks and the semantic signer network.
//!
//! Native protocol crates deliberately do not depend on this crate. In
//! particular, legacy ingress is never republished as a native envelope and
//! remote native authors are never proxy-signed into StackerDB.

mod composite;
mod config;
mod journal;
mod mapping;
mod pipeline;
mod writer;

pub use composite::{CompositeSignerNetwork, LegacyChunkWriter, OriginLegacyMapping};
pub use config::{BridgeMode, SignerBridgeConfig, SignerBridgeConfigError};
pub use journal::{BridgeJournal, BridgeJournalError, CorrelationRecord};
pub use mapping::{
    legacy_chunk_id, semantic_message_id, BridgeDiagnostics, LegacyAuthor, LegacyChunkPolicy,
    LegacyLocator, PendingLegacyWrite, TemporarySignerBridge, TemporarySignerBridgeError,
};
pub use pipeline::{LegacyWritePipeline, LegacyWritePipelineWarning, LegacyWritePumpReport};
pub use writer::{LegacyWriteResult, StackerDbLegacyWriter};
