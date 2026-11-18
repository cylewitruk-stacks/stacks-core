#![no_main]

use clarity::codec::StacksMessageCodec;
use libfuzzer_sys::fuzz_target;
use libsigner::v0::messages::SignerMessage;
use libstackerdb::StackerDBChunkData;

fuzz_target!(|bytes: &[u8]| {
    // These are the two nested incumbent codecs at the quarantined bridge
    // boundary. The bridge separately enforces its 2 MiB cap before invoking
    // either decoder in production.
    let mut chunk_bytes = bytes;
    if let Ok(chunk) = StackerDBChunkData::consensus_deserialize(&mut chunk_bytes) {
        let mut payload = chunk.data.as_slice();
        let _ = SignerMessage::consensus_deserialize(&mut payload);
    }

    let mut signer_bytes = bytes;
    let _ = SignerMessage::consensus_deserialize(&mut signer_bytes);
});
