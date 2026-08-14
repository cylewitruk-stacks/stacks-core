#![no_main]

use libfuzzer_sys::fuzz_target;
use prost::Message;
use stacks_network::{
    decode_announcement, decode_content_push, decode_content_push_ack, decode_content_request,
    decode_content_response, decode_directory_query, decode_directory_response,
    decode_sync_request, decode_sync_response, validate_hello, validate_hello_response,
};
use stacks_network_types::wire::v1::{
    EnvelopeKind, LegacyIdentityBinding, RoleDirectoryRecord, RoleProof, SignerEnvelope,
};
use stacks_network_types::{
    directory_record_digest, legacy_identity_binding_digest, role_proof_digest, role_proof_id,
    signer_envelope_digest, signer_envelope_id, validate_directory_record_bounds,
    validate_legacy_identity_binding_bounds, validate_role_proof_bounds,
    validate_signer_envelope_bounds, EnvelopeLimits, NetworkEnvelope, NetworkScope,
};

fuzz_target!(|bytes: &[u8]| {
    // Exercise every public outer bound. Successful decoding is then routed to
    // the matching domain decoder; all failures must remain panic-free and
    // allocation-bounded by NetworkEnvelope.
    for limits in [
        EnvelopeLimits::HELLO,
        EnvelopeLimits::BLOCK,
        EnvelopeLimits::DIRECTORY,
        EnvelopeLimits::SYNC,
    ] {
        let Ok(envelope) = NetworkEnvelope::decode(bytes, limits) else {
            continue;
        };
        let chain_id = envelope.chain_id();
        match envelope.kind() {
            EnvelopeKind::HelloRequest => {
                let _ = validate_hello(&envelope, NetworkScope::new(chain_id, 0));
            }
            EnvelopeKind::HelloResponse => {
                let _ = validate_hello_response(&envelope, NetworkScope::new(chain_id, 0), &[]);
            }
            EnvelopeKind::Announcement => {
                let _ = decode_announcement(&envelope, chain_id);
            }
            EnvelopeKind::ContentRequest => {
                let _ = decode_content_request(&envelope, chain_id);
            }
            EnvelopeKind::ContentResponse => {
                let _ = decode_content_response(&envelope, chain_id);
            }
            EnvelopeKind::ContentPush => {
                let _ = decode_content_push(&envelope, chain_id);
            }
            EnvelopeKind::ContentPushAck => {
                let _ = decode_content_push_ack(&envelope, chain_id);
            }
            EnvelopeKind::Signer => {
                if let Ok(signer) = SignerEnvelope::decode(envelope.payload()) {
                    if let Ok(body) = validate_signer_envelope_bounds(&signer) {
                        let _ = signer_envelope_digest(body);
                        let _ = signer_envelope_id(&signer);
                    }
                }
            }
            EnvelopeKind::SyncRequest => {
                let _ = decode_sync_request(&envelope, chain_id);
            }
            EnvelopeKind::SyncResponse => {
                let _ = decode_sync_response(&envelope, chain_id);
            }
            EnvelopeKind::RoleDirectoryQuery => {
                let _ = decode_directory_query(&envelope, chain_id);
                if let Ok(proof) = RoleProof::decode(envelope.payload()) {
                    if let Ok(body) = validate_role_proof_bounds(&proof) {
                        let _ = role_proof_digest(body);
                        let _ = role_proof_id(&proof);
                    }
                }
            }
            EnvelopeKind::RoleDirectoryResponse => {
                if let Ok(response) = decode_directory_response(&envelope, chain_id) {
                    for record in response.records {
                        if validate_directory_record_bounds(&record).is_ok() {
                            let _ = directory_record_digest(&record);
                        }
                    }
                }
                if let Ok(record) = RoleDirectoryRecord::decode(envelope.payload()) {
                    if validate_directory_record_bounds(&record).is_ok() {
                        let _ = directory_record_digest(&record);
                    }
                }
            }
            EnvelopeKind::Unspecified => {}
        }
    }

    if let Ok(binding) = LegacyIdentityBinding::decode(bytes) {
        if validate_legacy_identity_binding_bounds(&binding).is_ok() {
            let _ = legacy_identity_binding_digest(&binding);
        }
    }
});
