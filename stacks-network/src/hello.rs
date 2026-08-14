use prost::Message;
use stacks_network_types::wire::v1::{EnvelopeKind, Hello, HelloResponse, Status};
use stacks_network_types::{
    validate_legacy_identity_binding_bounds, ContentId, LegacyIdentityBindingError,
    NetworkEnvelope, NetworkScope,
};

const HELLO_CONTENT_DOMAIN: &[u8] = b"STACKS_LIBP2P_HELLO_CONTENT_ID_V1";
const HELLO_RESPONSE_CONTENT_DOMAIN: &[u8] = b"STACKS_LIBP2P_HELLO_RESPONSE_CONTENT_ID_V1";
const MAX_HASH_BYTES: usize = 64;
const MAX_MULTIADDR_BYTES: usize = 512;
const MAX_ADVERTISED_ADDRESSES: usize = 32;
const MAX_PROTOCOL_VERSIONS: usize = 16;
const MAX_CHALLENGE_BYTES: usize = 64;

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum HelloError {
    #[error("envelope kind is not hello request")]
    WrongEnvelopeKind,
    #[error("outer chain ID does not match hello chain ID")]
    OuterChainMismatch,
    #[error(
        "wrong chain: expected {expected_chain_id:#x}/{expected_network_id:#x}, got {actual_chain_id:#x}/{actual_network_id:#x}"
    )]
    WrongChain {
        expected_chain_id: u32,
        expected_network_id: u32,
        actual_chain_id: u32,
        actual_network_id: u32,
    },
    #[error("unsupported hello envelope version {0}")]
    UnsupportedVersion(u32),
    #[error("hello exceeds bounded field counts or lengths")]
    Bounds,
    #[error("hello content ID does not match its canonical transcript")]
    ContentIdMismatch,
    #[error("hello protobuf decode failed: {0}")]
    Decode(String),
    #[error("hello response does not echo the request challenge")]
    ChallengeMismatch,
    #[error("hello response status is not OK")]
    ResponseStatus,
    #[error(transparent)]
    LegacyIdentityBinding(#[from] LegacyIdentityBindingError),
}

pub fn hello_envelope(hello: &Hello) -> Result<NetworkEnvelope, HelloError> {
    validate_bounds(hello)?;
    let content_id = hello_content_id(hello);
    Ok(NetworkEnvelope::new(
        hello.chain_id,
        EnvelopeKind::HelloRequest,
        0,
        content_id,
        hello.encode_to_vec(),
    ))
}

pub fn hello_response_envelope(
    hello: &Hello,
    challenge_response: Vec<u8>,
) -> Result<NetworkEnvelope, HelloError> {
    validate_bounds(hello)?;
    let response = HelloResponse {
        status: Status::Ok as i32,
        hello: Some(hello.clone()),
        challenge_response,
    };
    let payload = response.encode_to_vec();
    Ok(NetworkEnvelope::new(
        hello.chain_id,
        EnvelopeKind::HelloResponse,
        0,
        ContentId::from_domain_bytes(HELLO_RESPONSE_CONTENT_DOMAIN, &payload),
        payload,
    ))
}

/// Construct a bounded negative Hello response without echoing peer-controlled
/// data. Non-OK responses deliberately carry no Hello or challenge.
pub fn hello_status_response_envelope(chain_id: u32, status: Status) -> NetworkEnvelope {
    debug_assert!(status != Status::Ok && status != Status::Unspecified);
    let response = HelloResponse {
        status: status as i32,
        hello: None,
        challenge_response: Vec::new(),
    };
    let payload = response.encode_to_vec();
    NetworkEnvelope::new(
        chain_id,
        EnvelopeKind::HelloResponse,
        0,
        ContentId::from_domain_bytes(HELLO_RESPONSE_CONTENT_DOMAIN, &payload),
        payload,
    )
}

pub fn validate_hello_response(
    envelope: &NetworkEnvelope,
    scope: NetworkScope,
    expected_challenge: &[u8],
) -> Result<Hello, HelloError> {
    if envelope.kind() != EnvelopeKind::HelloResponse {
        return Err(HelloError::WrongEnvelopeKind);
    }
    let response = HelloResponse::decode(envelope.payload())
        .map_err(|error| HelloError::Decode(error.to_string()))?;
    if response.status != Status::Ok as i32 {
        return Err(HelloError::ResponseStatus);
    }
    if response.challenge_response != expected_challenge {
        return Err(HelloError::ChallengeMismatch);
    }
    if envelope.content_id()
        != ContentId::from_domain_bytes(HELLO_RESPONSE_CONTENT_DOMAIN, envelope.payload())
    {
        return Err(HelloError::ContentIdMismatch);
    }
    let hello = response.hello.ok_or(HelloError::Bounds)?;
    validate_bounds(&hello)?;
    if envelope.chain_id() != hello.chain_id {
        return Err(HelloError::OuterChainMismatch);
    }
    if hello.chain_id != scope.chain_id() || hello.network_id != scope.network_id() {
        return Err(HelloError::WrongChain {
            expected_chain_id: scope.chain_id(),
            expected_network_id: scope.network_id(),
            actual_chain_id: hello.chain_id,
            actual_network_id: hello.network_id,
        });
    }
    Ok(hello)
}

pub fn validate_hello(
    envelope: &NetworkEnvelope,
    scope: NetworkScope,
) -> Result<Hello, HelloError> {
    if envelope.kind() != EnvelopeKind::HelloRequest {
        return Err(HelloError::WrongEnvelopeKind);
    }
    let hello =
        Hello::decode(envelope.payload()).map_err(|error| HelloError::Decode(error.to_string()))?;
    validate_bounds(&hello)?;
    if envelope.chain_id() != hello.chain_id {
        return Err(HelloError::OuterChainMismatch);
    }
    if hello.chain_id != scope.chain_id() || hello.network_id != scope.network_id() {
        return Err(HelloError::WrongChain {
            expected_chain_id: scope.chain_id(),
            expected_network_id: scope.network_id(),
            actual_chain_id: hello.chain_id,
            actual_network_id: hello.network_id,
        });
    }
    if hello.envelope_version != 1 {
        return Err(HelloError::UnsupportedVersion(hello.envelope_version));
    }
    if envelope.content_id() != hello_content_id(&hello) {
        return Err(HelloError::ContentIdMismatch);
    }
    Ok(hello)
}

fn validate_bounds(hello: &Hello) -> Result<(), HelloError> {
    if let Some(binding) = hello.legacy_identity_binding.as_ref() {
        validate_legacy_identity_binding_bounds(binding)?;
    }
    let hashes_bounded = hello.burn_tip_hash.len() <= MAX_HASH_BYTES
        && hello.stable_burn_tip_hash.len() <= MAX_HASH_BYTES
        && hello.stacks_tip_id.len() <= MAX_HASH_BYTES;
    let addresses_bounded = hello.advertised_multiaddrs.len() <= MAX_ADVERTISED_ADDRESSES
        && hello
            .advertised_multiaddrs
            .iter()
            .all(|address| address.len() <= MAX_MULTIADDR_BYTES);
    if !hashes_bounded
        || !addresses_bounded
        || hello.supported_protocol_versions.len() > MAX_PROTOCOL_VERSIONS
        || hello.challenge.len() > MAX_CHALLENGE_BYTES
    {
        return Err(HelloError::Bounds);
    }
    Ok(())
}

fn hello_content_id(hello: &Hello) -> ContentId {
    let mut transcript = Vec::with_capacity(512);
    put_u32(&mut transcript, hello.envelope_version);
    put_u32(&mut transcript, hello.chain_id);
    put_u32(&mut transcript, hello.network_id);
    put_u32(&mut transcript, hello.peer_version);
    transcript.extend_from_slice(&hello.capabilities.to_be_bytes());
    transcript.extend_from_slice(&hello.burn_tip_height.to_be_bytes());
    put_bytes(&mut transcript, &hello.burn_tip_hash);
    transcript.extend_from_slice(&hello.stable_burn_tip_height.to_be_bytes());
    put_bytes(&mut transcript, &hello.stable_burn_tip_hash);
    transcript.extend_from_slice(&hello.stacks_tip_height.to_be_bytes());
    put_bytes(&mut transcript, &hello.stacks_tip_id);
    transcript.extend_from_slice(&hello.current_reward_cycle.to_be_bytes());

    let mut versions = hello.supported_protocol_versions.clone();
    versions.sort_unstable();
    versions.dedup();
    put_u32(&mut transcript, versions.len() as u32);
    for version in versions {
        put_u32(&mut transcript, version);
    }

    let mut addresses = hello.advertised_multiaddrs.clone();
    addresses.sort_unstable();
    addresses.dedup();
    put_u32(&mut transcript, addresses.len() as u32);
    for address in addresses {
        put_bytes(&mut transcript, &address);
    }
    match hello.legacy_identity_binding.as_ref() {
        Some(binding) => {
            transcript.push(1);
            put_bytes(&mut transcript, &binding.encode_to_vec());
        }
        None => transcript.push(0),
    }
    put_bytes(&mut transcript, &hello.challenge);
    ContentId::from_domain_bytes(HELLO_CONTENT_DOMAIN, &transcript)
}

fn put_u32(target: &mut Vec<u8>, value: u32) {
    target.extend_from_slice(&value.to_be_bytes());
}

fn put_bytes(target: &mut Vec<u8>, bytes: &[u8]) {
    target.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    target.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello() -> Hello {
        Hello {
            envelope_version: 1,
            chain_id: 0x8000_0000,
            network_id: 0x8000_0000,
            supported_protocol_versions: vec![2, 1, 1],
            peer_version: 1,
            capabilities: 0,
            burn_tip_height: 0,
            burn_tip_hash: vec![],
            stable_burn_tip_height: 0,
            stable_burn_tip_hash: vec![],
            stacks_tip_height: 0,
            stacks_tip_id: vec![],
            current_reward_cycle: 0,
            advertised_multiaddrs: vec![b"/memory/2".to_vec(), b"/memory/1".to_vec()],
            legacy_identity_binding: None,
            challenge: vec![7; 32],
        }
    }

    #[test]
    fn canonical_content_id_ignores_set_order_and_duplicates() {
        let first = hello_envelope(&hello()).unwrap();
        let mut reordered = hello();
        reordered.supported_protocol_versions = vec![1, 2];
        reordered.advertised_multiaddrs.reverse();
        let second = hello_envelope(&reordered).unwrap();
        assert_eq!(first.content_id(), second.content_id());
    }

    #[test]
    fn rejects_wrong_chain() {
        let envelope = hello_envelope(&hello()).unwrap();
        assert!(matches!(
            validate_hello(&envelope, NetworkScope::new(1, 1)),
            Err(HelloError::WrongChain { .. })
        ));
    }

    #[test]
    fn response_binds_the_request_challenge() {
        let request = hello();
        let response = hello_response_envelope(&request, request.challenge.clone()).unwrap();
        assert!(validate_hello_response(
            &response,
            NetworkScope::new(request.chain_id, request.network_id),
            &request.challenge
        )
        .is_ok());
        assert_eq!(
            validate_hello_response(
                &response,
                NetworkScope::new(request.chain_id, request.network_id),
                b"different"
            ),
            Err(HelloError::ChallengeMismatch)
        );
    }
}
