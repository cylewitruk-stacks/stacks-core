use prost::Message;
use stacks_network_types::wire::v1::{
    EnvelopeKind, RoleDirectoryQuery, RoleDirectoryResponse, Status,
};
use stacks_network_types::NetworkEnvelope;

use crate::outer_envelope::ScopedEnvelopeCodec;

const DIRECTORY_QUERY_DOMAIN: &[u8] = b"STACKS_LIBP2P_ROLE_DIRECTORY_QUERY_V1";
const DIRECTORY_RESPONSE_DOMAIN: &[u8] = b"STACKS_LIBP2P_ROLE_DIRECTORY_RESPONSE_V1";

pub fn directory_query_envelope(chain_id: u32, query: &RoleDirectoryQuery) -> NetworkEnvelope {
    let payload = query.encode_to_vec();
    directory_codec(
        chain_id,
        EnvelopeKind::RoleDirectoryQuery,
        DIRECTORY_QUERY_DOMAIN,
    )
    .wrap(payload)
}

pub fn decode_directory_query(
    envelope: &NetworkEnvelope,
    chain_id: u32,
) -> Result<RoleDirectoryQuery, String> {
    directory_codec(
        chain_id,
        EnvelopeKind::RoleDirectoryQuery,
        DIRECTORY_QUERY_DOMAIN,
    )
    .validate(envelope)?;
    RoleDirectoryQuery::decode(envelope.payload())
        .map_err(|error| format!("invalid role-directory query protobuf: {error}"))
}

pub fn directory_response_envelope(
    chain_id: u32,
    response: &RoleDirectoryResponse,
) -> NetworkEnvelope {
    let payload = response.encode_to_vec();
    directory_codec(
        chain_id,
        EnvelopeKind::RoleDirectoryResponse,
        DIRECTORY_RESPONSE_DOMAIN,
    )
    .wrap(payload)
}

pub fn decode_directory_response(
    envelope: &NetworkEnvelope,
    chain_id: u32,
) -> Result<RoleDirectoryResponse, String> {
    directory_codec(
        chain_id,
        EnvelopeKind::RoleDirectoryResponse,
        DIRECTORY_RESPONSE_DOMAIN,
    )
    .validate(envelope)?;
    let response = RoleDirectoryResponse::decode(envelope.payload())
        .map_err(|error| format!("invalid role-directory response protobuf: {error}"))?;
    Status::try_from(response.status)
        .ok()
        .filter(|status| *status != Status::Unspecified)
        .ok_or_else(|| "role-directory response has invalid status".to_owned())?;
    Ok(response)
}

fn directory_codec(
    chain_id: u32,
    kind: EnvelopeKind,
    domain: &'static [u8],
) -> ScopedEnvelopeCodec {
    ScopedEnvelopeCodec::new(chain_id, kind, domain, "role-directory")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_wire_helpers_bind_kind_chain_and_content() {
        let query = RoleDirectoryQuery {
            requester: None,
            reward_cycles: vec![1],
            roles: vec![1],
            max_records: 2,
            requester_record: None,
        };
        let envelope = directory_query_envelope(7, &query);
        assert_eq!(decode_directory_query(&envelope, 7).unwrap(), query);
        assert!(decode_directory_query(&envelope, 8).is_err());

        let response = RoleDirectoryResponse {
            status: Status::Ok as i32,
            records: Vec::new(),
        };
        let envelope = directory_response_envelope(7, &response);
        assert_eq!(decode_directory_response(&envelope, 7).unwrap(), response);
    }
}
