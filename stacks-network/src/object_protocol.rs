use prost::Message;
use stacks_network_types::wire::v1::{
    ContentPush, ContentPushAck, ContentRequest, ContentResponse, EnvelopeKind, ObjectAnnouncement,
    ObjectType, Status,
};
use stacks_network_types::{Announcement, ContentId, NetworkEnvelope, NetworkObject, ObjectKind};

use crate::outer_envelope::ScopedEnvelopeCodec;

const ANNOUNCEMENT_DOMAIN: &[u8] = b"STACKS_OBJECT_ANNOUNCEMENT_WIRE_V1";
const CONTENT_REQUEST_DOMAIN: &[u8] = b"STACKS_CONTENT_REQUEST_V1";
const CONTENT_RESPONSE_DOMAIN: &[u8] = b"STACKS_CONTENT_RESPONSE_V1";
const CONTENT_PUSH_DOMAIN: &[u8] = b"STACKS_CONTENT_PUSH_V1";
const CONTENT_PUSH_ACK_DOMAIN: &[u8] = b"STACKS_CONTENT_PUSH_ACK_V1";

pub fn announcement_envelope(chain_id: u32, value: &Announcement) -> NetworkEnvelope {
    let payload = ObjectAnnouncement {
        kind: encode_kind(value.kind),
        content_id: value.content_id.as_bytes().to_vec(),
        canonical_metadata: value.canonical_metadata.clone(),
    }
    .encode_to_vec();
    codec(chain_id, EnvelopeKind::Announcement, ANNOUNCEMENT_DOMAIN).wrap(payload)
}

pub fn decode_announcement(
    envelope: &NetworkEnvelope,
    chain_id: u32,
) -> Result<Announcement, String> {
    codec(chain_id, EnvelopeKind::Announcement, ANNOUNCEMENT_DOMAIN).validate(envelope)?;
    let value = ObjectAnnouncement::decode(envelope.payload())
        .map_err(|error| format!("invalid announcement protobuf: {error}"))?;
    Ok(Announcement {
        kind: decode_kind(value.kind)?,
        content_id: content_id(&value.content_id)?,
        canonical_metadata: value.canonical_metadata,
    })
}

pub fn content_request_envelope(chain_id: u32, kind: ObjectKind, id: ContentId) -> NetworkEnvelope {
    codec(
        chain_id,
        EnvelopeKind::ContentRequest,
        CONTENT_REQUEST_DOMAIN,
    )
    .wrap(
        ContentRequest {
            kind: encode_kind(kind),
            content_id: id.as_bytes().to_vec(),
        }
        .encode_to_vec(),
    )
}

pub fn decode_content_request(
    envelope: &NetworkEnvelope,
    chain_id: u32,
) -> Result<(ObjectKind, ContentId), String> {
    codec(
        chain_id,
        EnvelopeKind::ContentRequest,
        CONTENT_REQUEST_DOMAIN,
    )
    .validate(envelope)?;
    let value = ContentRequest::decode(envelope.payload())
        .map_err(|error| format!("invalid content request protobuf: {error}"))?;
    Ok((decode_kind(value.kind)?, content_id(&value.content_id)?))
}

pub fn content_response_envelope(
    chain_id: u32,
    status: Status,
    object: Option<&NetworkObject>,
    requested_kind: ObjectKind,
    requested_id: ContentId,
) -> NetworkEnvelope {
    let value = ContentResponse {
        status: status as i32,
        kind: object.map_or_else(|| encode_kind(requested_kind), |v| encode_kind(v.kind)),
        content_id: object.map_or_else(
            || requested_id.as_bytes().to_vec(),
            |v| v.content_id.as_bytes().to_vec(),
        ),
        payload: object.map(|v| v.bytes.clone()).unwrap_or_default(),
    };
    codec(
        chain_id,
        EnvelopeKind::ContentResponse,
        CONTENT_RESPONSE_DOMAIN,
    )
    .wrap(value.encode_to_vec())
}

pub fn decode_content_response(
    envelope: &NetworkEnvelope,
    chain_id: u32,
) -> Result<(Status, Option<NetworkObject>), String> {
    codec(
        chain_id,
        EnvelopeKind::ContentResponse,
        CONTENT_RESPONSE_DOMAIN,
    )
    .validate(envelope)?;
    let value = ContentResponse::decode(envelope.payload())
        .map_err(|error| format!("invalid content response protobuf: {error}"))?;
    let status = decode_status(value.status)?;
    let kind = decode_kind(value.kind)?;
    let id = content_id(&value.content_id)?;
    match (status, value.payload.is_empty()) {
        (Status::Ok, false) => Ok((
            status,
            Some(NetworkObject {
                kind,
                content_id: id,
                bytes: value.payload,
            }),
        )),
        (Status::Ok, true) => Err("successful content response has no payload".to_owned()),
        (_, false) => Err("failed content response includes a payload".to_owned()),
        (_, true) => Ok((status, None)),
    }
}

pub fn content_push_envelope(chain_id: u32, object: &NetworkObject) -> NetworkEnvelope {
    codec(chain_id, EnvelopeKind::ContentPush, CONTENT_PUSH_DOMAIN).wrap(
        ContentPush {
            kind: encode_kind(object.kind),
            content_id: object.content_id.as_bytes().to_vec(),
            payload: object.bytes.clone(),
        }
        .encode_to_vec(),
    )
}

pub fn decode_content_push(
    envelope: &NetworkEnvelope,
    chain_id: u32,
) -> Result<NetworkObject, String> {
    codec(chain_id, EnvelopeKind::ContentPush, CONTENT_PUSH_DOMAIN).validate(envelope)?;
    let value = ContentPush::decode(envelope.payload())
        .map_err(|error| format!("invalid content push protobuf: {error}"))?;
    Ok(NetworkObject {
        kind: decode_kind(value.kind)?,
        content_id: content_id(&value.content_id)?,
        bytes: value.payload,
    })
}

pub fn content_push_ack_envelope(chain_id: u32, status: Status, id: ContentId) -> NetworkEnvelope {
    codec(
        chain_id,
        EnvelopeKind::ContentPushAck,
        CONTENT_PUSH_ACK_DOMAIN,
    )
    .wrap(
        ContentPushAck {
            status: status as i32,
            content_id: id.as_bytes().to_vec(),
        }
        .encode_to_vec(),
    )
}

pub fn decode_content_push_ack(
    envelope: &NetworkEnvelope,
    chain_id: u32,
) -> Result<(Status, ContentId), String> {
    codec(
        chain_id,
        EnvelopeKind::ContentPushAck,
        CONTENT_PUSH_ACK_DOMAIN,
    )
    .validate(envelope)?;
    let value = ContentPushAck::decode(envelope.payload())
        .map_err(|error| format!("invalid content push acknowledgement: {error}"))?;
    Ok((decode_status(value.status)?, content_id(&value.content_id)?))
}

fn codec(chain_id: u32, kind: EnvelopeKind, domain: &'static [u8]) -> ScopedEnvelopeCodec {
    ScopedEnvelopeCodec::new(chain_id, kind, domain, "object")
}

fn content_id(bytes: &[u8]) -> Result<ContentId, String> {
    ContentId::try_from(bytes).map_err(|error| error.to_string())
}

fn encode_kind(kind: ObjectKind) -> i32 {
    ObjectType::from(kind) as i32
}

fn decode_kind(kind: i32) -> Result<ObjectKind, String> {
    let kind = ObjectType::try_from(kind).map_err(|_| "invalid object kind".to_owned())?;
    ObjectKind::try_from(kind).map_err(|error| error.to_string())
}

fn decode_status(value: i32) -> Result<Status, String> {
    Status::try_from(value)
        .ok()
        .filter(|value| *value != Status::Unspecified)
        .ok_or_else(|| "invalid object protocol status".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_protocol_round_trips_and_binds_outer_content() {
        let object = NetworkObject {
            kind: ObjectKind::NakamotoBlock,
            content_id: ContentId::from_bytes([7; 32]),
            bytes: vec![1, 2, 3],
        };
        let push = content_push_envelope(9, &object);
        assert_eq!(decode_content_push(&push, 9).unwrap(), object);
        assert!(decode_content_push(&push, 10).is_err());
        let response =
            content_response_envelope(9, Status::Ok, Some(&object), object.kind, object.content_id);
        assert_eq!(
            decode_content_response(&response, 9).unwrap(),
            (Status::Ok, Some(object))
        );
    }
}
