use prost::Message;
use stacks_network_types::wire::v1::{
    sync_request, sync_response, AttachmentInventoryPage, EnvelopeKind, InventoryPage, MempoolPage,
    MicroblockPage, ObjectType, SignerLane, SignerReplayPage, Status, SyncRequest, SyncResponse,
};
use stacks_network_types::{
    validate_signer_envelope_bounds, ContentId, NetworkEnvelope, CONTENT_ID_LEN,
};
use std::ops::Range;

use crate::outer_envelope::ScopedEnvelopeCodec;

pub const MAX_SYNC_INVENTORY_ITEMS: usize = 4096;
/// Epoch 2.x may return both an anchored block and its confirmed microblock
/// stream for each requested height.
pub const MAX_SYNC_EPOCH2_HEIGHTS: usize = MAX_SYNC_INVENTORY_ITEMS / 2;
pub const MAX_SYNC_MEMPOOL_ITEMS: usize = 1024;
pub const MAX_SYNC_REQUESTED_BYTES: u32 = 256 * 1024;
pub const MAX_SYNC_CURSOR_BYTES: usize = 64;
pub const MAX_SYNC_ID_BYTES: usize = 64;
/// Sync offsets ultimately index SQLite-backed burn and reward-cycle state.
/// Reject values that cannot be represented by the signed database key space,
/// even though protobuf encodes them as `u64`.
pub const MAX_SYNC_OFFSET: u64 = i64::MAX as u64;
pub const ATTACHMENT_HASH_BYTES: usize = 20;
// Match the incumbent authenticated HTTP callback/request ceiling. JSON can be
// materially larger than the 2 MiB consensus block bytes, but remains bounded
// before allocation by the framed codec and per-peer byte budget.
pub const MAX_SIGNER_REPLAY_ITEMS: usize = 128;
pub const MAX_SIGNER_REPLAY_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_UNCONFIRMED_MICROBLOCKS: usize = 1024;

const SYNC_REQUEST_DOMAIN: &[u8] = b"STACKS_SYNC_REQUEST_V1";
const SYNC_RESPONSE_DOMAIN: &[u8] = b"STACKS_SYNC_RESPONSE_V1";

pub fn sync_request_envelope(
    chain_id: u32,
    request: &SyncRequest,
) -> Result<NetworkEnvelope, String> {
    validate_sync_request(request)?;
    Ok(
        sync_codec(chain_id, EnvelopeKind::SyncRequest, SYNC_REQUEST_DOMAIN)
            .wrap(request.encode_to_vec()),
    )
}

pub fn decode_sync_request(
    envelope: &NetworkEnvelope,
    chain_id: u32,
) -> Result<SyncRequest, String> {
    sync_codec(chain_id, EnvelopeKind::SyncRequest, SYNC_REQUEST_DOMAIN).validate(envelope)?;
    let request = SyncRequest::decode(envelope.payload())
        .map_err(|error| format!("invalid sync request protobuf: {error}"))?;
    validate_sync_request(&request)?;
    Ok(request)
}

pub fn sync_response_envelope(
    chain_id: u32,
    response: &SyncResponse,
) -> Result<NetworkEnvelope, String> {
    validate_sync_response(response)?;
    Ok(
        sync_codec(chain_id, EnvelopeKind::SyncResponse, SYNC_RESPONSE_DOMAIN)
            .wrap(response.encode_to_vec()),
    )
}

pub fn decode_sync_response(
    envelope: &NetworkEnvelope,
    chain_id: u32,
) -> Result<SyncResponse, String> {
    sync_codec(chain_id, EnvelopeKind::SyncResponse, SYNC_RESPONSE_DOMAIN).validate(envelope)?;
    let response = SyncResponse::decode(envelope.payload())
        .map_err(|error| format!("invalid sync response protobuf: {error}"))?;
    validate_sync_response(&response)?;
    Ok(response)
}

pub fn validate_sync_request(request: &SyncRequest) -> Result<(), String> {
    match request.request.as_ref() {
        Some(sync_request::Request::GetStatus(_)) => Ok(()),
        Some(sync_request::Request::GetPoxInventory(request)) => {
            validate_offset(request.start_cycle, "PoX inventory")?;
            validate_count(request.count, MAX_SYNC_INVENTORY_ITEMS, "PoX inventory")
        }
        Some(sync_request::Request::GetTenureInventory(request)) => validate_count(
            request.max_items,
            MAX_SYNC_INVENTORY_ITEMS,
            "tenure inventory",
        ),
        Some(sync_request::Request::GetEpoch2Inventory(request)) => {
            validate_offset(request.start_height, "Epoch 2 inventory")?;
            validate_count(request.count, MAX_SYNC_EPOCH2_HEIGHTS, "Epoch 2 inventory")
        }
        Some(sync_request::Request::GetMempoolPage(request)) => {
            validate_count(request.max_items, MAX_SYNC_MEMPOOL_ITEMS, "mempool page")?;
            if request.max_bytes < CONTENT_ID_LEN as u32
                || request.max_bytes > MAX_SYNC_REQUESTED_BYTES
            {
                return Err("mempool page byte limit is outside policy".to_owned());
            }
            if !request.cursor.is_empty() && request.cursor.len() != CONTENT_ID_LEN {
                return Err("mempool cursor is not a transaction ID".to_owned());
            }
            Ok(())
        }
        Some(sync_request::Request::GetAttachmentInventory(request)) => {
            validate_count(
                request.max_items,
                MAX_SYNC_INVENTORY_ITEMS,
                "attachment inventory",
            )?;
            if !request.cursor.is_empty() && request.cursor.len() != ATTACHMENT_HASH_BYTES {
                return Err("attachment inventory cursor is not a Hash160".to_owned());
            }
            Ok(())
        }
        Some(sync_request::Request::GetSignerReplay(request)) => {
            validate_count(request.max_items, MAX_SIGNER_REPLAY_ITEMS, "signer replay")?;
            if request.max_bytes == 0
                || usize::try_from(request.max_bytes).unwrap_or(usize::MAX)
                    > MAX_SIGNER_REPLAY_BYTES
                || request.cursors.len() > MAX_SIGNER_REPLAY_ITEMS
                || request.cursors.iter().any(|cursor| {
                    cursor.signer_public_key.len() != 33
                        || SignerLane::try_from(cursor.lane)
                            .ok()
                            .is_none_or(|lane| lane == SignerLane::Unspecified)
                })
            {
                return Err("signer replay bounds or cursor are outside policy".to_owned());
            }
            Ok(())
        }
        Some(sync_request::Request::GetUnconfirmedMicroblocks(request)) => {
            if request.parent_block_id.len() != CONTENT_ID_LEN
                || request.start_sequence > u32::from(u16::MAX)
            {
                return Err("unconfirmed microblock cursor is invalid".to_owned());
            }
            validate_count(
                request.max_items,
                MAX_UNCONFIRMED_MICROBLOCKS,
                "unconfirmed microblocks",
            )
        }
        None => Err("sync request has no typed body".to_owned()),
    }
}

/// Return a pagination range that is safe for iteration and capacity sizing.
/// Requests beginning beyond the available end produce an empty range instead
/// of subtracting the untrusted start from a smaller clamped end.
pub fn bounded_inventory_range(start: u64, count: u32, available_end: u64) -> Range<u64> {
    let end = start.saturating_add(u64::from(count)).min(available_end);
    start..end.max(start)
}

pub fn validate_sync_response(response: &SyncResponse) -> Result<(), String> {
    let status = Status::try_from(response.status)
        .ok()
        .filter(|status| *status != Status::Unspecified)
        .ok_or_else(|| "sync response has invalid status".to_owned())?;
    if status != Status::Ok {
        return response
            .response
            .is_none()
            .then_some(())
            .ok_or_else(|| "failed sync response must not carry data".to_owned());
    }
    match response.response.as_ref() {
        Some(sync_response::Response::StatusView(status)) => {
            if status.burn_tip_hash.len() != 32
                || status.stable_burn_tip_hash.len() != 32
                || status.stacks_tip_id.len() != CONTENT_ID_LEN
            {
                return Err("sync status identifiers have invalid lengths".to_owned());
            }
            Ok(())
        }
        Some(sync_response::Response::Inventory(page)) => validate_inventory_page(page),
        Some(sync_response::Response::Mempool(page)) => validate_mempool_page(page),
        Some(sync_response::Response::Attachments(page)) => validate_attachment_page(page),
        Some(sync_response::Response::Ack(_)) => Ok(()),
        Some(sync_response::Response::SignerReplay(page)) => validate_signer_replay_page(page),
        Some(sync_response::Response::UnconfirmedMicroblocks(page)) => {
            validate_unconfirmed_microblock_page(page)
        }
        None => Err("successful sync response has no typed body".to_owned()),
    }
}

fn validate_unconfirmed_microblock_page(page: &MicroblockPage) -> Result<(), String> {
    if page.parent_block_id.len() != CONTENT_ID_LEN
        || page.microblocks.len() > MAX_UNCONFIRMED_MICROBLOCKS
        || page.next_sequence > u32::from(u16::MAX).saturating_add(1)
        || page.microblocks.iter().any(Vec::is_empty)
    {
        return Err("unconfirmed microblock page is outside policy".to_owned());
    }
    Ok(())
}

fn validate_signer_replay_page(page: &SignerReplayPage) -> Result<(), String> {
    if page.envelopes.len() > MAX_SIGNER_REPLAY_ITEMS
        || page.encoded_len() > MAX_SIGNER_REPLAY_BYTES
    {
        return Err("signer replay response exceeds policy".to_owned());
    }
    for envelope in &page.envelopes {
        validate_signer_envelope_bounds(envelope).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn validate_attachment_page(page: &AttachmentInventoryPage) -> Result<(), String> {
    if page.items.len() > MAX_SYNC_INVENTORY_ITEMS {
        return Err("attachment inventory response has too many items".to_owned());
    }
    if (!page.next_cursor.is_empty() && page.next_cursor.len() != ATTACHMENT_HASH_BYTES)
        || page.items.iter().any(|item| {
            !item.available
                || item.object_id.len() != CONTENT_ID_LEN
                || item.kind != ObjectType::Attachment as i32
        })
    {
        return Err("attachment inventory response contains an invalid item or cursor".to_owned());
    }
    Ok(())
}

fn validate_inventory_page(page: &InventoryPage) -> Result<(), String> {
    if page.items.len() > MAX_SYNC_INVENTORY_ITEMS {
        return Err("sync inventory response has too many items".to_owned());
    }
    if page.items.iter().any(|item| {
        item.object_id.len() > MAX_SYNC_ID_BYTES || ObjectType::try_from(item.kind).is_err()
    }) {
        return Err("sync inventory identifier exceeds policy".to_owned());
    }
    Ok(())
}

fn validate_mempool_page(page: &MempoolPage) -> Result<(), String> {
    if page.transaction_ids.len() > MAX_SYNC_MEMPOOL_ITEMS {
        return Err("mempool response has too many transaction IDs".to_owned());
    }
    if (!page.next_cursor.is_empty() && page.next_cursor.len() != CONTENT_ID_LEN)
        || page
            .transaction_ids
            .iter()
            .any(|id| id.len() != ContentId::from_bytes([0; 32]).as_bytes().len())
    {
        return Err("mempool response contains an invalid ID or cursor".to_owned());
    }
    Ok(())
}

fn validate_count(count: u32, max: usize, name: &str) -> Result<(), String> {
    if count == 0 || usize::try_from(count).unwrap_or(usize::MAX) > max {
        Err(format!("{name} count is outside policy"))
    } else {
        Ok(())
    }
}

fn validate_offset(offset: u64, name: &str) -> Result<(), String> {
    if offset > MAX_SYNC_OFFSET {
        Err(format!("{name} offset is outside policy"))
    } else {
        Ok(())
    }
}

fn sync_codec(chain_id: u32, kind: EnvelopeKind, domain: &'static [u8]) -> ScopedEnvelopeCodec {
    ScopedEnvelopeCodec::new(chain_id, kind, domain, "sync")
}

#[cfg(test)]
mod tests {
    use stacks_network_types::wire::v1::{
        GetAttachmentInventory, GetEpoch2Inventory, GetMempoolPage, GetPoxInventory,
        GetSignerReplay, GetStatus, GetUnconfirmedMicroblocks, SignerReplayCursor,
    };

    use super::*;

    #[test]
    fn sync_wire_is_typed_bounded_and_content_bound() {
        let request = SyncRequest {
            request: Some(sync_request::Request::GetStatus(GetStatus {})),
        };
        let envelope = sync_request_envelope(1, &request).unwrap();
        assert_eq!(decode_sync_request(&envelope, 1).unwrap(), request);
        assert!(decode_sync_request(&envelope, 2).is_err());

        let oversized = SyncRequest {
            request: Some(sync_request::Request::GetMempoolPage(GetMempoolPage {
                cursor: Vec::new(),
                max_items: 1,
                max_bytes: MAX_SYNC_REQUESTED_BYTES + 1,
            })),
        };
        assert!(sync_request_envelope(1, &oversized).is_err());

        let invalid_attachment_cursor = SyncRequest {
            request: Some(sync_request::Request::GetAttachmentInventory(
                GetAttachmentInventory {
                    cursor: vec![0; ATTACHMENT_HASH_BYTES - 1],
                    max_items: 1,
                },
            )),
        };
        assert!(sync_request_envelope(1, &invalid_attachment_cursor).is_err());

        let signer_replay = SyncRequest {
            request: Some(sync_request::Request::GetSignerReplay(GetSignerReplay {
                reward_cycle: 7,
                cursors: vec![SignerReplayCursor {
                    signer_public_key: vec![2; 33],
                    lane: SignerLane::StateMachineUpdate as i32,
                    sequence: 9,
                }],
                max_items: 8,
                max_bytes: 64 * 1024,
            })),
        };
        assert_eq!(
            decode_sync_request(&sync_request_envelope(1, &signer_replay).unwrap(), 1).unwrap(),
            signer_replay
        );

        let attachment_page = SyncResponse {
            status: Status::Ok as i32,
            response: Some(sync_response::Response::Attachments(
                AttachmentInventoryPage {
                    items: vec![stacks_network_types::wire::v1::InventoryItem {
                        index: 0,
                        object_id: vec![1; CONTENT_ID_LEN],
                        available: true,
                        kind: ObjectType::Attachment as i32,
                    }],
                    next_cursor: vec![2; ATTACHMENT_HASH_BYTES],
                    complete: false,
                },
            )),
        };
        let envelope = sync_response_envelope(1, &attachment_page).unwrap();
        assert_eq!(decode_sync_response(&envelope, 1).unwrap(), attachment_page);

        let unconfirmed_request = SyncRequest {
            request: Some(sync_request::Request::GetUnconfirmedMicroblocks(
                GetUnconfirmedMicroblocks {
                    parent_block_id: vec![3; CONTENT_ID_LEN],
                    start_sequence: 7,
                    max_items: 8,
                },
            )),
        };
        assert_eq!(
            decode_sync_request(&sync_request_envelope(1, &unconfirmed_request).unwrap(), 1,)
                .unwrap(),
            unconfirmed_request,
        );
        let unconfirmed_page = SyncResponse {
            status: Status::Ok as i32,
            response: Some(sync_response::Response::UnconfirmedMicroblocks(
                MicroblockPage {
                    parent_block_id: vec![3; CONTENT_ID_LEN],
                    microblocks: vec![vec![1, 2, 3]],
                    next_sequence: 8,
                    complete: false,
                },
            )),
        };
        assert!(sync_response_envelope(1, &unconfirmed_page).is_ok());
    }

    #[test]
    fn adversarial_inventory_offsets_are_rejected_or_empty() {
        for start_cycle in [1_u64 << 63, u64::MAX] {
            let request = SyncRequest {
                request: Some(sync_request::Request::GetPoxInventory(GetPoxInventory {
                    start_cycle,
                    count: 1,
                })),
            };
            assert!(validate_sync_request(&request).is_err());
            let envelope = sync_codec(1, EnvelopeKind::SyncRequest, SYNC_REQUEST_DOMAIN)
                .wrap(request.encode_to_vec());
            assert!(decode_sync_request(&envelope, 1).is_err());
        }
        for start_height in [1_u64 << 63, u64::MAX] {
            let request = SyncRequest {
                request: Some(sync_request::Request::GetEpoch2Inventory(
                    GetEpoch2Inventory {
                        start_height,
                        count: 1,
                    },
                )),
            };
            assert!(validate_sync_request(&request).is_err());
            let envelope = sync_codec(1, EnvelopeKind::SyncRequest, SYNC_REQUEST_DOMAIN)
                .wrap(request.encode_to_vec());
            assert!(decode_sync_request(&envelope, 1).is_err());
        }

        let known_end = 42;
        let range = bounded_inventory_range(known_end + 1, 1, known_end);
        assert!(range.is_empty());
        assert_eq!(range.end.saturating_sub(range.start), 0);
        assert_eq!(bounded_inventory_range(40, 8, known_end), 40..42);
    }
}
