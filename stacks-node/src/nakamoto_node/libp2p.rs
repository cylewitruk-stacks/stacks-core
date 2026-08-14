use std::io::{self, Cursor};
use std::sync::Arc;

use stacks::burnchains::Burnchain;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader};
use stacks::chainstate::stacks::db::StacksChainState;
use stacks::chainstate::stacks::{StacksBlockHeader, StacksTransaction};
use stacks::config::Config;
pub use stacks::net::semantic::{
    anchored_block_object, attachment_hash_from_content_id, attachment_object,
    microblock_stream_object, nakamoto_block_object, transaction_object,
};
use stacks::net::semantic::{
    attachment_content_id, decode_anchored_block, decode_attachment, decode_microblock_stream,
    decode_nakamoto_block, decode_transaction,
};
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::{StacksPrivateKey, StacksPublicKey};
use stacks_common::types::PrivateKey;
use stacks_network::{
    node_identity_from_seed, AuthorizationBootstrap, ContentServices, NetworkConfig, NetworkHandle,
    NetworkObjectValidator, NetworkService, PeerEndpoint, PeerStoreConfig, PeerStorePolicy,
    ServiceConfig, TransportBootstrap, TransportProfile,
};
use stacks_network_types::wire::v1::{
    Hello, InventoryItem, InventoryPage, LegacyIdentityBinding, ObjectType,
};
use stacks_network_types::{
    legacy_identity_binding_digest, Announcement, ContentId, NetworkObject, NetworkScope,
    ObjectKind, CAP_NODE_V1, LEGACY_IDENTITY_BINDING_VERSION,
};

const MAX_ANNOUNCEMENT_HEADER_BYTES: usize = 64 * 1024;

/// Bind the stable native PeerId to the incumbent rotating conversation key.
/// This proof intentionally contains no endpoint and is refreshed on every
/// legacy rekey by the peer thread.
pub fn legacy_identity_binding(
    peer_id: libp2p::PeerId,
    chain_id: u32,
    legacy_key: &StacksPrivateKey,
    legacy_key_expire_burn_height: u64,
) -> io::Result<LegacyIdentityBinding> {
    let mut binding = LegacyIdentityBinding {
        version: LEGACY_IDENTITY_BINDING_VERSION,
        chain_id,
        peer_id: peer_id.to_bytes(),
        legacy_node_public_key: StacksPublicKey::from_private(legacy_key).to_bytes_compressed(),
        legacy_key_expire_burn_height,
        signature: vec![0; 65],
    };
    binding.signature = legacy_key
        .sign(&legacy_identity_binding_digest(&binding))
        .map_err(|error| {
            io::Error::other(format!("failed to sign legacy identity binding: {error}"))
        })?
        .as_bytes()
        .to_vec();
    Ok(binding)
}

/// Stacks-domain validation at the transport/hub boundary. This intentionally
/// establishes canonical identity and structural validity only; contextual
/// chain acceptance (tenure, signer set, signatures, and fork choice) remains
/// the relayer/chainstate's responsibility.
#[derive(Default)]
pub struct StacksObjectValidator;

impl NetworkObjectValidator for StacksObjectValidator {
    fn validate_announcement(&self, announcement: &Announcement) -> Result<(), String> {
        if announcement.kind != ObjectKind::NakamotoBlock {
            return Err("v1 only supports Nakamoto block announcements".to_owned());
        }
        let header: NakamotoBlockHeader = decode_exact(
            &announcement.canonical_metadata,
            MAX_ANNOUNCEMENT_HEADER_BYTES,
            "Nakamoto announcement header",
        )?;
        if !header.signer_signature.is_empty() {
            return Err("announcement header must exclude signer signatures".to_owned());
        }
        let expected = ContentId::from_bytes(header.block_id().0);
        if announcement.content_id != expected {
            return Err("announcement block ID does not match its canonical header".to_owned());
        }
        Ok(())
    }

    fn validate_object(&self, object: &NetworkObject) -> Result<(), String> {
        let expected = match object.kind {
            ObjectKind::Transaction => ContentId::from_bytes(decode_transaction(object)?.txid().0),
            ObjectKind::NakamotoBlock => {
                ContentId::from_bytes(decode_nakamoto_block(object)?.header.block_id().0)
            }
            ObjectKind::AnchoredBlock => {
                let (consensus_hash, block) = decode_anchored_block(object)?;
                ContentId::from_bytes(
                    stacks_common::types::chainstate::StacksBlockId::new(
                        &consensus_hash,
                        &block.block_hash(),
                    )
                    .0,
                )
            }
            ObjectKind::Microblock => {
                let (parent_consensus_hash, stream) = decode_microblock_stream(object)?;
                let tail = stream
                    .last()
                    .ok_or_else(|| "confirmed microblock stream is empty".to_owned())?;
                ContentId::from_bytes(
                    StacksBlockHeader::make_index_block_hash(
                        &parent_consensus_hash,
                        &tail.block_hash(),
                    )
                    .0,
                )
            }
            ObjectKind::Attachment => attachment_content_id(&decode_attachment(object)?),
            ObjectKind::BlockProposal => {
                if object.bytes.is_empty()
                    || object.bytes.len() > stacks_network_types::MAX_PROPOSAL_OBJECT_BYTES
                {
                    return Err("proposal object length is outside its bounded range".to_owned());
                }
                stacks_network_types::proposal_content_id(&object.bytes)
            }
        };
        if object.content_id != expected {
            return Err("object content ID does not match its consensus payload".to_owned());
        }
        Ok(())
    }
}

/// Build a native Epoch 2.x wire page from the transport-neutral chainstate
/// availability evaluator. Both node run loops call this helper, and neither
/// transport re-implements block or microblock availability policy. The
/// libp2p-specific work here is limited to materializing the already-
/// authoritative objects in the content hub.
pub fn epoch2_inventory_page(
    burnchain: &Burnchain,
    sortdb: &SortitionDB,
    chainstate: &StacksChainState,
    start_height: u64,
    count: u32,
    network: &NetworkHandle,
) -> Result<InventoryPage, String> {
    let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
        .map_err(|error| error.to_string())?;
    let index = sortdb.index_handle(&tip.sortition_id);
    let range = stacks_network::bounded_inventory_range(
        start_height,
        count,
        tip.block_height.saturating_add(1),
    );
    let requested_end = start_height.saturating_add(u64::from(count));
    let mut snapshots =
        Vec::with_capacity(usize::try_from(range.end.saturating_sub(range.start)).unwrap_or(0));
    for height in range {
        let snapshot = if height == tip.block_height {
            Some(tip.clone())
        } else {
            index
                .get_block_snapshot_by_height(height)
                .map_err(|error| error.to_string())?
        };
        let Some(snapshot) = snapshot else { break };
        snapshots.push((height, snapshot));
    }

    let header_hashes = snapshots
        .iter()
        .map(|(_, snapshot)| {
            (
                snapshot.consensus_hash.clone(),
                snapshot
                    .sortition
                    .then(|| snapshot.winning_stacks_block_hash.clone()),
            )
        })
        .collect::<Vec<_>>();
    let availability = chainstate
        .get_blocks_inventory_for_burnchain_range(burnchain, start_height, &header_hashes)
        .map_err(|error| error.to_string())?;
    let mut items = Vec::with_capacity(snapshots.len().saturating_mul(2));

    for (offset, (height, snapshot)) in snapshots.into_iter().enumerate() {
        let offset = u16::try_from(offset)
            .map_err(|_| "Epoch 2.x inventory page exceeds u16 policy".to_owned())?;
        let block_available = availability.has_ith_block(offset);
        let block = if block_available {
            let block = StacksChainState::load_block(
                &chainstate.blocks_path,
                &snapshot.consensus_hash,
                &snapshot.winning_stacks_block_hash,
            )
            .map_err(|error| error.to_string())?
            .ok_or_else(|| {
                format!(
                    "inventory marked Epoch 2.x block available but object was absent at height {height}"
                )
            })?;
            Some(block)
        } else {
            None
        };
        let (available, object_id) = match block.as_ref() {
            Some(block) => {
                let object = anchored_block_object(&snapshot.consensus_hash, block);
                let object_id = object.content_id.as_bytes().to_vec();
                network
                    .commit_object(object)
                    .map_err(|error| error.to_string())?;
                (true, object_id)
            }
            None => (false, Vec::new()),
        };
        items.push(InventoryItem {
            index: height,
            object_id,
            available,
            kind: ObjectType::AnchoredBlock as i32,
        });

        if !availability.has_ith_microblock_stream(offset) {
            continue;
        }
        let block = block.ok_or_else(|| {
            format!(
                "inventory marked microblocks available without an Epoch 2.x block at height {height}"
            )
        })?;
        let child_id =
            StacksBlockHeader::make_index_block_hash(&snapshot.consensus_hash, &block.block_hash());
        let (parent_consensus_hash, parent_block_hash) =
            StacksChainState::get_parent_block_header_hashes(chainstate.db(), &child_id)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| {
                    format!(
                        "inventory marked microblocks available but the parent was absent at height {height}"
                    )
                })?;
        let stream = StacksChainState::load_processed_microblock_stream_fork(
            chainstate.db(),
            &parent_consensus_hash,
            &parent_block_hash,
            &block.header.parent_microblock,
        )
        .map_err(|error| error.to_string())?
        .filter(|stream| !stream.is_empty())
        .ok_or_else(|| {
            format!(
                "inventory marked microblocks available but the stream was absent at height {height}"
            )
        })?;
        let object = microblock_stream_object(&parent_consensus_hash, &stream)?;
        let object_id = object.content_id.as_bytes().to_vec();
        network
            .commit_object(object)
            .map_err(|error| error.to_string())?;
        items.push(InventoryItem {
            index: height,
            object_id,
            available: true,
            kind: ObjectType::Microblock as i32,
        });
    }

    let next_cursor = items
        .last()
        .map(|item| item.index.saturating_add(1))
        .unwrap_or(start_height);
    Ok(InventoryPage {
        complete: next_cursor > tip.block_height || next_cursor >= requested_end,
        next_cursor,
        items,
    })
}

pub fn nakamoto_block_announcement(block: &NakamotoBlock) -> Announcement {
    let mut canonical_header = block.header.clone();
    canonical_header.signer_signature.clear();
    Announcement {
        kind: ObjectKind::NakamotoBlock,
        content_id: ContentId::from_bytes(block.header.block_id().0),
        canonical_metadata: canonical_header.serialize_to_vec(),
    }
}

pub(super) fn publish_nakamoto_block(
    network: &NetworkHandle,
    block: &NakamotoBlock,
) -> io::Result<()> {
    network.publish_block(
        nakamoto_block_object(block),
        nakamoto_block_announcement(block),
    )
}

pub(super) fn publish_transaction(
    network: &NetworkHandle,
    transaction: &StacksTransaction,
) -> io::Result<()> {
    network.publish_object(transaction_object(transaction))
}

fn decode_exact<T: StacksMessageCodec>(
    bytes: &[u8],
    limit: usize,
    name: &'static str,
) -> Result<T, String> {
    if bytes.len() > limit {
        return Err(format!("{name} exceeds {limit} bytes"));
    }
    let mut cursor = Cursor::new(bytes);
    let value = T::consensus_deserialize(&mut cursor)
        .map_err(|error| format!("invalid {name}: {error}"))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(format!("{name} has trailing bytes"));
    }
    Ok(value)
}

pub fn spawn(config: &Config, burnchain: &Burnchain) -> io::Result<NetworkService> {
    let scope = NetworkScope::new(config.burnchain.chain_id, config.burnchain.chain_id);
    let identity = node_identity_from_seed(&config.node.local_peer_seed, scope)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let listen_addresses = config
        .node
        .libp2p
        .bind
        .iter()
        .map(|address| parse_multiaddr("node.libp2p.bind", address))
        .collect::<io::Result<Vec<_>>>()?;
    let advertised_addresses = config
        .node
        .libp2p
        .advertise
        .iter()
        .map(|address| parse_multiaddr("node.libp2p.advertise", address))
        .collect::<io::Result<Vec<_>>>()?;
    let bootstrap_endpoints = config
        .node
        .libp2p
        .bootstrap_peers
        .iter()
        .map(|address| parse_peer_endpoint("node.libp2p.bootstrap_peers", address))
        .collect::<io::Result<Vec<_>>>()?;
    let bootstrap_addresses = bootstrap_endpoints
        .into_iter()
        .map(PeerEndpoint::into_multiaddr)
        .collect();
    let rendezvous_endpoints = config
        .node
        .libp2p
        .rendezvous_peers
        .iter()
        .map(|address| parse_peer_endpoint("node.libp2p.rendezvous_peers", address))
        .collect::<io::Result<Vec<_>>>()?;
    let private_rendezvous_peers = rendezvous_endpoints
        .iter()
        .map(PeerEndpoint::peer_id)
        .collect();
    // The application network identifier is the Stacks chain ID.  Do not use
    // `Burnchain::network_id` here: that is Bitcoin's wire-network magic and
    // would put otherwise-compatible Stacks peers on distinct protocols.
    // Ordinary full nodes consume blocks, transactions, and historical sync,
    // but are not members of the private signer coordination plane. Keeping
    // them off this topic also prevents unaffiliated nodes from spending
    // validation budget on signer traffic they cannot authorize.
    let direct_push_fanout = if config.node.libp2p.direct_block_push {
        usize::try_from(config.node.libp2p.direct_push_fanout)
            .map_err(|_| io::Error::other("direct push fanout does not fit this platform"))?
    } else {
        0
    };
    let network = NetworkConfig::node_profile(
        scope,
        format!("stacks-node-libp2p/{}", env!("CARGO_PKG_VERSION")),
        &config.node.libp2p.limits,
        config.node.miner,
        config.node.libp2p.kademlia_server,
        direct_push_fanout,
    )
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let hello = Hello {
        envelope_version: 1,
        chain_id: network.chain_id,
        network_id: network.network_id,
        supported_protocol_versions: vec![1],
        peer_version: burnchain.peer_version,
        capabilities: CAP_NODE_V1,
        burn_tip_height: 0,
        burn_tip_hash: Vec::new(),
        stable_burn_tip_height: 0,
        stable_burn_tip_hash: Vec::new(),
        stacks_tip_height: 0,
        stacks_tip_id: Vec::new(),
        current_reward_cycle: 0,
        advertised_multiaddrs: advertised_addresses
            .iter()
            .map(|address| address.to_vec())
            .collect(),
        legacy_identity_binding: None,
        challenge: Vec::new(),
    };
    let peer_store = PeerStoreConfig {
        path: config.get_libp2p_peer_db_file_path().into(),
        chain_id: network.chain_id,
        network_id: network.network_id,
        local_peer_id: identity.public().to_peer_id(),
        policy: PeerStorePolicy {
            max_peers: usize::try_from(config.node.libp2p.limits.max_persisted_peers)
                .map_err(|_| io::Error::other("max_persisted_peers does not fit this platform"))?,
            max_addresses_per_peer: usize::try_from(
                config.node.libp2p.limits.max_persisted_addresses_per_peer,
            )
            .map_err(|_| {
                io::Error::other("max_persisted_addresses_per_peer does not fit this platform")
            })?,
            entry_ttl_secs: config.node.libp2p.limits.peer_store_ttl_secs,
            startup_dial_count: usize::try_from(config.node.libp2p.limits.peer_store_startup_dials)
                .map_err(|_| {
                    io::Error::other("peer_store_startup_dials does not fit this platform")
                })?,
            write_queue_capacity: usize::try_from(config.node.libp2p.limits.peer_store_write_queue)
                .map_err(|_| {
                    io::Error::other("peer_store_write_queue does not fit this platform")
                })?,
        },
    };
    let service = NetworkService::spawn(
        ServiceConfig::new(
            TransportBootstrap {
                identity,
                network,
                transport: TransportProfile::Tcp,
                listen_addresses,
                bootstrap_addresses,
                peer_store: Some(peer_store),
            },
            AuthorizationBootstrap {
                private_rendezvous_peers,
                ..AuthorizationBootstrap::default()
            },
            ContentServices {
                validator: Some(Arc::new(StacksObjectValidator)),
                cache_bytes: usize::try_from(config.node.libp2p.limits.object_cache_bytes)
                    .map_err(|_| {
                        io::Error::other("object cache limit does not fit this platform")
                    })?,
            },
            hello,
        )
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?,
        format!("libp2p:{}", config.node.name),
    )?;
    let generic_stackerdb_state = config.node.generic_stackerdb_replication_state();
    stacks::monitoring::set_libp2p_network_context(serde_json::json!({
        "peer_transport_mode": config.node.libp2p.rollout_mode.as_str(),
        "legacy_listener_enabled": config.node.libp2p.rollout_mode.legacy_listener_enabled(),
        "generic_stackerdb_replication": generic_stackerdb_state.as_str(),
        "generic_stackerdb_replication_reason": generic_stackerdb_state.reason(),
        "generic_stackerdb_contract_count": config.node.generic_stackerdb_contract_count(),
        "signer_bridge_mode": config.node.libp2p.signer_bridge.mode.as_str(),
        "http_rpc_active": true,
        "signer_local_node_http_rpc_required": true,
    }));
    let diagnostics = service.diagnostics();
    info!(
        "Started parallel libp2p network";
        "peer_id" => diagnostics.local_peer_id,
        "configured_listeners" => config.node.libp2p.bind.join(","),
        "peer_transport_mode" => config.node.libp2p.rollout_mode.as_str(),
        "legacy_listener_enabled" => config.node.libp2p.rollout_mode.legacy_listener_enabled(),
        "generic_stackerdb_replication" => generic_stackerdb_state.as_str(),
        "generic_stackerdb_contract_count" => config.node.generic_stackerdb_contract_count(),
        "signer_bridge_mode" => config.node.libp2p.signer_bridge.mode.as_str(),
        "http_rpc_active" => true,
        "signer_local_node_http_rpc_required" => true,
    );
    Ok(service)
}

fn parse_multiaddr(field: &str, address: &str) -> io::Result<libp2p::Multiaddr> {
    address.parse().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid {field} multiaddress {address:?}: {error}"),
        )
    })
}

fn parse_peer_endpoint(field: &str, address: &str) -> io::Result<PeerEndpoint> {
    address.parse().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid {field} peer endpoint {address:?}: {error}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use stacks::chainstate::burn::ConsensusHash;
    use stacks::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader};
    use stacks::chainstate::stacks::StacksBlock;
    use stacks::core::test_util::make_coinbase_tx;
    use stacks::net::atlas::Attachment;
    use stacks_common::util::hash::{MerkleTree, Sha512Trunc256Sum};
    use stacks_common::util::secp256k1::{MessageSignature, Secp256k1PrivateKey};

    use super::*;

    #[test]
    fn transaction_objects_use_consensus_ids_and_exact_bounded_decoding() {
        let private_key = Secp256k1PrivateKey::from_seed(b"libp2p-object-validator");
        let transaction = make_coinbase_tx(&private_key, 0, 0, 0x8000_0000);
        let object = transaction_object(&transaction);
        let validator = StacksObjectValidator;

        validator.validate_object(&object).unwrap();
        assert_eq!(decode_transaction(&object).unwrap(), transaction);

        let mut trailing = object.clone();
        trailing.bytes.push(0);
        assert!(validator.validate_object(&trailing).is_err());

        let mut wrong_id = object;
        wrong_id.content_id = ContentId::from_bytes([9; 32]);
        assert!(validator.validate_object(&wrong_id).is_err());
    }

    #[test]
    fn epoch2_objects_bind_consensus_context_and_decode_exactly() {
        let consensus_hash = ConsensusHash([7; 20]);
        let private_key = Secp256k1PrivateKey::from_seed(b"libp2p-epoch2-object");
        let mut block = StacksBlock::genesis_block();
        block
            .txs
            .push(make_coinbase_tx(&private_key, 0, 0, 0x8000_0000));
        let txids = block
            .txs
            .iter()
            .map(|tx| tx.txid().as_bytes().to_vec())
            .collect::<Vec<_>>();
        block.header.tx_merkle_root = MerkleTree::<Sha512Trunc256Sum>::new(&txids).root();
        let object = anchored_block_object(&consensus_hash, &block);
        let validator = StacksObjectValidator;

        validator.validate_object(&object).unwrap();
        assert_eq!(
            decode_anchored_block(&object).unwrap(),
            (consensus_hash, block)
        );

        let mut changed_context = object.clone();
        changed_context.bytes[0] ^= 1;
        assert!(validator.validate_object(&changed_context).is_err());

        let mut trailing = object;
        trailing.bytes.push(0);
        assert!(validator.validate_object(&trailing).is_err());
    }

    #[test]
    fn attachment_objects_preserve_the_incumbent_hash_and_enforce_bounds() {
        let attachment = Attachment::new(b"bounded-atlas-content".to_vec());
        let object = attachment_object(&attachment);
        let validator = StacksObjectValidator;

        validator.validate_object(&object).unwrap();
        assert_eq!(decode_attachment(&object).unwrap(), attachment);
        assert_eq!(
            attachment_hash_from_content_id(&object.content_id),
            Some(attachment.hash())
        );

        let mut changed = object.clone();
        changed.bytes.push(0);
        assert!(validator.validate_object(&changed).is_err());

        let oversized = attachment_object(&Attachment::new(vec![0; 1024 * 1024 + 1]));
        assert!(validator.validate_object(&oversized).is_err());
    }

    #[test]
    fn announcement_commits_to_miner_signature_and_excludes_signer_signatures() {
        let mut block = NakamotoBlock::new(NakamotoBlockHeader::empty(), Vec::new());
        block.header.miner_signature = MessageSignature([1; 65]);
        block.header.signer_signature = vec![MessageSignature([2; 65])];

        let announcement = nakamoto_block_announcement(&block);
        let validator = StacksObjectValidator;
        validator.validate_announcement(&announcement).unwrap();

        let announced_header: NakamotoBlockHeader = decode_exact(
            &announcement.canonical_metadata,
            MAX_ANNOUNCEMENT_HEADER_BYTES,
            "test header",
        )
        .unwrap();
        assert_eq!(announced_header.miner_signature, MessageSignature([1; 65]));
        assert!(announced_header.signer_signature.is_empty());
        assert_eq!(announced_header.block_id(), block.header.block_id());

        let mut different_miner = block.clone();
        different_miner.header.miner_signature = MessageSignature([3; 65]);
        assert_ne!(
            nakamoto_block_announcement(&different_miner).content_id,
            announcement.content_id
        );

        let mut trailing = announcement;
        trailing.canonical_metadata.push(0);
        assert!(validator.validate_announcement(&trailing).is_err());
    }
}
