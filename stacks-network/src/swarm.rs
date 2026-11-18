use std::io;
use std::time::Duration;

use libp2p::identity;
use libp2p::swarm::{Config as SwarmConfig, Swarm};

use crate::{memory_transport, tcp_transport, NetworkConfig, StacksBehaviour};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportProfile {
    Tcp,
    Memory,
}

pub fn build_swarm(
    identity: &identity::Keypair,
    network_config: &NetworkConfig,
    transport_profile: TransportProfile,
) -> io::Result<Swarm<StacksBehaviour>> {
    network_config
        .validate()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let transport = match transport_profile {
        TransportProfile::Tcp => tcp_transport(identity)?,
        TransportProfile::Memory => memory_transport(identity)?,
    };
    let behaviour = StacksBehaviour::new(identity, network_config)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    Ok(Swarm::new(
        transport,
        behaviour,
        identity.public().to_peer_id(),
        SwarmConfig::with_tokio_executor().with_idle_connection_timeout(Duration::from_secs(60)),
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use futures::StreamExt;
    use libp2p::request_response::{Event as RequestResponseEvent, Message};
    use libp2p::swarm::SwarmEvent;
    use libp2p::Multiaddr;
    use libp2p_swarm_test::SwarmExt;
    use prost::Message as ProstMessage;
    use stacks_common::types::chainstate::{StacksPrivateKey, StacksPublicKey};
    use stacks_common::types::PrivateKey;
    use stacks_network_types::wire::v1::{
        sync_request, sync_response, GetStatus, GetUnconfirmedMicroblocks, Hello, MicroblockPage,
        SignerEnvelope, SignerEnvelopeBody, SignerLane, Status, SyncRequest, SyncResponse,
        SyncStatus,
    };
    use stacks_network_types::{
        signer_envelope_digest, ContentId, NetworkObject, ObjectKind, CAP_NODE_V1,
        SIGNER_ENVELOPE_VERSION,
    };

    use super::*;
    use crate::identity::node_identity_from_seed;
    use crate::{
        hello_response_envelope, signer_topic, validate_hello, AuthenticatedGossip,
        ContentExchangeEvent, StacksBehaviourEvent, SyncBehaviourEvent,
    };

    static NEXT_MEMORY_PORT: AtomicU64 = AtomicU64::new(10_000);

    fn memory_address() -> Multiaddr {
        format!(
            "/memory/{}",
            NEXT_MEMORY_PORT.fetch_add(1, Ordering::Relaxed)
        )
        .parse()
        .unwrap()
    }

    fn hello(config: &NetworkConfig) -> Hello {
        Hello {
            envelope_version: 1,
            chain_id: config.chain_id,
            network_id: config.network_id,
            supported_protocol_versions: vec![1],
            peer_version: 1,
            capabilities: CAP_NODE_V1,
            burn_tip_height: 0,
            burn_tip_hash: vec![],
            stable_burn_tip_height: 0,
            stable_burn_tip_hash: vec![],
            stacks_tip_height: 0,
            stacks_tip_id: vec![],
            current_reward_cycle: 0,
            advertised_multiaddrs: vec![],
            legacy_identity_binding: None,
            challenge: vec![42; 32],
        }
    }

    #[tokio::test]
    async fn swarm_test_helpers_orchestrate_parallel_stacks_noise_memory_swarms() {
        let runs = (0_u8..4).map(|run| async move {
            let mut config = NetworkConfig::regtest();
            config.max_process_memory_bytes = usize::MAX;
            let alice_key = node_identity_from_seed(&[b'a', run], config.scope()).unwrap();
            let bob_key = node_identity_from_seed(&[b'b', run], config.scope()).unwrap();
            // Construct production-shaped Stacks swarms. In particular, do
            // not use SwarmExt::new_ephemeral_tokio: upstream's convenience
            // swarm intentionally uses plaintext instead of Noise.
            let mut alice = build_swarm(&alice_key, &config, TransportProfile::Memory).unwrap();
            let mut bob = build_swarm(&bob_key, &config, TransportProfile::Memory).unwrap();
            let listen_address = memory_address();
            bob.listen_on(listen_address).unwrap();
            let bound = loop {
                if let SwarmEvent::NewListenAddr { address, .. } = bob.next_swarm_event().await {
                    break address;
                }
            };
            // SwarmExt::connect deliberately reads external_addresses.
            bob.add_external_address(bound);
            alice.connect(&mut bob).await;
            assert!(alice.is_connected(bob.local_peer_id()));
            assert!(bob.is_connected(alice.local_peer_id()));
        });
        futures::future::join_all(runs).await;
    }

    #[tokio::test]
    async fn real_memory_swarms_complete_noise_yamux_and_hello() {
        let mut config = NetworkConfig::regtest();
        config.max_process_memory_bytes = usize::MAX;
        let alice_key = node_identity_from_seed(b"alice", config.scope()).unwrap();
        let bob_key = node_identity_from_seed(b"bob", config.scope()).unwrap();
        let mut alice = build_swarm(&alice_key, &config, TransportProfile::Memory).unwrap();
        let mut bob = build_swarm(&bob_key, &config, TransportProfile::Memory).unwrap();
        let bob_address = memory_address();
        bob.listen_on(bob_address.clone()).unwrap();

        let bob_listen = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let SwarmEvent::NewListenAddr { address, .. } = bob.select_next_some().await {
                    break address;
                }
            }
        })
        .await
        .expect("bob listens");
        alice.dial(bob_listen).unwrap();

        let mut request_sent = false;
        let completed = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = alice.select_next_some() => match event {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == *bob.local_peer_id() && !request_sent => {
                            alice.behaviour_mut().application_mut().begin_handshake(peer_id, hello(&config)).unwrap();
                            request_sent = true;
                        }
                        SwarmEvent::Behaviour(StacksBehaviourEvent::RequestResponse(RequestResponseEvent::Message {
                            peer, message: Message::Response { response, .. }, ..
                        })) => {
                            assert!(alice.behaviour().application().is_peer_authenticated(&peer));
                            let _ = response;
                            break true;
                        }
                        _ => {}
                    },
                    event = bob.select_next_some() => {
                        if let SwarmEvent::Behaviour(StacksBehaviourEvent::RequestResponse(RequestResponseEvent::Message {
                            message: Message::Request { request, channel, .. }, ..
                        })) = event {
                            let request = validate_hello(&request, config.scope()).unwrap();
                            let response = hello_response_envelope(&hello(&config), request.challenge).unwrap();
                            bob.behaviour_mut().application_mut().send_hello_response(channel, response).unwrap();
                        }
                    }
                }
            }
        }).await.expect("hello completes before timeout");
        assert!(completed);
    }

    #[tokio::test]
    async fn discovery_bootstrap_and_identify_addresses_are_hello_gated_over_noise_memory() {
        let mut config = NetworkConfig::regtest();
        config.max_process_memory_bytes = usize::MAX;
        let alice_key = node_identity_from_seed(b"discovery-alice", config.scope()).unwrap();
        let bob_key = node_identity_from_seed(b"discovery-bob", config.scope()).unwrap();
        let mut alice = build_swarm(&alice_key, &config, TransportProfile::Memory).unwrap();
        let mut bob = build_swarm(&bob_key, &config, TransportProfile::Memory).unwrap();
        let bob_peer = *bob.local_peer_id();
        bob.listen_on(memory_address()).unwrap();
        let bob_listen = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = bob.next_swarm_event().await {
                break address;
            }
        };
        let bootstrap: Multiaddr = format!("{bob_listen}/p2p/{bob_peer}").parse().unwrap();
        alice
            .behaviour_mut()
            .add_bootstrap_address(bootstrap)
            .unwrap();

        let mut alice_started_hello = false;
        let mut bob_started_hello = false;
        let mut observed_gated_identify = false;
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = alice.select_next_some() => match event {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == bob_peer && !alice_started_hello => {
                            alice.behaviour_mut().application_mut().begin_handshake(peer_id, hello(&config)).unwrap();
                            alice_started_hello = true;
                        }
                        SwarmEvent::Behaviour(StacksBehaviourEvent::Discovery(crate::DiscoveryEvent::PeerAddressesChanged {
                            peer,
                            usable,
                            ..
                        })) if peer == bob_peer => {
                            assert!(
                                !usable
                                    || alice
                                        .behaviour()
                                        .application()
                                        .is_peer_authenticated(&peer),
                                "Identify must not make addresses usable before Hello",
                            );
                            observed_gated_identify = true;
                        }
                        SwarmEvent::Behaviour(StacksBehaviourEvent::RequestResponse(RequestResponseEvent::Message {
                            peer,
                            message: Message::Request { request, channel, .. },
                            ..
                        })) => {
                            let request = validate_hello(&request, config.scope()).unwrap();
                            let response = hello_response_envelope(&hello(&config), request.challenge).unwrap();
                            alice.behaviour_mut().application_mut().send_hello_response(channel, response).unwrap();
                            alice.behaviour_mut().authenticate_discovery_peer(peer);
                        }
                        SwarmEvent::Behaviour(StacksBehaviourEvent::RequestResponse(RequestResponseEvent::Message {
                            peer,
                            message: Message::Response { .. },
                            ..
                        })) if peer == bob_peer => {
                            alice.behaviour_mut().authenticate_discovery_peer(peer);
                        }
                        _ => {}
                    },
                    event = bob.select_next_some() => match event {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } if !bob_started_hello => {
                            bob.behaviour_mut().application_mut().begin_handshake(peer_id, hello(&config)).unwrap();
                            bob_started_hello = true;
                        }
                        SwarmEvent::Behaviour(StacksBehaviourEvent::RequestResponse(RequestResponseEvent::Message {
                            peer,
                            message: Message::Request { request, channel, .. },
                            ..
                        })) => {
                            let request = validate_hello(&request, config.scope()).unwrap();
                            let response = hello_response_envelope(&hello(&config), request.challenge).unwrap();
                            bob.behaviour_mut().application_mut().send_hello_response(channel, response).unwrap();
                            bob.behaviour_mut().authenticate_discovery_peer(peer);
                        }
                        SwarmEvent::Behaviour(StacksBehaviourEvent::RequestResponse(RequestResponseEvent::Message {
                            peer,
                            message: Message::Response { .. },
                            ..
                        })) => {
                            bob.behaviour_mut().authenticate_discovery_peer(peer);
                        }
                        _ => {}
                    }
                }
                if observed_gated_identify
                    && alice.behaviour().discovery_addresses_are_usable(&bob_peer)
                {
                    break;
                }
            }
        })
        .await
        .expect("bootstrap, Noise/Yamux, Identify, and Hello complete without sleeps");
        assert!(!alice.behaviour().discovered_addresses(&bob_peer).is_empty());
    }

    #[tokio::test]
    async fn pre_hello_application_request_is_rejected_inside_the_behaviour() {
        let mut config = NetworkConfig::regtest();
        config.max_process_memory_bytes = usize::MAX;
        let alice_key = node_identity_from_seed(b"pre-hello-alice", config.scope()).unwrap();
        let bob_key = node_identity_from_seed(b"pre-hello-bob", config.scope()).unwrap();
        let mut alice = build_swarm(&alice_key, &config, TransportProfile::Memory).unwrap();
        let mut bob = build_swarm(&bob_key, &config, TransportProfile::Memory).unwrap();
        let bob_peer = *bob.local_peer_id();
        let address = memory_address();
        bob.listen_on(address).unwrap();
        let bound = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = bob.next_swarm_event().await {
                break address;
            }
        };
        alice.dial(bound).unwrap();

        let mut sent = false;
        let mut receiver_rejected = false;
        let mut sender_observed_bounded_response = false;
        tokio::time::timeout(Duration::from_secs(10), async {
            while !receiver_rejected || !sender_observed_bounded_response {
                tokio::select! {
                    event = alice.select_next_some() => match event {
                        SwarmEvent::ConnectionEstablished { .. } if !sent => {
                            let request = crate::content_request_envelope(
                                config.chain_id,
                                stacks_network_types::ObjectKind::NakamotoBlock,
                                stacks_network_types::ContentId::from_bytes([7; 32]),
                            );
                            assert_eq!(
                                alice.behaviour_mut().application_mut().start_content_fetch(
                                    stacks_network_types::ObjectKind::NakamotoBlock,
                                    stacks_network_types::ContentId::from_bytes([7; 32]),
                                    [bob_peer],
                                ),
                                Err(crate::ApplicationGateError::Unauthenticated),
                            );
                            alice.behaviour_mut().application_mut()
                                .send_content_request_unchecked(&bob_peer, request);
                            sent = true;
                        }
                        SwarmEvent::Behaviour(StacksBehaviourEvent::Content(_)) => {
                            panic!("pre-Hello response escaped the application gate")
                        }
                        SwarmEvent::Behaviour(StacksBehaviourEvent::PreHelloRejected {
                            protocol: crate::ApplicationProtocol::Content,
                            ..
                        }) => sender_observed_bounded_response = true,
                        _ => {}
                    },
                    event = bob.select_next_some() => match event {
                        SwarmEvent::Behaviour(StacksBehaviourEvent::Content(_)) => {
                            panic!("pre-Hello request reached the application service boundary")
                        }
                        SwarmEvent::Behaviour(StacksBehaviourEvent::PreHelloRejected {
                            protocol: crate::ApplicationProtocol::Content,
                            ..
                        }) => receiver_rejected = true,
                        _ => {}
                    }
                }
            }
        })
        .await
        .expect("pre-Hello rejection is bounded and event-driven");
    }

    #[tokio::test]
    async fn sync_and_content_behaviours_round_trip_over_noise_memory() {
        let mut config = NetworkConfig::regtest();
        config.max_process_memory_bytes = usize::MAX;
        let alice_key = node_identity_from_seed(b"semantic-alice", config.scope()).unwrap();
        let bob_key = node_identity_from_seed(b"semantic-bob", config.scope()).unwrap();
        let mut alice = build_swarm(&alice_key, &config, TransportProfile::Memory).unwrap();
        let mut bob = build_swarm(&bob_key, &config, TransportProfile::Memory).unwrap();
        let alice_peer = *alice.local_peer_id();
        let bob_peer = *bob.local_peer_id();
        bob.listen_on(memory_address()).unwrap();
        let bound = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = bob.next_swarm_event().await {
                break address;
            }
        };
        alice.dial(bound).unwrap();

        let content_id = ContentId::from_bytes([0x55; 32]);
        let object = NetworkObject {
            kind: ObjectKind::Attachment,
            content_id,
            bytes: b"bounded-semantic-object".to_vec(),
        };
        let mut alice_started_hello = false;
        let mut bob_started_hello = false;
        let mut requests_started = false;
        let mut sync_complete = false;
        let mut unconfirmed_complete = false;
        let mut content_complete = false;

        tokio::time::timeout(Duration::from_secs(10), async {
            while !sync_complete || !unconfirmed_complete || !content_complete {
                tokio::select! {
                    event = alice.select_next_some() => match event {
                        SwarmEvent::ConnectionEstablished { peer_id, .. }
                            if peer_id == bob_peer && !alice_started_hello =>
                        {
                            alice.behaviour_mut().application_mut()
                                .begin_handshake(peer_id, hello(&config)).unwrap();
                            alice_started_hello = true;
                        }
                        SwarmEvent::Behaviour(StacksBehaviourEvent::RequestResponse(
                            RequestResponseEvent::Message {
                                message: Message::Request { request, channel, .. }, ..
                            }
                        )) => {
                            let request = validate_hello(
                                &request, config.scope()
                            ).unwrap();
                            let response = hello_response_envelope(
                                &hello(&config), request.challenge
                            ).unwrap();
                            alice.behaviour_mut().application_mut()
                                .send_hello_response(channel, response).unwrap();
                        }
                        SwarmEvent::Behaviour(StacksBehaviourEvent::Sync(
                            SyncBehaviourEvent::Response {
                                owner: crate::SyncRequestOwner::ExternalManaged {
                                    correlation_id: 41,
                                },
                                response: Ok(response),
                                ..
                            }
                        )) => {
                            assert!(matches!(
                                response.response,
                                Some(sync_response::Response::StatusView(SyncStatus {
                                    burn_tip_height: 123,
                                    ..
                                }))
                            ));
                            sync_complete = true;
                            alice.behaviour_mut().application_mut().start_sync_request(
                                [bob_peer],
                                SyncRequest {
                                    request: Some(sync_request::Request::GetUnconfirmedMicroblocks(
                                        GetUnconfirmedMicroblocks {
                                            parent_block_id: vec![9; 32],
                                            start_sequence: 4,
                                            max_items: 8,
                                        },
                                    )),
                                },
                                42,
                                1,
                                Duration::from_millis(50),
                            ).unwrap();
                        }
                        SwarmEvent::Behaviour(StacksBehaviourEvent::Sync(
                            SyncBehaviourEvent::Response {
                                owner: crate::SyncRequestOwner::ExternalManaged {
                                    correlation_id: 42,
                                },
                                response: Ok(response),
                                ..
                            }
                        )) => {
                            assert!(matches!(
                                response.response,
                                Some(sync_response::Response::UnconfirmedMicroblocks(
                                    MicroblockPage { next_sequence: 4, complete: true, .. }
                                ))
                            ));
                            unconfirmed_complete = true;
                        }
                        SwarmEvent::Behaviour(StacksBehaviourEvent::Content(
                            ContentExchangeEvent::Fetched { object: received, .. }
                        )) => {
                            assert_eq!(received, object);
                            content_complete = true;
                        }
                        _ => {}
                    },
                    event = bob.select_next_some() => match event {
                        SwarmEvent::ConnectionEstablished { peer_id, .. }
                            if peer_id == alice_peer && !bob_started_hello =>
                        {
                            bob.behaviour_mut().application_mut()
                                .begin_handshake(peer_id, hello(&config)).unwrap();
                            bob_started_hello = true;
                        }
                        SwarmEvent::Behaviour(StacksBehaviourEvent::RequestResponse(
                            RequestResponseEvent::Message {
                                message: Message::Request { request, channel, .. }, ..
                            }
                        )) => {
                            let request = validate_hello(
                                &request, config.scope()
                            ).unwrap();
                            let response = hello_response_envelope(
                                &hello(&config), request.challenge
                            ).unwrap();
                            bob.behaviour_mut().application_mut()
                                .send_hello_response(channel, response).unwrap();
                        }
                        SwarmEvent::Behaviour(StacksBehaviourEvent::Sync(
                            SyncBehaviourEvent::InboundRequest {
                                response_token,
                                request,
                                ..
                            }
                        )) => {
                            let response = match request.request {
                                Some(sync_request::Request::GetStatus(GetStatus {})) => {
                                    sync_response::Response::StatusView(SyncStatus {
                                        burn_tip_height: 123,
                                        burn_tip_hash: vec![1; 32],
                                        stable_burn_tip_height: 120,
                                        stable_burn_tip_hash: vec![2; 32],
                                        stacks_tip_height: 99,
                                        stacks_tip_id: vec![3; 32],
                                        current_reward_cycle: 7,
                                    })
                                }
                                Some(sync_request::Request::GetUnconfirmedMicroblocks(request)) => {
                                    sync_response::Response::UnconfirmedMicroblocks(MicroblockPage {
                                        parent_block_id: request.parent_block_id,
                                        microblocks: Vec::new(),
                                        next_sequence: request.start_sequence,
                                        complete: true,
                                    })
                                }
                                other => panic!("unexpected sync request: {other:?}"),
                            };
                            bob.behaviour_mut().application_mut().respond_sync(
                                response_token,
                                SyncResponse {
                                    status: Status::Ok as i32,
                                    response: Some(response),
                                },
                            ).unwrap();
                        }
                        SwarmEvent::Behaviour(StacksBehaviourEvent::Content(
                            ContentExchangeEvent::InboundFetch {
                                response_token,
                                kind,
                                id,
                                ..
                            }
                        )) => {
                            assert_eq!(kind, ObjectKind::Attachment);
                            assert_eq!(id, content_id);
                            bob.behaviour_mut().application_mut().respond_content_fetch(
                                response_token,
                                Status::Ok,
                                Some(&object),
                            ).unwrap();
                        }
                        _ => {}
                    }
                }

                if !requests_started
                    && alice
                        .behaviour()
                        .application()
                        .is_peer_authenticated(&bob_peer)
                    && bob
                        .behaviour()
                        .application()
                        .is_peer_authenticated(&alice_peer)
                {
                    alice
                        .behaviour_mut()
                        .application_mut()
                        .start_sync_request(
                            [bob_peer],
                            SyncRequest {
                                request: Some(sync_request::Request::GetStatus(GetStatus {})),
                            },
                            41,
                            1,
                            Duration::from_millis(50),
                        )
                        .unwrap();
                    assert_eq!(
                        alice.behaviour_mut().application_mut().start_content_fetch(
                            ObjectKind::Attachment,
                            content_id,
                            [bob_peer],
                        ),
                        Ok(true),
                    );
                    requests_started = true;
                }
            }
        })
        .await
        .expect("sync and content complete over production Noise/Yamux memory transport");
    }

    #[tokio::test]
    async fn memory_swarms_deliver_role_signed_signer_envelope() {
        let mut config = NetworkConfig::regtest();
        config.max_process_memory_bytes = usize::MAX;
        let alice_key = node_identity_from_seed(b"signer-envelope-alice", config.scope()).unwrap();
        let bob_key = node_identity_from_seed(b"signer-envelope-bob", config.scope()).unwrap();
        let mut alice = build_swarm(&alice_key, &config, TransportProfile::Memory).unwrap();
        let mut bob = build_swarm(&bob_key, &config, TransportProfile::Memory).unwrap();
        let bob_peer_id = *bob.local_peer_id();
        let bob_address = memory_address();
        bob.listen_on(bob_address).unwrap();

        let bob_listen = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let SwarmEvent::NewListenAddr { address, .. } = bob.select_next_some().await {
                    break address;
                }
            }
        })
        .await
        .expect("bob listens");
        alice.dial(bob_listen).unwrap();

        let signer_key = StacksPrivateKey::from_seed(&[7; 32]);
        let body = SignerEnvelopeBody {
            version: SIGNER_ENVELOPE_VERSION,
            chain_id: config.chain_id,
            network_id: config.network_id,
            reward_cycle: 9,
            lane: SignerLane::Control as i32,
            sequence: 4,
            previous_envelope_id: Vec::new(),
            signer_public_key: StacksPublicKey::from_private(&signer_key).to_bytes_compressed(),
            transport_peer_id: bob_peer_id.to_bytes(),
            payload: b"semantic-control-fixture".to_vec(),
            burn_view_consensus_hash: vec![0; 20],
            proposal_manifest: None,
        };
        let signature = signer_key.sign(&signer_envelope_digest(&body)).unwrap();
        let envelope = SignerEnvelope {
            body: Some(body),
            signature: signature.as_bytes().to_vec(),
        };
        let mut alice_started = false;
        let mut bob_started = false;
        let mut alice_authenticated_bob = false;
        let mut bob_authenticated_alice = false;
        let mut published = false;

        let verified = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = alice.select_next_some() => {
                        match event {
                            SwarmEvent::ConnectionEstablished { peer_id, .. } if !alice_started => {
                                alice.behaviour_mut().application_mut().begin_handshake(peer_id, hello(&config)).unwrap();
                                alice_started = true;
                            }
                            SwarmEvent::Behaviour(StacksBehaviourEvent::RequestResponse(RequestResponseEvent::Message {
                                message: Message::Request { request, channel, .. }, ..
                            })) => {
                                let request = validate_hello(&request, config.scope()).unwrap();
                                let response = hello_response_envelope(&hello(&config), request.challenge).unwrap();
                                alice.behaviour_mut().application_mut().send_hello_response(channel, response).unwrap();
                            }
                            SwarmEvent::Behaviour(StacksBehaviourEvent::RequestResponse(RequestResponseEvent::Message {
                                message: Message::Response { .. }, ..
                            })) => alice_authenticated_bob = true,
                            SwarmEvent::Behaviour(StacksBehaviourEvent::Gossip(message)) => {
                                let AuthenticatedGossip::Signer(staged) = message.payload else {
                                    continue;
                                };
                                break staged.envelope;
                            }
                            _ => {}
                        }
                    },
                    event = bob.select_next_some() => {
                        match event {
                            SwarmEvent::ConnectionEstablished { peer_id, .. } if !bob_started => {
                                bob.behaviour_mut().application_mut().begin_handshake(peer_id, hello(&config)).unwrap();
                                bob_started = true;
                            }
                            SwarmEvent::Behaviour(StacksBehaviourEvent::RequestResponse(RequestResponseEvent::Message {
                                message: Message::Request { request, channel, .. }, ..
                            })) => {
                                let request = validate_hello(&request, config.scope()).unwrap();
                                let response = hello_response_envelope(&hello(&config), request.challenge).unwrap();
                                bob.behaviour_mut().application_mut().send_hello_response(channel, response).unwrap();
                            }
                            SwarmEvent::Behaviour(StacksBehaviourEvent::RequestResponse(RequestResponseEvent::Message {
                                message: Message::Response { .. }, ..
                            })) => bob_authenticated_alice = true,
                            _ => {}
                        }
                        if alice_authenticated_bob && bob_authenticated_alice && !published {
                            published = bob.behaviour_mut().application_mut().publish_gossip(
                                signer_topic(config.chain_id, config.network_id),
                                envelope.encode_to_vec(),
                            ).is_ok();
                        }
                    }
                }
            }
        })
        .await
        .expect("semantic signer envelope arrives before timeout");
        assert_eq!(verified.body.payload, b"semantic-control-fixture");
    }
}
