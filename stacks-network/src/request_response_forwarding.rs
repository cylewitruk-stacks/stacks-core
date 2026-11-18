// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! One forwarding shell for the bounded Stacks request-response behaviours.
//!
//! A generic wrapper was deliberately avoided: rust-libp2p's associated
//! connection-handler types would force the domain policy to borrow both its
//! wrapper and the inner request-response behaviour during protocol-event
//! handling. This narrow macro keeps each concrete codec and event type in the
//! type system while defining the security-neutral forwarding exactly once.
//! Domain lifecycle and timer work remains visible through the two required
//! inherent hooks.

macro_rules! impl_bounded_request_response_behaviour {
    ($behaviour:ty, $event:ty) => {
        impl libp2p::swarm::NetworkBehaviour for $behaviour {
            type ConnectionHandler = <libp2p::request_response::Behaviour<
                crate::BoundedEnvelopeCodec,
            > as libp2p::swarm::NetworkBehaviour>::ConnectionHandler;
            type ToSwarm = $event;

            fn handle_pending_inbound_connection(
                &mut self,
                connection_id: libp2p::swarm::ConnectionId,
                local_addr: &libp2p::Multiaddr,
                remote_addr: &libp2p::Multiaddr,
            ) -> Result<(), libp2p::swarm::ConnectionDenied> {
                self.protocol.handle_pending_inbound_connection(
                    connection_id,
                    local_addr,
                    remote_addr,
                )
            }

            fn handle_pending_outbound_connection(
                &mut self,
                connection_id: libp2p::swarm::ConnectionId,
                maybe_peer: Option<libp2p::PeerId>,
                addresses: &[libp2p::Multiaddr],
                effective_role: libp2p::core::Endpoint,
            ) -> Result<Vec<libp2p::Multiaddr>, libp2p::swarm::ConnectionDenied> {
                self.protocol.handle_pending_outbound_connection(
                    connection_id,
                    maybe_peer,
                    addresses,
                    effective_role,
                )
            }

            fn handle_established_inbound_connection(
                &mut self,
                connection_id: libp2p::swarm::ConnectionId,
                peer: libp2p::PeerId,
                local_addr: &libp2p::Multiaddr,
                remote_addr: &libp2p::Multiaddr,
            ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
                self.protocol.handle_established_inbound_connection(
                    connection_id,
                    peer,
                    local_addr,
                    remote_addr,
                )
            }

            fn handle_established_outbound_connection(
                &mut self,
                connection_id: libp2p::swarm::ConnectionId,
                peer: libp2p::PeerId,
                addr: &libp2p::Multiaddr,
                role_override: libp2p::core::Endpoint,
                port_use: libp2p::core::transport::PortUse,
            ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
                self.protocol.handle_established_outbound_connection(
                    connection_id,
                    peer,
                    addr,
                    role_override,
                    port_use,
                )
            }

            fn on_swarm_event(&mut self, event: libp2p::swarm::FromSwarm) {
                self.on_forwarded_swarm_event(&event);
                self.protocol.on_swarm_event(event);
            }

            fn on_connection_handler_event(
                &mut self,
                peer_id: libp2p::PeerId,
                connection_id: libp2p::swarm::ConnectionId,
                event: libp2p::swarm::THandlerOutEvent<Self>,
            ) {
                self.protocol
                    .on_connection_handler_event(peer_id, connection_id, event);
            }

            fn poll(
                &mut self,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<
                libp2p::swarm::ToSwarm<Self::ToSwarm, libp2p::swarm::THandlerInEvent<Self>>,
            > {
                self.poll_scheduled(cx);
                if let Some(event) = self.events.pop_front() {
                    return std::task::Poll::Ready(libp2p::swarm::ToSwarm::GenerateEvent(event));
                }
                loop {
                    match std::task::ready!(self.protocol.poll(cx)) {
                        libp2p::swarm::ToSwarm::GenerateEvent(event) => {
                            self.on_protocol_event(event);
                            if let Some(event) = self.events.pop_front() {
                                return std::task::Poll::Ready(
                                    libp2p::swarm::ToSwarm::GenerateEvent(event),
                                );
                            }
                        }
                        other => return std::task::Poll::Ready(other.map_out(|_| unreachable!())),
                    }
                }
            }
        }
    };
}
