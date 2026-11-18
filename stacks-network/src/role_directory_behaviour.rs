// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Private role-directory wire, authorization, retention, and query policy.
//!
//! The service loop supplies only cross-protocol resource-budget decisions.
//! Wire messages remain retained behind opaque action tokens until admitted,
//! so expensive signature and directory work cannot bypass that budget.

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::task::Context;
use std::time::Duration;

use futures_timer::Delay;
use libp2p::request_response::{self, OutboundRequestId, ResponseChannel};
use libp2p::swarm::{ConnectionId, FromSwarm};
use libp2p::{Multiaddr, PeerId};
use prost::Message as ProstMessage;
use stacks_network_types::wire::v1::{
    Role, RoleDirectoryQuery, RoleDirectoryRecord, RoleDirectoryResponse, Status,
};
use stacks_network_types::{
    supports, EnvelopeLimits, NetworkEnvelope, NetworkScope, RewardCycleWindow, CAP_ROLE_DIRECTORY,
};

use crate::{
    decode_directory_query, decode_directory_response, directory_query_envelope,
    directory_response_envelope, AuthorizationSnapshot, AuthorizationSnapshotError,
    AuthorizationSnapshotState, AuthorizationSnapshotUpdate, BoundedEnvelopeCodec, DirectoryView,
    RoleAuthorizations, RoleDirectory, VerifiedDirectoryRecord, MAX_DIRECTORY_QUERY_RECORDS,
};

const DIRECTORY_TICK: Duration = Duration::from_secs(5);
const MAX_PENDING_DIRECTORY_ACTIONS: usize = 256;

#[derive(Debug)]
pub enum RoleDirectoryBehaviourEvent {
    /// A bounded wire request retained until the shared resource service calls
    /// `admit_action` or `reject_action`.
    AdmissionRequired {
        token: u64,
        peer: PeerId,
        connection_id: ConnectionId,
        encoded_bytes: usize,
        validation_units: u64,
        direction: DirectoryDirection,
    },
    RecordAccepted {
        source: PeerId,
        record: Box<VerifiedDirectoryRecord>,
    },
    QueryCompleted {
        peer: PeerId,
        records: usize,
        direction: DirectoryDirection,
    },
    DialHint {
        peer: PeerId,
        address: Multiaddr,
    },
    Rejected {
        peer: PeerId,
        direction: DirectoryDirection,
        error: String,
    },
    OutboundFailure {
        peer: PeerId,
        error: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryDirection {
    InboundQuery,
    OutboundResponse,
}

enum PendingDirectoryAction {
    Inbound {
        peer: PeerId,
        request: NetworkEnvelope,
        channel: ResponseChannel<NetworkEnvelope>,
    },
    Outbound {
        peer: PeerId,
        response: NetworkEnvelope,
    },
}

struct DirectoryAuthorization {
    view: DirectoryView,
    authorizations: RoleAuthorizations,
    snapshot: AuthorizationSnapshotState,
    directory: RoleDirectory,
    local_record: Option<RoleDirectoryRecord>,
    rendezvous_peers: HashSet<PeerId>,
    capable_peers: HashSet<PeerId>,
}

#[derive(Default)]
struct DirectoryRequests {
    outbound: HashMap<OutboundRequestId, PeerId>,
    actions: HashMap<u64, PendingDirectoryAction>,
    next_action_token: u64,
}

pub struct RoleDirectoryBehaviour {
    protocol: request_response::Behaviour<BoundedEnvelopeCodec>,
    scope: NetworkScope,
    authorization: DirectoryAuthorization,
    requests: DirectoryRequests,
    events: VecDeque<RoleDirectoryBehaviourEvent>,
    timer: Delay,
}

pub struct PreparedDirectoryAuthorization {
    authorization_state: AuthorizationSnapshotState,
    authorizations: RoleAuthorizations,
    directory: RoleDirectory,
    cycles: RewardCycleWindow,
    update: AuthorizationSnapshotUpdate,
}

impl PreparedDirectoryAuthorization {
    pub fn update(&self) -> &AuthorizationSnapshotUpdate {
        &self.update
    }
}

impl RoleDirectoryBehaviour {
    pub fn new(
        protocol: request_response::Behaviour<BoundedEnvelopeCodec>,
        scope: NetworkScope,
    ) -> Self {
        let chain_id = scope.chain_id();
        let network_id = scope.network_id();
        Self {
            protocol,
            scope,
            authorization: DirectoryAuthorization {
                view: DirectoryView::new(
                    NetworkScope::new(chain_id, network_id),
                    0,
                    RewardCycleWindow::current_only(0),
                ),
                authorizations: RoleAuthorizations::default(),
                snapshot: AuthorizationSnapshotState::default(),
                directory: RoleDirectory::default(),
                local_record: None,
                rendezvous_peers: HashSet::new(),
                capable_peers: HashSet::new(),
            },
            requests: DirectoryRequests::default(),
            events: VecDeque::new(),
            timer: Delay::new(DIRECTORY_TICK),
        }
    }

    pub fn apply_authorization_snapshot(
        &mut self,
        snapshot: AuthorizationSnapshot,
    ) -> Result<AuthorizationSnapshotUpdate, AuthorizationSnapshotError> {
        let prepared = self.prepare_authorization_snapshot(&snapshot)?;
        Ok(self.commit_authorization_snapshot(prepared))
    }

    pub fn prepare_authorization_snapshot(
        &self,
        snapshot: &AuthorizationSnapshot,
    ) -> Result<PreparedDirectoryAuthorization, AuthorizationSnapshotError> {
        let mut authorization_state = self.authorization.snapshot.clone();
        let update = authorization_state.apply(snapshot.clone())?;
        let mut authorizations = self.authorization.authorizations.clone();
        let mut directory = self.authorization.directory.clone();
        let mut cycles = self.authorization.view.cycles();
        if !matches!(update, AuthorizationSnapshotUpdate::Stale { .. }) {
            let applied = authorization_state
                .applied()
                .ok_or(AuthorizationSnapshotError::MissingAppliedState)?;
            authorizations = RoleAuthorizations::new(applied.entries().iter().cloned());
            cycles = applied.reward_cycle_window();
            directory.reconcile_authorizations(&authorizations);
            directory.prune(self.authorization.view.burn_height(), cycles);
        }
        Ok(PreparedDirectoryAuthorization {
            authorization_state,
            authorizations,
            directory,
            cycles,
            update,
        })
    }

    pub fn commit_authorization_snapshot(
        &mut self,
        prepared: PreparedDirectoryAuthorization,
    ) -> AuthorizationSnapshotUpdate {
        self.authorization.snapshot = prepared.authorization_state;
        self.authorization.authorizations = prepared.authorizations;
        self.authorization.directory = prepared.directory;
        self.authorization.view.update_cycles(prepared.cycles);
        prepared.update
    }

    pub fn update_burn_height(&mut self, burn_height: u64) {
        self.authorization.view.update_burn_height(burn_height);
        self.authorization
            .directory
            .prune(burn_height, self.authorization.view.cycles());
    }

    pub fn set_rendezvous_peers(&mut self, peers: impl IntoIterator<Item = PeerId>) {
        self.authorization.rendezvous_peers = peers.into_iter().collect();
    }

    pub fn authenticate_peer(&mut self, peer: PeerId, capabilities: u64) {
        if supports(capabilities, CAP_ROLE_DIRECTORY) {
            self.authorization.capable_peers.insert(peer);
        } else {
            self.authorization.capable_peers.remove(&peer);
        }
    }

    pub fn revoke_peer(&mut self, peer: &PeerId) {
        self.authorization.capable_peers.remove(peer);
        self.requests.outbound.retain(|_, pending| pending != peer);
        self.requests.actions.retain(|_, pending| match pending {
            PendingDirectoryAction::Inbound {
                peer: pending_peer, ..
            }
            | PendingDirectoryAction::Outbound {
                peer: pending_peer, ..
            } => pending_peer != peer,
        });
    }

    pub fn set_local_record(&mut self, record: Option<RoleDirectoryRecord>) -> Result<(), String> {
        if let Some(candidate) = record.as_ref() {
            self.insert_record(record_peer(candidate)?, candidate.clone())?;
        }
        self.authorization.local_record = record;
        Ok(())
    }

    pub fn restore_records(
        &mut self,
        records: impl IntoIterator<Item = RoleDirectoryRecord>,
    ) -> Vec<String> {
        records
            .into_iter()
            .filter_map(|record| {
                let source = record_peer(&record);
                source
                    .and_then(|source| self.insert_record(source, record))
                    .err()
            })
            .collect()
    }

    pub fn admit_action(&mut self, token: u64) -> Result<(), String> {
        let action = self
            .requests
            .actions
            .remove(&token)
            .ok_or_else(|| format!("unknown role-directory admission token {token}"))?;
        match action {
            PendingDirectoryAction::Inbound {
                peer,
                request,
                channel,
            } => self.process_inbound(peer, request, channel),
            PendingDirectoryAction::Outbound { peer, response } => {
                self.process_outbound(peer, response)
            }
        }
    }

    pub fn reject_action(&mut self, token: u64, status: Status) -> Result<(), String> {
        let action = self
            .requests
            .actions
            .remove(&token)
            .ok_or_else(|| format!("unknown role-directory admission token {token}"))?;
        if let PendingDirectoryAction::Inbound { peer, channel, .. } = action {
            let response = directory_response_envelope(
                self.scope.chain_id(),
                &RoleDirectoryResponse {
                    status: status as i32,
                    records: Vec::new(),
                },
            );
            self.protocol
                .send_response(channel, response)
                .map_err(|_| format!("role-directory response channel to {peer} closed"))?;
        }
        Ok(())
    }

    pub fn pending_action_len(&self) -> usize {
        self.requests.actions.len()
    }

    pub fn pending_outbound_len(&self) -> usize {
        self.requests.outbound.len()
    }

    fn reserve_action(
        &mut self,
        action: PendingDirectoryAction,
    ) -> Result<u64, Box<PendingDirectoryAction>> {
        if self.requests.actions.len() >= MAX_PENDING_DIRECTORY_ACTIONS {
            return Err(Box::new(action));
        }
        for _ in 0..=MAX_PENDING_DIRECTORY_ACTIONS {
            let token = self.requests.next_action_token;
            self.requests.next_action_token = self.requests.next_action_token.wrapping_add(1);
            if let std::collections::hash_map::Entry::Vacant(entry) =
                self.requests.actions.entry(token)
            {
                entry.insert(action);
                return Ok(token);
            }
        }
        Err(Box::new(action))
    }

    fn process_inbound(
        &mut self,
        peer: PeerId,
        request: NetworkEnvelope,
        channel: ResponseChannel<NetworkEnvelope>,
    ) -> Result<(), String> {
        let result = self
            .authorization
            .capable_peers
            .contains(&peer)
            .then_some(())
            .ok_or_else(|| "role-directory query came from an incapable peer".to_owned())
            .and_then(|_| decode_directory_query(&request, self.scope.chain_id()))
            .and_then(|query| {
                if let Some(record) = query.requester_record.as_ref() {
                    if record.proof.as_ref() != query.requester.as_ref() {
                        return Err("directory registration proof mismatch".to_owned());
                    }
                    self.insert_record(peer, record.clone())?;
                }
                self.authorization
                    .directory
                    .query(
                        &query,
                        &peer,
                        self.authorization.view,
                        &self.authorization.authorizations,
                    )
                    .map_err(|error| error.to_string())
            });
        let (status, mut records) = match result {
            Ok(records) => (Status::Ok, records),
            Err(error) => {
                self.events
                    .push_back(RoleDirectoryBehaviourEvent::Rejected {
                        peer,
                        direction: DirectoryDirection::InboundQuery,
                        error,
                    });
                (Status::Unauthorized, Vec::new())
            }
        };
        let mut response = RoleDirectoryResponse {
            status: status as i32,
            records: Vec::new(),
        };
        while let Some(record) = records.first().cloned() {
            response.records.push(record);
            if response.encoded_len() > EnvelopeLimits::DIRECTORY.max_payload_bytes {
                response.records.pop();
                break;
            }
            records.remove(0);
        }
        let count = response.records.len();
        self.protocol
            .send_response(
                channel,
                directory_response_envelope(self.scope.chain_id(), &response),
            )
            .map_err(|_| format!("role-directory response channel to {peer} closed"))?;
        if status == Status::Ok {
            self.events
                .push_back(RoleDirectoryBehaviourEvent::QueryCompleted {
                    peer,
                    records: count,
                    direction: DirectoryDirection::InboundQuery,
                });
        }
        Ok(())
    }

    fn process_outbound(&mut self, peer: PeerId, response: NetworkEnvelope) -> Result<(), String> {
        let response = decode_directory_response(&response, self.scope.chain_id())?;
        if response.status != Status::Ok as i32 {
            return Err(format!(
                "role-directory returned status {}",
                response.status
            ));
        }
        let count = response.records.len();
        for record in response.records {
            let verified = self.insert_record(peer, record)?;
            for address in &verified.addresses {
                self.events
                    .push_back(RoleDirectoryBehaviourEvent::DialHint {
                        peer: verified.peer_id,
                        address: address.clone(),
                    });
            }
        }
        self.events
            .push_back(RoleDirectoryBehaviourEvent::QueryCompleted {
                peer,
                records: count,
                direction: DirectoryDirection::OutboundResponse,
            });
        Ok(())
    }

    fn insert_record(
        &mut self,
        source: PeerId,
        record: RoleDirectoryRecord,
    ) -> Result<VerifiedDirectoryRecord, String> {
        let verified = crate::verify_directory_record(
            record.clone(),
            self.scope.chain_id(),
            self.scope.network_id(),
            self.authorization.view.burn_height(),
            &self.authorization.authorizations,
        )
        .map_err(|error| error.to_string())?;
        self.authorization
            .directory
            .insert(
                record,
                self.authorization.view,
                &self.authorization.authorizations,
            )
            .map_err(|error| error.to_string())?;
        self.events
            .push_back(RoleDirectoryBehaviourEvent::RecordAccepted {
                source,
                record: Box::new(verified.clone()),
            });
        Ok(verified)
    }

    fn drive_queries(&mut self) {
        let Some(record) = self.authorization.local_record.clone() else {
            return;
        };
        let Some(proof) = record.proof.clone() else {
            return;
        };
        let reward_cycles = self.authorization.view.cycles().iter().collect();
        let query = RoleDirectoryQuery {
            requester: Some(proof),
            reward_cycles,
            roles: vec![Role::Signer as i32, Role::Miner as i32],
            max_records: MAX_DIRECTORY_QUERY_RECORDS as u32,
            requester_record: Some(record),
        };
        let envelope = directory_query_envelope(self.scope.chain_id(), &query);
        let targets = self
            .authorization
            .rendezvous_peers
            .intersection(&self.authorization.capable_peers)
            .filter(|peer| {
                !self
                    .requests
                    .outbound
                    .values()
                    .any(|pending| pending == *peer)
            })
            .copied()
            .collect::<Vec<_>>();
        for peer in targets {
            let request_id = self.protocol.send_request(&peer, envelope.clone());
            self.requests.outbound.insert(request_id, peer);
        }
    }

    fn on_protocol_event(
        &mut self,
        event: request_response::Event<NetworkEnvelope, NetworkEnvelope>,
    ) {
        match event {
            request_response::Event::Message {
                peer,
                connection_id,
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
            } => {
                let encoded_bytes = request.encoded_len();
                let action = PendingDirectoryAction::Inbound {
                    peer,
                    request,
                    channel,
                };
                match self.reserve_action(action) {
                    Ok(token) => {
                        self.events
                            .push_back(RoleDirectoryBehaviourEvent::AdmissionRequired {
                                token,
                                peer,
                                connection_id,
                                encoded_bytes,
                                validation_units: 16,
                                direction: DirectoryDirection::InboundQuery,
                            })
                    }
                    Err(action) if matches!(&*action, PendingDirectoryAction::Inbound { .. }) => {
                        let PendingDirectoryAction::Inbound { channel, .. } = *action else {
                            unreachable!("match guard checked inbound action")
                        };
                        let response = directory_response_envelope(
                            self.scope.chain_id(),
                            &RoleDirectoryResponse {
                                status: Status::Busy as i32,
                                records: Vec::new(),
                            },
                        );
                        let _ = self.protocol.send_response(channel, response);
                        self.events
                            .push_back(RoleDirectoryBehaviourEvent::Rejected {
                                peer,
                                direction: DirectoryDirection::InboundQuery,
                                error: "role-directory admission capacity reached".to_owned(),
                            });
                    }
                    Err(_) => {
                        unreachable!("inbound reservation retains an inbound action")
                    }
                }
            }
            request_response::Event::Message {
                peer,
                connection_id,
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
            } => {
                let encoded_bytes = response.encoded_len();
                let Some(expected) = self.requests.outbound.remove(&request_id) else {
                    self.events
                        .push_back(RoleDirectoryBehaviourEvent::Rejected {
                            peer,
                            direction: DirectoryDirection::OutboundResponse,
                            error: "unknown role-directory response".to_owned(),
                        });
                    return;
                };
                if expected != peer {
                    self.events
                        .push_back(RoleDirectoryBehaviourEvent::Rejected {
                            peer,
                            direction: DirectoryDirection::OutboundResponse,
                            error: "role-directory response peer mismatch".to_owned(),
                        });
                    return;
                }
                let action = PendingDirectoryAction::Outbound { peer, response };
                if let Ok(token) = self.reserve_action(action) {
                    self.events
                        .push_back(RoleDirectoryBehaviourEvent::AdmissionRequired {
                            token,
                            peer,
                            connection_id,
                            encoded_bytes,
                            validation_units: 16,
                            direction: DirectoryDirection::OutboundResponse,
                        });
                } else {
                    self.events
                        .push_back(RoleDirectoryBehaviourEvent::Rejected {
                            peer,
                            direction: DirectoryDirection::OutboundResponse,
                            error: "role-directory admission capacity reached".to_owned(),
                        });
                }
            }
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                let peer = self.requests.outbound.remove(&request_id).unwrap_or(peer);
                self.events
                    .push_back(RoleDirectoryBehaviourEvent::OutboundFailure {
                        peer,
                        error: error.to_string(),
                    });
            }
            request_response::Event::InboundFailure { peer, error, .. } => {
                self.events
                    .push_back(RoleDirectoryBehaviourEvent::Rejected {
                        peer,
                        direction: DirectoryDirection::InboundQuery,
                        error: error.to_string(),
                    });
            }
            request_response::Event::ResponseSent { .. } => {}
        }
    }
}

fn record_peer(record: &RoleDirectoryRecord) -> Result<PeerId, String> {
    let bytes = record
        .proof
        .as_ref()
        .and_then(|proof| proof.body.as_ref())
        .map(|body| body.transport_peer_id.as_slice())
        .ok_or_else(|| "role-directory record has no role-proof body".to_owned())?;
    PeerId::from_bytes(bytes).map_err(|_| "role-directory record has an invalid PeerId".to_owned())
}

impl RoleDirectoryBehaviour {
    fn on_forwarded_swarm_event(&mut self, _event: &FromSwarm<'_>) {}

    fn poll_scheduled(&mut self, cx: &mut Context<'_>) {
        if std::pin::Pin::new(&mut self.timer).poll(cx).is_ready() {
            self.drive_queries();
            self.timer.reset(DIRECTORY_TICK);
        }
    }
}

impl_bounded_request_response_behaviour!(RoleDirectoryBehaviour, RoleDirectoryBehaviourEvent);

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::request_response::ProtocolSupport;
    use libp2p::StreamProtocol;
    use stacks_network_types::wire::v1::Role;

    fn behaviour() -> RoleDirectoryBehaviour {
        let protocol = request_response::Behaviour::with_codec(
            BoundedEnvelopeCodec::new(EnvelopeLimits::DIRECTORY),
            [(
                StreamProtocol::new("/stacks/role-directory/test/1"),
                ProtocolSupport::Full,
            )],
            request_response::Config::default(),
        );
        RoleDirectoryBehaviour::new(protocol, NetworkScope::new(1, 2))
    }

    fn signer(cycle: u64, byte: u8) -> crate::RoleAuthorization {
        crate::RoleAuthorization {
            role: Role::Signer,
            reward_cycle: cycle,
            role_id: Some(u32::from(byte).to_be_bytes().to_vec()),
            key: crate::AuthorizedRoleKey::PublicKey([byte; 33]),
        }
    }

    #[test]
    fn identical_authorization_refresh_preserves_authenticated_capability() {
        let mut directory = behaviour();
        let peer = PeerId::random();
        directory.authenticate_peer(peer, CAP_ROLE_DIRECTORY);
        directory
            .apply_authorization_snapshot(
                AuthorizationSnapshot::new(1, 9, Some(10), [signer(9, 1)]).unwrap(),
            )
            .unwrap();
        let update = directory
            .apply_authorization_snapshot(
                AuthorizationSnapshot::new(2, 9, Some(10), [signer(9, 1)]).unwrap(),
            )
            .unwrap();
        assert!(matches!(
            update,
            AuthorizationSnapshotUpdate::Unchanged { generation: 2, .. }
        ));
        assert!(directory.authorization.capable_peers.contains(&peer));
    }

    #[test]
    fn delayed_snapshot_cannot_roll_authorization_back() {
        let mut directory = behaviour();
        directory
            .apply_authorization_snapshot(
                AuthorizationSnapshot::new(3, 9, None, [signer(9, 1)]).unwrap(),
            )
            .unwrap();
        let update = directory
            .apply_authorization_snapshot(
                AuthorizationSnapshot::new(2, 9, None, [signer(9, 2)]).unwrap(),
            )
            .unwrap();
        assert!(matches!(
            update,
            AuthorizationSnapshotUpdate::Stale {
                applied_generation: 3,
                received_generation: 2
            }
        ));
        assert_eq!(
            directory
                .authorization
                .snapshot
                .applied()
                .unwrap()
                .signer_keys(9),
            std::collections::BTreeSet::from([[1; 33]])
        );
    }

    #[test]
    fn admission_actions_are_strictly_bounded() {
        let mut directory = behaviour();
        let peer = PeerId::random();
        for _ in 0..MAX_PENDING_DIRECTORY_ACTIONS {
            assert!(directory
                .reserve_action(PendingDirectoryAction::Outbound {
                    peer,
                    response: directory_response_envelope(
                        1,
                        &RoleDirectoryResponse {
                            status: Status::Ok as i32,
                            records: Vec::new(),
                        },
                    ),
                })
                .is_ok());
        }
        assert_eq!(
            directory.pending_action_len(),
            MAX_PENDING_DIRECTORY_ACTIONS
        );
        assert!(directory
            .reserve_action(PendingDirectoryAction::Outbound {
                peer,
                response: directory_response_envelope(
                    1,
                    &RoleDirectoryResponse {
                        status: Status::Ok as i32,
                        records: Vec::new(),
                    },
                ),
            })
            .is_err());
        assert_eq!(
            directory.pending_action_len(),
            MAX_PENDING_DIRECTORY_ACTIONS
        );
    }
}
