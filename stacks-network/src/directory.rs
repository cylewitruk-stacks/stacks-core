use std::collections::{HashMap, HashSet};

use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use stacks_common::types::chainstate::{StacksPrivateKey, StacksPublicKey};
use stacks_common::types::{PrivateKey, PublicKey};
use stacks_common::util::hash::Hash160;
use stacks_common::util::secp256k1::MessageSignature;
use stacks_network_types::wire::v1::{
    Role, RoleDirectoryQuery, RoleDirectoryRecord, RoleProof, RoleProofBody,
};
use stacks_network_types::{
    directory_record_digest, role_proof_digest, validate_directory_record_bounds, ContentId,
    DirectoryRecordError, NetworkScope, RewardCycleWindow, ROLE_PROOF_VERSION,
};

use crate::{RoleAuthorizer, RoleValidationError, RoleVerificationContext, VerifiedRoleProof};

pub const MAX_DIRECTORY_RECORDS: usize = 4096;
pub const MAX_DIRECTORY_QUERY_RECORDS: usize = 256;

#[allow(clippy::too_many_arguments)]
pub fn signed_role_directory_record(
    scope: NetworkScope,
    peer_id: PeerId,
    role: Role,
    reward_cycle: u64,
    role_id: Vec<u8>,
    valid_from_burn_height: u64,
    valid_until_burn_height: u64,
    advertised_addresses: impl IntoIterator<Item = Multiaddr>,
    private_key: &StacksPrivateKey,
) -> Result<RoleDirectoryRecord, String> {
    let body = RoleProofBody {
        version: ROLE_PROOF_VERSION,
        chain_id: scope.chain_id(),
        network_id: scope.network_id(),
        transport_peer_id: peer_id.to_bytes(),
        role: role as i32,
        reward_cycle,
        role_id,
        valid_from_burn_height,
        valid_until_burn_height,
    };
    let proof = RoleProof {
        body: Some(body.clone()),
        stacks_public_key: StacksPublicKey::from_private(private_key).to_bytes_compressed(),
        stacks_signature: private_key
            .sign(&role_proof_digest(&body))
            .map_err(|error| error.to_string())?
            .as_bytes()
            .to_vec(),
    };
    let mut addresses = advertised_addresses
        .into_iter()
        .map(|address| address.to_vec())
        .collect::<Vec<_>>();
    addresses.sort();
    addresses.dedup();
    let mut record = RoleDirectoryRecord {
        proof: Some(proof),
        addresses,
        record_signature: vec![0; 65],
    };
    record.record_signature = private_key
        .sign(&directory_record_digest(&record).map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())?
        .as_bytes()
        .to_vec();
    Ok(record)
}

/// Immutable chain context used to validate and retain private directory
/// records. Keeping it cohesive avoids passing subtly inconsistent height or
/// reward-cycle tuples between insertion and query paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryView {
    scope: NetworkScope,
    burn_height: u64,
    cycles: RewardCycleWindow,
}

impl DirectoryView {
    pub const fn new(scope: NetworkScope, burn_height: u64, cycles: RewardCycleWindow) -> Self {
        Self {
            scope,
            burn_height,
            cycles,
        }
    }

    pub const fn scope(self) -> NetworkScope {
        self.scope
    }

    pub const fn burn_height(self) -> u64 {
        self.burn_height
    }

    pub const fn cycles(self) -> RewardCycleWindow {
        self.cycles
    }

    pub fn update_cycles(&mut self, cycles: RewardCycleWindow) {
        self.cycles = cycles;
    }

    pub fn update_burn_height(&mut self, burn_height: u64) {
        self.burn_height = burn_height;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizedRoleKey {
    PublicKey([u8; 33]),
    PublicKeyHash160([u8; 20]),
}

impl AuthorizedRoleKey {
    pub(crate) fn matches(&self, stacks_public_key: &[u8; 33]) -> bool {
        match self {
            Self::PublicKey(expected) => expected == stacks_public_key,
            Self::PublicKeyHash160(expected) => {
                Hash160::from_data(stacks_public_key).as_bytes() == expected
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoleAuthorization {
    pub role: Role,
    pub reward_cycle: u64,
    /// `None` permits any structurally valid role ID for this key. Callers
    /// should use an exact ID whenever chainstate supplies one.
    pub role_id: Option<Vec<u8>>,
    pub key: AuthorizedRoleKey,
}

#[derive(Clone, Debug, Default)]
pub struct RoleAuthorizations {
    entries: Vec<RoleAuthorization>,
}

impl RoleAuthorizations {
    pub fn new(entries: impl IntoIterator<Item = RoleAuthorization>) -> Self {
        Self {
            entries: entries.into_iter().collect(),
        }
    }

    pub fn replace_signers(&mut self, reward_cycle: u64, keys: Vec<[u8; 33]>) {
        self.entries
            .retain(|entry| entry.role != Role::Signer || entry.reward_cycle != reward_cycle);
        self.entries
            .extend(keys.into_iter().map(|stacks_public_key| RoleAuthorization {
                role: Role::Signer,
                reward_cycle,
                role_id: None,
                key: AuthorizedRoleKey::PublicKey(stacks_public_key),
            }));
    }

    pub fn replace_miners(&mut self, reward_cycle: u64, miners: Vec<(Vec<u8>, [u8; 20])>) {
        self.entries
            .retain(|entry| entry.role != Role::Miner || entry.reward_cycle != reward_cycle);
        self.entries
            .extend(
                miners
                    .into_iter()
                    .map(|(role_id, public_key_hash)| RoleAuthorization {
                        role: Role::Miner,
                        reward_cycle,
                        role_id: Some(role_id),
                        key: AuthorizedRoleKey::PublicKeyHash160(public_key_hash),
                    }),
            );
    }

    pub fn retain_cycles(&mut self, current: u64, next: Option<u64>) {
        self.entries
            .retain(|entry| entry.reward_cycle == current || Some(entry.reward_cycle) == next);
    }

    pub fn entries(&self) -> &[RoleAuthorization] {
        &self.entries
    }
}

impl RoleAuthorizer for RoleAuthorizations {
    fn is_authorized(
        &self,
        role: Role,
        reward_cycle: u64,
        role_id: &[u8],
        stacks_public_key: &[u8; 33],
    ) -> bool {
        self.entries.iter().any(|entry| {
            entry.role == role
                && entry.reward_cycle == reward_cycle
                && entry.key.matches(stacks_public_key)
                && entry
                    .role_id
                    .as_ref()
                    .is_none_or(|expected| expected.as_slice() == role_id)
        })
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedDirectoryRecord {
    pub record: RoleDirectoryRecord,
    pub role: VerifiedRoleProof,
    pub peer_id: PeerId,
    pub addresses: Vec<Multiaddr>,
}

#[derive(Clone, Debug, thiserror::Error, Eq, PartialEq)]
pub enum DirectoryError {
    #[error(transparent)]
    Bounds(#[from] DirectoryRecordError),
    #[error(transparent)]
    Role(#[from] RoleValidationError),
    #[error("invalid directory-record signature")]
    Signature,
    #[error("invalid directory address")]
    Address,
    #[error("directory address is bound to a different PeerId")]
    AddressPeerMismatch,
    #[error("directory record is outside the retained reward cycles")]
    Cycle,
    #[error("directory query is malformed or exceeds its bound")]
    Query,
    #[error("directory requester is not an authorized private-control-plane role")]
    Requester,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct DirectoryKey {
    peer_id: PeerId,
    reward_cycle: u64,
    role: i32,
}

/// Bounded private role directory. It never writes records to Kademlia; callers
/// expose it only through an authenticated request/response protocol.
#[derive(Clone, Default)]
pub struct RoleDirectory {
    records: HashMap<DirectoryKey, VerifiedDirectoryRecord>,
}

impl RoleDirectory {
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn insert(
        &mut self,
        record: RoleDirectoryRecord,
        view: DirectoryView,
        authorizer: &impl RoleAuthorizer,
    ) -> Result<ContentId, DirectoryError> {
        let verified = verify_directory_record_in_view(record, view, authorizer)?;
        if !view.cycles().contains(verified.role.body.reward_cycle) {
            return Err(DirectoryError::Cycle);
        }
        let proof_id = verified.role.proof_id;
        let key = DirectoryKey {
            peer_id: verified.peer_id,
            reward_cycle: verified.role.body.reward_cycle,
            role: verified.role.body.role,
        };
        let replace = self.records.get(&key).is_none_or(|existing| {
            let existing_until = existing.role.body.valid_until_burn_height;
            let candidate_until = verified.role.body.valid_until_burn_height;
            candidate_until > existing_until
                || (candidate_until == existing_until
                    && verified.role.proof_id.as_bytes() > existing.role.proof_id.as_bytes())
        });
        if replace {
            self.records.insert(key, verified);
        }
        self.prune(view.burn_height(), view.cycles());
        self.enforce_bound();
        Ok(proof_id)
    }

    pub fn query(
        &mut self,
        request: &RoleDirectoryQuery,
        requester_peer: &PeerId,
        view: DirectoryView,
        authorizer: &impl RoleAuthorizer,
    ) -> Result<Vec<RoleDirectoryRecord>, DirectoryError> {
        let max_records = usize::try_from(request.max_records)
            .ok()
            .filter(|value| *value > 0 && *value <= MAX_DIRECTORY_QUERY_RECORDS)
            .ok_or(DirectoryError::Query)?;
        let requester = request
            .requester
            .as_ref()
            .ok_or(DirectoryError::Requester)?;
        let requester = RoleVerificationContext::new(view.scope(), view.burn_height(), authorizer)
            .verify(requester, requester_peer)?;
        let requester_role =
            Role::try_from(requester.body.role).map_err(|_| DirectoryError::Requester)?;
        if !matches!(requester_role, Role::Signer | Role::Miner) {
            return Err(DirectoryError::Requester);
        }

        let cycles = validate_query_cycles(&request.reward_cycles, view.cycles())?;
        let roles = validate_query_roles(&request.roles)?;
        self.prune(view.burn_height(), view.cycles());

        let mut matches: Vec<_> = self
            .records
            .values()
            .filter(|entry| cycles.contains(&entry.role.body.reward_cycle))
            .filter(|entry| roles.contains(&entry.role.body.role))
            .collect();
        matches.sort_by(|left, right| {
            left.role
                .body
                .reward_cycle
                .cmp(&right.role.body.reward_cycle)
                .then_with(|| left.role.body.role.cmp(&right.role.body.role))
                .then_with(|| left.peer_id.to_bytes().cmp(&right.peer_id.to_bytes()))
        });
        Ok(matches
            .into_iter()
            .take(max_records)
            .map(|entry| entry.record.clone())
            .collect())
    }

    pub fn prune(&mut self, burn_height: u64, cycles: RewardCycleWindow) {
        self.records.retain(|key, entry| {
            cycles.contains(key.reward_cycle)
                && burn_height >= entry.role.body.valid_from_burn_height
                && burn_height <= entry.role.body.valid_until_burn_height
        });
    }

    /// Remove records whose role identity is no longer present in the latest
    /// canonical authorization snapshot. Expiry/cycle pruning alone is not
    /// sufficient after a partial reward-set membership change.
    pub fn reconcile_authorizations(&mut self, authorizer: &impl RoleAuthorizer) -> usize {
        let before = self.records.len();
        self.records.retain(|_, entry| {
            let Ok(role) = Role::try_from(entry.role.body.role) else {
                return false;
            };
            authorizer.is_authorized(
                role,
                entry.role.body.reward_cycle,
                &entry.role.body.role_id,
                &entry.role.stacks_public_key,
            )
        });
        before.saturating_sub(self.records.len())
    }

    fn enforce_bound(&mut self) {
        if self.records.len() <= MAX_DIRECTORY_RECORDS {
            return;
        }
        let mut eviction: Vec<_> = self
            .records
            .iter()
            .map(|(key, value)| {
                (
                    key.clone(),
                    value.role.body.valid_until_burn_height,
                    value.role.proof_id,
                )
            })
            .collect();
        eviction.sort_by(|left, right| {
            left.1
                .cmp(&right.1)
                .then_with(|| left.2.as_bytes().cmp(right.2.as_bytes()))
        });
        for (key, _, _) in eviction
            .into_iter()
            .take(self.records.len() - MAX_DIRECTORY_RECORDS)
        {
            self.records.remove(&key);
        }
    }
}

pub fn verify_directory_record(
    record: RoleDirectoryRecord,
    chain_id: u32,
    network_id: u32,
    burn_height: u64,
    authorizer: &impl RoleAuthorizer,
) -> Result<VerifiedDirectoryRecord, DirectoryError> {
    verify_directory_record_scoped(
        record,
        NetworkScope::new(chain_id, network_id),
        burn_height,
        authorizer,
    )
}

fn verify_directory_record_in_view(
    record: RoleDirectoryRecord,
    view: DirectoryView,
    authorizer: &impl RoleAuthorizer,
) -> Result<VerifiedDirectoryRecord, DirectoryError> {
    verify_directory_record_scoped(record, view.scope(), view.burn_height(), authorizer)
}

fn verify_directory_record_scoped(
    record: RoleDirectoryRecord,
    scope: NetworkScope,
    burn_height: u64,
    authorizer: &impl RoleAuthorizer,
) -> Result<VerifiedDirectoryRecord, DirectoryError> {
    validate_directory_record_bounds(&record)?;
    let proof = record
        .proof
        .as_ref()
        .ok_or(DirectoryRecordError::MissingProof)?;
    let body = proof
        .body
        .as_ref()
        .ok_or(DirectoryRecordError::MissingProof)?;
    let peer_id = PeerId::from_bytes(&body.transport_peer_id)
        .map_err(|_| DirectoryError::Role(RoleValidationError::PeerBinding))?;
    let role =
        RoleVerificationContext::new(scope, burn_height, authorizer).verify(proof, &peer_id)?;

    let public_key = StacksPublicKey::from_slice(&role.stacks_public_key)
        .map_err(|_| DirectoryError::Signature)?;
    let signature: [u8; 65] = record
        .record_signature
        .as_slice()
        .try_into()
        .map_err(|_| DirectoryError::Signature)?;
    if !public_key
        .verify(
            &directory_record_digest(&record)?,
            &MessageSignature(signature),
        )
        .map_err(|_| DirectoryError::Signature)?
    {
        return Err(DirectoryError::Signature);
    }

    let mut addresses = Vec::with_capacity(record.addresses.len());
    for bytes in &record.addresses {
        let address = Multiaddr::try_from(bytes.clone()).map_err(|_| DirectoryError::Address)?;
        if address
            .iter()
            .filter_map(protocol_peer)
            .last()
            .is_some_and(|peer| peer != peer_id)
        {
            return Err(DirectoryError::AddressPeerMismatch);
        }
        addresses.push(address);
    }
    Ok(VerifiedDirectoryRecord {
        record,
        role,
        peer_id,
        addresses,
    })
}

fn protocol_peer(protocol: Protocol<'_>) -> Option<PeerId> {
    match protocol {
        Protocol::P2p(peer) => Some(peer),
        _ => None,
    }
}

fn validate_query_cycles(
    requested: &[u64],
    window: RewardCycleWindow,
) -> Result<HashSet<u64>, DirectoryError> {
    if requested.is_empty() || requested.len() > 2 {
        return Err(DirectoryError::Query);
    }
    let cycles: HashSet<_> = requested.iter().copied().collect();
    if cycles.len() != requested.len() || cycles.iter().any(|cycle| !window.contains(*cycle)) {
        return Err(DirectoryError::Query);
    }
    Ok(cycles)
}

fn validate_query_roles(requested: &[i32]) -> Result<HashSet<i32>, DirectoryError> {
    if requested.is_empty() || requested.len() > 3 {
        return Err(DirectoryError::Query);
    }
    let roles: HashSet<_> = requested.iter().copied().collect();
    if roles.len() != requested.len()
        || roles
            .iter()
            .any(|role| !matches!(Role::try_from(*role), Ok(Role::Signer | Role::Miner)))
    {
        return Err(DirectoryError::Query);
    }
    Ok(roles)
}

#[cfg(test)]
mod tests {
    use stacks_common::types::chainstate::StacksPrivateKey;
    use stacks_common::types::PrivateKey;
    use stacks_network_types::wire::v1::{RoleProof, RoleProofBody};
    use stacks_network_types::{role_proof_digest, ROLE_PROOF_VERSION};

    use super::*;

    struct KeysAuthorizer(HashSet<[u8; 33]>);

    impl RoleAuthorizer for KeysAuthorizer {
        fn is_authorized(
            &self,
            role: Role,
            reward_cycle: u64,
            _role_id: &[u8],
            stacks_public_key: &[u8; 33],
        ) -> bool {
            role == Role::Signer && reward_cycle == 7 && self.0.contains(stacks_public_key)
        }
    }

    fn proof(key: &StacksPrivateKey, peer: &PeerId, until: u64) -> RoleProof {
        let body = RoleProofBody {
            version: ROLE_PROOF_VERSION,
            chain_id: 0x8000_0000,
            network_id: 0x8000_0000,
            transport_peer_id: peer.to_bytes(),
            role: Role::Signer as i32,
            reward_cycle: 7,
            role_id: 0_u32.to_be_bytes().to_vec(),
            valid_from_burn_height: 100,
            valid_until_burn_height: until,
        };
        RoleProof {
            stacks_signature: key
                .sign(&role_proof_digest(&body))
                .unwrap()
                .as_bytes()
                .to_vec(),
            stacks_public_key: StacksPublicKey::from_private(key).to_bytes_compressed(),
            body: Some(body),
        }
    }

    fn record(key: &StacksPrivateKey, peer: &PeerId, address: &str) -> RoleDirectoryRecord {
        let address: Multiaddr = address.parse().unwrap();
        let mut record = RoleDirectoryRecord {
            proof: Some(proof(key, peer, 119)),
            addresses: vec![address.to_vec()],
            record_signature: vec![0; 65],
        };
        let digest = directory_record_digest(&record).unwrap();
        record.record_signature = key.sign(&digest).unwrap().as_bytes().to_vec();
        record
    }

    #[test]
    fn miner_authorization_binds_key_hash_and_sortition_id() {
        let miner = StacksPrivateKey::from_seed(&[20; 32]);
        let other = StacksPrivateKey::from_seed(&[19; 32]);
        let miner_public_key: [u8; 33] = StacksPublicKey::from_private(&miner)
            .to_bytes_compressed()
            .try_into()
            .unwrap();
        let other_public_key: [u8; 33] = StacksPublicKey::from_private(&other)
            .to_bytes_compressed()
            .try_into()
            .unwrap();
        let mut authorizations = RoleAuthorizations::default();
        authorizations.replace_miners(
            7,
            vec![(vec![5; 20], Hash160::from_data(&miner_public_key).0)],
        );

        assert!(authorizations.is_authorized(Role::Miner, 7, &[5; 20], &miner_public_key));
        assert!(!authorizations.is_authorized(Role::Miner, 7, &[6; 20], &miner_public_key));
        assert!(!authorizations.is_authorized(Role::Miner, 7, &[5; 20], &other_public_key));
    }

    #[test]
    fn only_authorized_requesters_receive_current_cycle_records() {
        let alice_key = StacksPrivateKey::from_seed(&[21; 32]);
        let bob_key = StacksPrivateKey::from_seed(&[22; 32]);
        let alice_peer = PeerId::random();
        let bob_peer = PeerId::random();
        let keys = [
            StacksPublicKey::from_private(&alice_key)
                .to_bytes_compressed()
                .try_into()
                .unwrap(),
            StacksPublicKey::from_private(&bob_key)
                .to_bytes_compressed()
                .try_into()
                .unwrap(),
        ];
        let authorizer = KeysAuthorizer(keys.into_iter().collect());
        let mut directory = RoleDirectory::default();
        let view = DirectoryView::new(
            NetworkScope::new(0x8000_0000, 0x8000_0000),
            110,
            RewardCycleWindow::new(7, Some(8)).unwrap(),
        );
        directory
            .insert(
                record(&alice_key, &alice_peer, "/memory/7"),
                view,
                &authorizer,
            )
            .unwrap();

        let query = RoleDirectoryQuery {
            requester: Some(proof(&bob_key, &bob_peer, 119)),
            reward_cycles: vec![7],
            roles: vec![Role::Signer as i32],
            max_records: 10,
            requester_record: None,
        };
        let records = directory
            .query(&query, &bob_peer, view, &authorizer)
            .unwrap();
        assert_eq!(records.len(), 1);

        assert!(matches!(
            directory.query(&query, &PeerId::random(), view, &authorizer,),
            Err(DirectoryError::Role(RoleValidationError::PeerBinding))
        ));
        directory.prune(120, RewardCycleWindow::new(7, Some(8)).unwrap());
        assert!(directory.is_empty());
    }

    #[test]
    fn rejects_address_bound_to_another_peer_and_tampering() {
        let key = StacksPrivateKey::from_seed(&[23; 32]);
        let peer = PeerId::random();
        let other = PeerId::random();
        let public_key = StacksPublicKey::from_private(&key)
            .to_bytes_compressed()
            .try_into()
            .unwrap();
        let authorizer = KeysAuthorizer([public_key].into_iter().collect());
        let mismatched = record(&key, &peer, &format!("/memory/8/p2p/{other}"));
        assert!(matches!(
            verify_directory_record(mismatched, 0x8000_0000, 0x8000_0000, 110, &authorizer),
            Err(DirectoryError::AddressPeerMismatch)
        ));

        let mut tampered = record(&key, &peer, "/memory/8");
        tampered.addresses[0][8] = b'9';
        assert!(matches!(
            verify_directory_record(tampered, 0x8000_0000, 0x8000_0000, 110, &authorizer),
            Err(DirectoryError::Signature)
        ));
    }

    #[test]
    fn membership_change_removes_previously_valid_records() {
        let key = StacksPrivateKey::from_seed(&[24; 32]);
        let peer = PeerId::random();
        let public_key = StacksPublicKey::from_private(&key)
            .to_bytes_compressed()
            .try_into()
            .unwrap();
        let authorizer = KeysAuthorizer([public_key].into_iter().collect());
        let mut directory = RoleDirectory::default();
        let view = DirectoryView::new(
            NetworkScope::new(0x8000_0000, 0x8000_0000),
            110,
            RewardCycleWindow::current_only(7),
        );
        directory
            .insert(record(&key, &peer, "/memory/9"), view, &authorizer)
            .unwrap();
        assert_eq!(directory.len(), 1);

        let removed = directory.reconcile_authorizations(&KeysAuthorizer(HashSet::new()));
        assert_eq!(removed, 1);
        assert!(directory.is_empty());
    }
}
