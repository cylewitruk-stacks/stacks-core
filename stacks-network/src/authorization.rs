// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Versioned, immutable role-authorization snapshots.
//!
//! Signer and private-directory behaviours consume this value independently.
//! They never share mutable authorization maps. Applying a snapshot is
//! monotonic, and a semantically unchanged refresh preserves authenticated
//! PeerId bindings instead of clearing and rebuilding them.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};
use stacks_network_types::wire::v1::Role;
use stacks_network_types::RewardCycleWindow;

use crate::{AuthorizedRoleKey, RoleAuthorization};

const AUTHORIZATION_SNAPSHOT_DOMAIN: &[u8] = b"STACKS_LIBP2P_AUTHORIZATION_SNAPSHOT_V1";

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AuthorizationIdentity {
    pub role: i32,
    pub reward_cycle: u64,
    pub role_id: Option<Vec<u8>>,
    pub key: AuthorizationKey,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AuthorizationKey {
    PublicKey([u8; 33]),
    PublicKeyHash160([u8; 20]),
}

impl From<&RoleAuthorization> for AuthorizationIdentity {
    fn from(value: &RoleAuthorization) -> Self {
        Self {
            role: value.role as i32,
            reward_cycle: value.reward_cycle,
            role_id: value.role_id.clone(),
            key: match value.key {
                AuthorizedRoleKey::PublicKey(key) => AuthorizationKey::PublicKey(key),
                AuthorizedRoleKey::PublicKeyHash160(hash) => {
                    AuthorizationKey::PublicKeyHash160(hash)
                }
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationSnapshot {
    generation: u64,
    window: RewardCycleWindow,
    entries: Vec<RoleAuthorization>,
    identities: BTreeSet<AuthorizationIdentity>,
    digest: [u8; 32],
}

impl AuthorizationSnapshot {
    pub fn new(
        generation: u64,
        current_cycle: u64,
        next_cycle: Option<u64>,
        entries: impl IntoIterator<Item = RoleAuthorization>,
    ) -> Result<Self, AuthorizationSnapshotError> {
        let window = RewardCycleWindow::new(current_cycle, next_cycle)
            .map_err(|_| AuthorizationSnapshotError::CycleScope)?;
        let entries = entries.into_iter().collect::<Vec<_>>();
        let identities = entries
            .iter()
            .map(AuthorizationIdentity::from)
            .collect::<BTreeSet<_>>();
        if identities.len() != entries.len() {
            return Err(AuthorizationSnapshotError::DuplicateIdentity);
        }
        if identities.iter().any(|identity| {
            !window.contains(identity.reward_cycle)
                || !matches!(
                    Role::try_from(identity.role),
                    Ok(Role::Signer | Role::Miner)
                )
        }) {
            return Err(AuthorizationSnapshotError::CycleScope);
        }
        let digest = authorization_digest(window.current(), window.next(), &identities);
        Ok(Self {
            generation,
            window,
            entries,
            identities,
            digest,
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn current_cycle(&self) -> u64 {
        self.window.current()
    }

    pub fn next_cycle(&self) -> Option<u64> {
        self.window.next()
    }

    pub fn reward_cycle_window(&self) -> RewardCycleWindow {
        self.window
    }

    pub fn entries(&self) -> &[RoleAuthorization] {
        &self.entries
    }

    pub fn identities(&self) -> &BTreeSet<AuthorizationIdentity> {
        &self.identities
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn signer_keys(&self, reward_cycle: u64) -> BTreeSet<[u8; 33]> {
        self.identities
            .iter()
            .filter(|identity| {
                identity.role == Role::Signer as i32 && identity.reward_cycle == reward_cycle
            })
            .filter_map(|identity| match identity.key {
                AuthorizationKey::PublicKey(key) => Some(key),
                AuthorizationKey::PublicKeyHash160(_) => None,
            })
            .collect()
    }

    pub fn authorizes(
        &self,
        role: Role,
        reward_cycle: u64,
        role_id: &[u8],
        key: &[u8; 33],
    ) -> bool {
        self.entries.iter().any(|entry| {
            entry.role == role
                && entry.reward_cycle == reward_cycle
                && entry.key.matches(key)
                && entry
                    .role_id
                    .as_ref()
                    .is_none_or(|expected| expected.as_slice() == role_id)
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizationSnapshotError {
    CycleScope,
    DuplicateIdentity,
    GenerationConflict { generation: u64 },
    MissingAppliedState,
    ConsumerDivergence,
}

impl std::fmt::Display for AuthorizationSnapshotError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CycleScope => formatter.write_str(
                "authorization entry or next cycle is outside the snapshot reward-cycle scope",
            ),
            Self::DuplicateIdentity => {
                formatter.write_str("authorization snapshot contains a duplicate identity")
            }
            Self::GenerationConflict { generation } => write!(
                formatter,
                "authorization generation {generation} was reused with different content"
            ),
            Self::MissingAppliedState => formatter
                .write_str("authorization state did not retain a successfully applied snapshot"),
            Self::ConsumerDivergence => formatter.write_str(
                "authorization consumers prepared different updates for the same snapshot",
            ),
        }
    }
}

impl std::error::Error for AuthorizationSnapshotError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizationSnapshotUpdate {
    /// An older generation arrived after a newer canonical view. It is ignored.
    Stale {
        applied_generation: u64,
        received_generation: u64,
    },
    /// The generation advanced but the scoped authorization content did not.
    /// Consumers must retain valid PeerId bindings and connection state.
    Unchanged { generation: u64, digest: [u8; 32] },
    /// Scoped authorization changed. Consumers revoke only these identities
    /// and reconcile retained identities in place.
    Changed {
        generation: u64,
        digest: [u8; 32],
        removed: Vec<AuthorizationIdentity>,
        added: Vec<AuthorizationIdentity>,
    },
}

#[derive(Clone, Debug, Default)]
pub struct AuthorizationSnapshotState {
    applied: Option<AuthorizationSnapshot>,
}

impl AuthorizationSnapshotState {
    pub fn applied(&self) -> Option<&AuthorizationSnapshot> {
        self.applied.as_ref()
    }

    pub fn apply(
        &mut self,
        candidate: AuthorizationSnapshot,
    ) -> Result<AuthorizationSnapshotUpdate, AuthorizationSnapshotError> {
        let Some(applied) = self.applied.as_ref() else {
            let update = AuthorizationSnapshotUpdate::Changed {
                generation: candidate.generation,
                digest: candidate.digest,
                removed: Vec::new(),
                added: candidate.identities.iter().cloned().collect(),
            };
            self.applied = Some(candidate);
            return Ok(update);
        };
        if candidate.generation < applied.generation {
            return Ok(AuthorizationSnapshotUpdate::Stale {
                applied_generation: applied.generation,
                received_generation: candidate.generation,
            });
        }
        if candidate.generation == applied.generation {
            if candidate.digest != applied.digest {
                return Err(AuthorizationSnapshotError::GenerationConflict {
                    generation: candidate.generation,
                });
            }
            return Ok(AuthorizationSnapshotUpdate::Unchanged {
                generation: applied.generation,
                digest: applied.digest,
            });
        }
        if candidate.digest == applied.digest {
            let generation = candidate.generation;
            let digest = candidate.digest;
            self.applied = Some(candidate);
            return Ok(AuthorizationSnapshotUpdate::Unchanged { generation, digest });
        }
        let removed = applied
            .identities
            .difference(&candidate.identities)
            .cloned()
            .collect();
        let added = candidate
            .identities
            .difference(&applied.identities)
            .cloned()
            .collect();
        let update = AuthorizationSnapshotUpdate::Changed {
            generation: candidate.generation,
            digest: candidate.digest,
            removed,
            added,
        };
        self.applied = Some(candidate);
        Ok(update)
    }
}

fn authorization_digest(
    current_cycle: u64,
    next_cycle: Option<u64>,
    identities: &BTreeSet<AuthorizationIdentity>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(AUTHORIZATION_SNAPSHOT_DOMAIN);
    hasher.update(current_cycle.to_be_bytes());
    match next_cycle {
        Some(cycle) => {
            hasher.update([1]);
            hasher.update(cycle.to_be_bytes());
        }
        None => hasher.update([0]),
    }
    hasher.update((identities.len() as u64).to_be_bytes());
    for identity in identities {
        hasher.update(identity.role.to_be_bytes());
        hasher.update(identity.reward_cycle.to_be_bytes());
        match &identity.role_id {
            Some(role_id) => {
                hasher.update([1]);
                hasher.update((role_id.len() as u64).to_be_bytes());
                hasher.update(role_id);
            }
            None => hasher.update([0]),
        }
        match identity.key {
            AuthorizationKey::PublicKey(key) => {
                hasher.update([0]);
                hasher.update(key);
            }
            AuthorizationKey::PublicKeyHash160(hash) => {
                hasher.update([1]);
                hasher.update(hash);
            }
        }
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer(cycle: u64, byte: u8) -> RoleAuthorization {
        RoleAuthorization {
            role: Role::Signer,
            reward_cycle: cycle,
            role_id: Some(u32::from(byte).to_be_bytes().to_vec()),
            key: AuthorizedRoleKey::PublicKey([byte; 33]),
        }
    }

    #[test]
    fn identical_refresh_advances_generation_without_revocation() {
        let first = AuthorizationSnapshot::new(4, 9, Some(10), [signer(9, 1)]).unwrap();
        let same = AuthorizationSnapshot::new(5, 9, Some(10), [signer(9, 1)]).unwrap();
        assert_eq!(first.digest(), same.digest());
        let mut state = AuthorizationSnapshotState::default();
        assert!(matches!(
            state.apply(first).unwrap(),
            AuthorizationSnapshotUpdate::Changed { ref added, .. } if added.len() == 1
        ));
        assert!(matches!(
            state.apply(same).unwrap(),
            AuthorizationSnapshotUpdate::Unchanged { generation: 5, .. }
        ));
    }

    #[test]
    fn stale_and_conflicting_generations_are_fail_closed() {
        let mut state = AuthorizationSnapshotState::default();
        state
            .apply(AuthorizationSnapshot::new(8, 9, None, [signer(9, 1)]).unwrap())
            .unwrap();
        assert_eq!(
            state
                .apply(AuthorizationSnapshot::new(7, 9, None, [signer(9, 2)]).unwrap())
                .unwrap(),
            AuthorizationSnapshotUpdate::Stale {
                applied_generation: 8,
                received_generation: 7,
            }
        );
        assert!(matches!(
            state.apply(AuthorizationSnapshot::new(8, 9, None, [signer(9, 2)]).unwrap()),
            Err(AuthorizationSnapshotError::GenerationConflict { generation: 8 })
        ));
        assert_eq!(
            state.applied().unwrap().signer_keys(9),
            BTreeSet::from([[1; 33]])
        );
    }

    #[test]
    fn membership_and_cycle_changes_reconcile_by_identity() {
        let mut state = AuthorizationSnapshotState::default();
        state
            .apply(
                AuthorizationSnapshot::new(
                    1,
                    9,
                    Some(10),
                    [signer(9, 1), signer(9, 2), signer(10, 3)],
                )
                .unwrap(),
            )
            .unwrap();
        let update = state
            .apply(
                AuthorizationSnapshot::new(2, 10, Some(11), [signer(10, 3), signer(11, 4)])
                    .unwrap(),
            )
            .unwrap();
        let AuthorizationSnapshotUpdate::Changed { removed, added, .. } = update else {
            panic!("cycle transition must change scoped membership");
        };
        assert_eq!(
            removed
                .iter()
                .filter_map(|identity| match identity.key {
                    AuthorizationKey::PublicKey(key) => Some(key),
                    AuthorizationKey::PublicKeyHash160(_) => None,
                })
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([[1; 33], [2; 33]])
        );
        assert_eq!(
            added
                .iter()
                .filter_map(|identity| match identity.key {
                    AuthorizationKey::PublicKey(key) => Some(key),
                    AuthorizationKey::PublicKeyHash160(_) => None,
                })
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([[4; 33]])
        );
    }

    #[test]
    fn scope_and_duplicate_identity_are_rejected() {
        assert!(matches!(
            AuthorizationSnapshot::new(1, 9, Some(9), Vec::new()),
            Err(AuthorizationSnapshotError::CycleScope)
        ));
        assert!(matches!(
            AuthorizationSnapshot::new(1, 9, None, [signer(10, 1)]),
            Err(AuthorizationSnapshotError::CycleScope)
        ));
        assert!(matches!(
            AuthorizationSnapshot::new(1, 9, None, [signer(9, 1), signer(9, 1)]),
            Err(AuthorizationSnapshotError::DuplicateIdentity)
        ));
    }
}
