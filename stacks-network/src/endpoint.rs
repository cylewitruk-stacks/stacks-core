// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use std::str::FromStr;

use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};

/// A configured endpoint whose transport address is cryptographically bound
/// to the expected remote PeerId by a terminal `/p2p/<PeerId>` component.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerEndpoint {
    peer_id: PeerId,
    dial_addr: Multiaddr,
}

impl PeerEndpoint {
    pub fn new(peer_id: PeerId, mut address: Multiaddr) -> Result<Self, PeerEndpointError> {
        match address.pop() {
            Some(Protocol::P2p(advertised)) if advertised == peer_id => Ok(Self {
                peer_id,
                dial_addr: address,
            }),
            Some(Protocol::P2p(advertised)) => Err(PeerEndpointError::ConflictingPeerId {
                expected: Box::new(peer_id),
                advertised: Box::new(advertised),
            }),
            _ => Err(PeerEndpointError::MissingPeerId),
        }
    }

    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn dial_addr(&self) -> &Multiaddr {
        &self.dial_addr
    }

    pub fn into_multiaddr(mut self) -> Multiaddr {
        self.dial_addr.push(Protocol::P2p(self.peer_id));
        self.dial_addr
    }
}

impl FromStr for PeerEndpoint {
    type Err = PeerEndpointError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let address = value
            .parse::<Multiaddr>()
            .map_err(|error| PeerEndpointError::InvalidAddress(error.to_string()))?;
        Self::try_from(address)
    }
}

impl TryFrom<Multiaddr> for PeerEndpoint {
    type Error = PeerEndpointError;

    fn try_from(address: Multiaddr) -> Result<Self, Self::Error> {
        let Some(Protocol::P2p(peer_id)) = address.iter().last() else {
            return Err(PeerEndpointError::MissingPeerId);
        };
        Self::new(peer_id, address)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PeerEndpointError {
    #[error("invalid multiaddress: {0}")]
    InvalidAddress(String),
    #[error("configured endpoint must end in /p2p/<peer-id>")]
    MissingPeerId,
    #[error("configured endpoint advertises PeerId {advertised}, expected {expected}")]
    ConflictingPeerId {
        expected: Box<PeerId>,
        advertised: Box<PeerId>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_requires_one_matching_terminal_peer_id() {
        let peer = PeerId::random();
        let other = PeerId::random();
        let endpoint: PeerEndpoint = format!("/memory/7/p2p/{peer}").parse().unwrap();
        assert_eq!(endpoint.peer_id(), peer);
        assert_eq!(endpoint.dial_addr(), &"/memory/7".parse().unwrap());
        assert!("/memory/7".parse::<PeerEndpoint>().is_err());
        assert_eq!(
            PeerEndpoint::new(peer, format!("/memory/7/p2p/{other}").parse().unwrap()),
            Err(PeerEndpointError::ConflictingPeerId {
                expected: Box::new(peer),
                advertised: Box::new(other),
            })
        );
    }
}
