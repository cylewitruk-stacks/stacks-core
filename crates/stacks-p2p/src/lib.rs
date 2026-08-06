use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use serde::{Deserialize, Serialize};
use stacks_macros::{impl_array_hexstring_fmt, impl_array_newtype, impl_byte_array_newtype};
use stacks_primitives::StacksEpochId;

/// A container for an IPv4 or IPv6 peer address.
///
/// IPv6 addresses are stored in network byte order. IPv4 addresses are stored
/// as IPv6-to-IPv4-mapped addresses.
pub struct PeerAddress(pub [u8; 16]);
impl_array_newtype!(PeerAddress, u8, 16);
impl_array_hexstring_fmt!(PeerAddress);
impl_byte_array_newtype!(PeerAddress, u8, 16);

impl Serialize for PeerAddress {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_ipaddr().to_string())
    }
}

impl<'de> Deserialize<'de> for PeerAddress {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<PeerAddress, D::Error> {
        let inst = String::deserialize(d)?;
        let ip = inst.parse::<IpAddr>().map_err(serde::de::Error::custom)?;
        Ok(PeerAddress::from_ip(&ip))
    }
}

impl PeerAddress {
    pub fn from_slice(bytes: &[u8]) -> Option<PeerAddress> {
        Self::from_bytes(bytes)
    }

    pub fn is_ipv4(&self) -> bool {
        self.ipv4_octets().is_some()
    }

    pub fn ipv4_octets(&self) -> Option<[u8; 4]> {
        if self.0[0..12]
            != [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
            ]
        {
            return None;
        }
        Some([self[12], self[13], self[14], self[15]])
    }

    pub fn ipv4_bits(&self) -> Option<u32> {
        let octets = self.ipv4_octets()?;
        Some(
            ((octets[0] as u32) << 24)
                | ((octets[1] as u32) << 16)
                | ((octets[2] as u32) << 8)
                | (octets[3] as u32),
        )
    }

    pub fn to_ipaddr(&self) -> IpAddr {
        if self.is_ipv4() {
            IpAddr::V4(Ipv4Addr::new(
                self.0[12], self.0[13], self.0[14], self.0[15],
            ))
        } else {
            let addr_words: [u16; 8] = [
                ((self.0[0] as u16) << 8) | (self.0[1] as u16),
                ((self.0[2] as u16) << 8) | (self.0[3] as u16),
                ((self.0[4] as u16) << 8) | (self.0[5] as u16),
                ((self.0[6] as u16) << 8) | (self.0[7] as u16),
                ((self.0[8] as u16) << 8) | (self.0[9] as u16),
                ((self.0[10] as u16) << 8) | (self.0[11] as u16),
                ((self.0[12] as u16) << 8) | (self.0[13] as u16),
                ((self.0[14] as u16) << 8) | (self.0[15] as u16),
            ];
            IpAddr::V6(Ipv6Addr::new(
                addr_words[0],
                addr_words[1],
                addr_words[2],
                addr_words[3],
                addr_words[4],
                addr_words[5],
                addr_words[6],
                addr_words[7],
            ))
        }
    }

    pub fn to_socketaddr(&self, port: u16) -> SocketAddr {
        SocketAddr::new(self.to_ipaddr(), port)
    }

    pub fn from_socketaddr(addr: &SocketAddr) -> PeerAddress {
        PeerAddress::from_ip(&addr.ip())
    }

    pub fn from_ip(addr: &IpAddr) -> PeerAddress {
        match addr {
            IpAddr::V4(addr) => {
                let octets = addr.octets();
                PeerAddress([
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
                    octets[0], octets[1], octets[2], octets[3],
                ])
            }
            IpAddr::V6(addr) => {
                let words = addr.segments();
                PeerAddress([
                    (words[0] >> 8) as u8,
                    (words[0] & 0xff) as u8,
                    (words[1] >> 8) as u8,
                    (words[1] & 0xff) as u8,
                    (words[2] >> 8) as u8,
                    (words[2] & 0xff) as u8,
                    (words[3] >> 8) as u8,
                    (words[3] & 0xff) as u8,
                    (words[4] >> 8) as u8,
                    (words[4] & 0xff) as u8,
                    (words[5] >> 8) as u8,
                    (words[5] & 0xff) as u8,
                    (words[6] >> 8) as u8,
                    (words[6] & 0xff) as u8,
                    (words[7] >> 8) as u8,
                    (words[7] & 0xff) as u8,
                ])
            }
        }
    }

    pub fn from_ipv4(o1: u8, o2: u8, o3: u8, o4: u8) -> PeerAddress {
        PeerAddress([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, o1, o2, o3, o4,
        ])
    }

    pub fn is_anynet(&self) -> bool {
        self.0 == [0x00; 16] || self == &PeerAddress::from_ipv4(0, 0, 0, 0)
    }

    pub fn is_in_private_range(&self) -> bool {
        if self.is_ipv4() {
            self.0[12] == 10
                || (self.0[12] == 172 && self.0[13] >= 16 && self.0[13] <= 31)
                || (self.0[12] == 192 && self.0[13] == 168)
                || self.0[12] == 127
        } else {
            self.0[0] >= 0xfc || (self.0[0..15] == [0u8; 15] && self.0[15] == 1)
        }
    }

    pub fn is_loopback(&self) -> bool {
        self.to_ipaddr().is_loopback()
    }

    pub fn pretty_print(&self) -> String {
        self.to_ipaddr().to_string()
    }
}

/// Peer version (big-endian).
///
/// First byte: major network protocol version.
/// Second and third bytes: unused.
/// Fourth byte: highest epoch supported by this node.
pub const PEER_VERSION_MAINNET_MAJOR: u32 = 0x18000000;
pub const PEER_VERSION_TESTNET_MAJOR: u32 = 0xfacade00;

pub const PEER_VERSION_EPOCH_1_0: u8 = 0x00;
pub const PEER_VERSION_EPOCH_2_0: u8 = 0x00;
pub const PEER_VERSION_EPOCH_2_05: u8 = 0x05;
pub const PEER_VERSION_EPOCH_2_1: u8 = 0x06;
pub const PEER_VERSION_EPOCH_2_2: u8 = 0x07;
pub const PEER_VERSION_EPOCH_2_3: u8 = 0x08;
pub const PEER_VERSION_EPOCH_2_4: u8 = 0x09;
pub const PEER_VERSION_EPOCH_2_5: u8 = 0x0a;
pub const PEER_VERSION_EPOCH_3_0: u8 = 0x0b;
pub const PEER_VERSION_EPOCH_3_1: u8 = 0x0c;
pub const PEER_VERSION_EPOCH_3_2: u8 = 0x0d;
pub const PEER_VERSION_EPOCH_3_3: u8 = 0x0e;
pub const PEER_VERSION_EPOCH_3_4: u8 = 0x0f;
pub const PEER_VERSION_EPOCH_4_0: u8 = 0x10;
pub const PEER_VERSION_EPOCH_4_1: u8 = 0x11;

/// Latest epoch marker advertised in the P2P peer version.
pub const PEER_NETWORK_EPOCH: u32 = PEER_VERSION_EPOCH_4_0 as u32;

/// Peer versions advertised on mainnet and testnet-compatible networks.
pub const PEER_VERSION_MAINNET: u32 = PEER_VERSION_MAINNET_MAJOR | PEER_NETWORK_EPOCH;
pub const PEER_VERSION_TESTNET: u32 = PEER_VERSION_TESTNET_MAJOR | PEER_NETWORK_EPOCH;

const PEER_VERSION_BY_EPOCH: &[(StacksEpochId, u8)] = &[
    (StacksEpochId::Epoch10, PEER_VERSION_EPOCH_1_0),
    (StacksEpochId::Epoch20, PEER_VERSION_EPOCH_2_0),
    (StacksEpochId::Epoch2_05, PEER_VERSION_EPOCH_2_05),
    (StacksEpochId::Epoch21, PEER_VERSION_EPOCH_2_1),
    (StacksEpochId::Epoch22, PEER_VERSION_EPOCH_2_2),
    (StacksEpochId::Epoch23, PEER_VERSION_EPOCH_2_3),
    (StacksEpochId::Epoch24, PEER_VERSION_EPOCH_2_4),
    (StacksEpochId::Epoch25, PEER_VERSION_EPOCH_2_5),
    (StacksEpochId::Epoch30, PEER_VERSION_EPOCH_3_0),
    (StacksEpochId::Epoch31, PEER_VERSION_EPOCH_3_1),
    (StacksEpochId::Epoch32, PEER_VERSION_EPOCH_3_2),
    (StacksEpochId::Epoch33, PEER_VERSION_EPOCH_3_3),
    (StacksEpochId::Epoch34, PEER_VERSION_EPOCH_3_4),
    (StacksEpochId::Epoch40, PEER_VERSION_EPOCH_4_0),
    (StacksEpochId::Epoch41, PEER_VERSION_EPOCH_4_1),
];

pub trait EpochPeerVersion {
    fn peer_version(self) -> u8;
}

impl EpochPeerVersion for StacksEpochId {
    fn peer_version(self) -> u8 {
        PEER_VERSION_BY_EPOCH
            .iter()
            .find_map(|(epoch, peer_version)| (*epoch == self).then_some(*peer_version))
            .expect("missing peer version for Stacks epoch")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_versions_cover_all_epochs() {
        assert_eq!(PEER_VERSION_BY_EPOCH.len(), StacksEpochId::ALL.len());

        for &epoch in StacksEpochId::ALL {
            assert!(
                PEER_VERSION_BY_EPOCH
                    .iter()
                    .any(|(mapped_epoch, _)| *mapped_epoch == epoch),
                "missing peer version for {epoch}"
            );
        }
    }
}
