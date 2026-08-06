// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Compatibility facade for the canonical C32 implementation in
//! `stacks-primitives`.

use stacks_primitives::address::{
    c32_address as primitive_c32_address, c32_address_decode as primitive_c32_address_decode,
    C32Error,
};

use super::Error;

impl From<C32Error> for Error {
    fn from(error: C32Error) -> Self {
        match error {
            C32Error::InvalidCrockford32 => Self::InvalidCrockford32,
            C32Error::InvalidVersion(version) => Self::InvalidVersion(version),
            C32Error::BadChecksum(expected, actual) => Self::BadChecksum(expected, actual),
            C32Error::InvalidLength(length) => Self::InvalidLength(length),
        }
    }
}

pub fn c32_address_decode(value: &str) -> Result<(u8, Vec<u8>), Error> {
    primitive_c32_address_decode(value).map_err(Error::from)
}

pub fn c32_address(version: u8, data: &[u8]) -> Result<String, Error> {
    primitive_c32_address(version, data).map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use rand::Rng;

    use super::super::c32_old::{
        c32_address as legacy_c32_address, c32_address_decode as legacy_c32_address_decode,
    };
    use super::*;

    #[test]
    fn primitive_implementation_matches_legacy() {
        for _ in 0..5000 {
            let version = rand::thread_rng().gen_range(0..31);
            let bytes = rand::thread_rng().gen::<[u8; 20]>();

            let encoded = c32_address(version, &bytes).unwrap();
            assert_eq!(encoded, legacy_c32_address(version, &bytes).unwrap());
            assert_eq!(
                c32_address_decode(&encoded).unwrap(),
                (version, bytes.to_vec())
            );
            assert_eq!(
                legacy_c32_address_decode(&encoded).unwrap(),
                (version, bytes.to_vec())
            );
        }
    }

    #[test]
    fn compatibility_errors_retain_their_variants() {
        assert!(matches!(
            c32_address_decode("S𝟘2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKPVKG2CE"),
            Err(Error::InvalidCrockford32)
        ));
        assert!(matches!(
            c32_address(32, &[0; 20]),
            Err(Error::InvalidVersion(32))
        ));
    }
}
