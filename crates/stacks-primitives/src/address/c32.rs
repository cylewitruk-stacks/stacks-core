use sha2::{Digest, Sha256};

use super::C32Error;

const C32_CHARACTERS: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// C32 characters indexed by ASCII code for case-insensitive lookup.
/// Crockford aliases `O`, `L`, and `I` map to `0`, `1`, and `1`.
const C32_CHARACTERS_MAP: [Option<u8>; 128] = [
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    Some(0),
    Some(1),
    Some(2),
    Some(3),
    Some(4),
    Some(5),
    Some(6),
    Some(7),
    Some(8),
    Some(9),
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    Some(10),
    Some(11),
    Some(12),
    Some(13),
    Some(14),
    Some(15),
    Some(16),
    Some(17),
    Some(1),
    Some(18),
    Some(19),
    Some(1),
    Some(20),
    Some(21),
    Some(0),
    Some(22),
    Some(23),
    Some(24),
    Some(25),
    Some(26),
    None,
    Some(27),
    Some(28),
    Some(29),
    Some(30),
    Some(31),
    None,
    None,
    None,
    None,
    None,
    None,
    Some(10),
    Some(11),
    Some(12),
    Some(13),
    Some(14),
    Some(15),
    Some(16),
    Some(17),
    Some(1),
    Some(18),
    Some(19),
    Some(1),
    Some(20),
    Some(21),
    Some(0),
    Some(22),
    Some(23),
    Some(24),
    Some(25),
    Some(26),
    None,
    Some(27),
    Some(28),
    Some(29),
    Some(30),
    Some(31),
    None,
    None,
    None,
    None,
    None,
];

fn c32_encode(input_bytes: &[u8]) -> String {
    let size = input_bytes.len().saturating_mul(8).div_ceil(5);
    let mut result = Vec::with_capacity(size);
    let mut carry = 0;
    let mut carry_bits = 0;

    for current_value in input_bytes.iter().rev() {
        let low_bits_to_take = 5 - carry_bits;
        let low_bits = current_value & ((1 << low_bits_to_take) - 1);
        let c32_value = (low_bits << carry_bits) + carry;
        result.push(C32_CHARACTERS[c32_value as usize]);
        carry_bits = (8 + carry_bits) - 5;
        carry = current_value >> (8 - carry_bits);

        if carry_bits >= 5 {
            let c32_value = carry & ((1 << 5) - 1);
            result.push(C32_CHARACTERS[c32_value as usize]);
            carry_bits -= 5;
            carry >>= 5;
        }
    }

    if carry_bits > 0 {
        result.push(C32_CHARACTERS[carry as usize]);
    }

    while let Some(value) = result.pop() {
        if value != C32_CHARACTERS[0] {
            result.push(value);
            break;
        }
    }

    for current_value in input_bytes {
        if *current_value == 0 {
            result.push(C32_CHARACTERS[0]);
        } else {
            break;
        }
    }

    result.reverse();
    String::from_utf8(result).expect("C32 alphabet is valid UTF-8")
}

fn c32_decode(input: &str) -> Result<Vec<u8>, C32Error> {
    if !input.is_ascii() {
        return Err(C32Error::InvalidCrockford32);
    }

    let mut reversed_digits = Vec::with_capacity(input.len());
    for byte in input.as_bytes().iter().rev() {
        let Some(Some(value)) = C32_CHARACTERS_MAP.get(*byte as usize) else {
            return Err(C32Error::InvalidCrockford32);
        };
        reversed_digits.push(*value);
    }

    let size = reversed_digits.len().saturating_mul(5).div_ceil(8);
    let mut result = Vec::with_capacity(size);
    let mut carry: u16 = 0;
    let mut carry_bits = 0;

    for current_value in &reversed_digits {
        carry += (*current_value as u16) << carry_bits;
        carry_bits += 5;

        if carry_bits >= 8 {
            result.push((carry & 0xff) as u8);
            carry_bits -= 8;
            carry >>= 8;
        }
    }

    if carry_bits > 0 {
        result.push(carry as u8);
    }

    while let Some(value) = result.pop() {
        if value != 0 {
            result.push(value);
            break;
        }
    }

    for current_value in reversed_digits.iter().rev() {
        if *current_value == 0 {
            result.push(0);
        } else {
            break;
        }
    }

    result.reverse();
    Ok(result)
}

fn checksum(data: &[u8]) -> [u8; 4] {
    let digest = Sha256::digest(Sha256::digest(data));
    digest[..4]
        .try_into()
        .expect("SHA-256 digest always contains four bytes")
}

fn c32_check_encode(version: u8, data: &[u8]) -> Result<String, C32Error> {
    if version >= 32 {
        return Err(C32Error::InvalidVersion(version));
    }

    let mut checked_data = Vec::with_capacity(1 + data.len());
    checked_data.push(version);
    checked_data.extend_from_slice(data);

    let mut encoded_data = data.to_vec();
    encoded_data.extend_from_slice(&checksum(&checked_data));

    let mut encoded = c32_encode(&encoded_data).into_bytes();
    encoded.insert(0, C32_CHARACTERS[version as usize]);
    Ok(String::from_utf8(encoded).expect("C32 alphabet is valid UTF-8"))
}

fn c32_check_decode(value: &str) -> Result<(u8, Vec<u8>), C32Error> {
    if !value.is_ascii() || value.len() < 2 {
        return Err(C32Error::InvalidCrockford32);
    }

    let (version_text, data_text) = value.split_at(1);
    let data_and_checksum = c32_decode(data_text)?;
    if data_and_checksum.len() < 5 {
        return Err(C32Error::InvalidCrockford32);
    }

    let checksum_offset = data_and_checksum.len() - 4;
    let (data, expected_checksum) = data_and_checksum.split_at(checksum_offset);
    let mut checked_data = c32_decode(version_text)?;
    checked_data.extend_from_slice(data);
    let computed_checksum = checksum(&checked_data);

    if computed_checksum != expected_checksum {
        let computed = u32::from_le_bytes(computed_checksum);
        let expected = u32::from_le_bytes(
            expected_checksum
                .try_into()
                .expect("C32 checksum is exactly four bytes"),
        );
        return Err(C32Error::BadChecksum(computed, expected));
    }

    Ok((checked_data[0], data.to_vec()))
}

/// Decode a canonical C32Check Stacks address into its version and payload.
pub fn c32_address_decode(value: &str) -> Result<(u8, Vec<u8>), C32Error> {
    if !value.is_ascii() || value.len() <= 5 {
        Err(C32Error::InvalidCrockford32)
    } else {
        c32_check_decode(&value[1..])
    }
}

/// Encode a version and payload as a canonical C32Check Stacks address.
pub fn c32_address(version: u8, data: &[u8]) -> Result<String, C32Error> {
    Ok(format!("S{}", c32_check_encode(version, data)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_addresses_match_legacy_encoding() {
        let payloads = [
            "a46ff88886c2ef9762d970b4d2c63678835bd39d",
            "0000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000001",
            "1000000000000000000000000000000000000001",
            "1000000000000000000000000000000000000000",
        ];
        let expected = [
            "SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7",
            "SP000000000000000000002Q6VF78",
            "SP00000000000000000005JA84HQ",
            "SP80000000000000000000000000000004R0CMNV",
            "SP800000000000000000000000000000033H8YKK",
        ];

        for (payload, expected_address) in payloads.into_iter().zip(expected) {
            let bytes = const_hex::decode(payload).unwrap();
            let encoded = c32_address(22, &bytes).unwrap();
            assert_eq!(encoded, expected_address);
            assert_eq!(c32_address_decode(&encoded).unwrap(), (22, bytes));
        }
    }

    #[test]
    fn decoding_normalizes_case_and_crockford_aliases() {
        let variants = [
            "S02J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKPVKG2CE",
            "SO2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKPVKG2CE",
            "S02J6ZY48GVLEZ5V2V5RB9MP66SW86PYKKPVKG2CE",
            "sO2j6zy48gvlez5v2v5rb9mp66sw86pykkpvkg2ce",
        ];
        let expected = const_hex::decode("a46ff88886c2ef9762d970b4d2c63678835bd39d").unwrap();

        for address in variants {
            assert_eq!(c32_address_decode(address).unwrap(), (0, expected.clone()));
        }
    }

    #[test]
    fn rejects_non_ascii_and_invalid_checksums() {
        assert_eq!(
            c32_address_decode("S𝟘2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKPVKG2CE"),
            Err(C32Error::InvalidCrockford32)
        );
        assert!(matches!(
            c32_address_decode("SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ0"),
            Err(C32Error::BadChecksum(..))
        ));
    }

    #[test]
    fn rejects_invalid_versions() {
        assert_eq!(c32_address(32, &[0; 20]), Err(C32Error::InvalidVersion(32)));
    }
}
