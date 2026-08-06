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

use std::io::{Read, Write};

pub use stacks_primitives::StacksString;

use crate::codec::{
    read_next, write_next, BoundReader, Error as codec_error, StacksMessageCodec, MAX_MESSAGE_LEN,
};

impl StacksMessageCodec for StacksString {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.to_vec())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<StacksString, codec_error> {
        let bytes: Vec<u8> = {
            let mut bound_read = BoundReader::from_reader(fd, MAX_MESSAGE_LEN as u64);
            read_next(&mut bound_read)
        }?;

        let s = String::from_utf8(bytes).map_err(|_e| {
            codec_error::DeserializeError(
                "Invalid Stacks string: could not build from utf8".to_string(),
            )
        })?;

        StacksString::from_string(&s).ok_or_else(|| {
            codec_error::DeserializeError(
                "Invalid Stacks string: non-printable or non-ASCII string".to_string(),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stacks_string_codec() {
        let value = StacksString::try_from_str("hello-world").unwrap();
        let expected = b"\0\0\0\x0bhello-world";

        assert_eq!(value.serialize_to_vec(), expected);
        assert_eq!(
            StacksString::consensus_deserialize(&mut &expected[..]).unwrap(),
            value
        );

        for end in 0..expected.len() {
            assert!(StacksString::consensus_deserialize(&mut &expected[..end]).is_err());
        }
    }

    #[test]
    fn deserialize_rejects_non_printable_bytes() {
        let bytes = b"\0\0\0\x05a\x01bcd";
        let err = StacksString::consensus_deserialize(&mut &bytes[..]).unwrap_err();
        assert!(matches!(err, codec_error::DeserializeError(_)));
        assert!(err.to_string().contains("non-printable"));
    }
}
