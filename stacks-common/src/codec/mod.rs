// TODO: migrate callers to `stacks-codec` directly, then remove this bridge.
pub use stacks_codec::codec::*;

use crate::types::chainstate::SortitionId;

impl_byte_array_message_codec!(SortitionId, 32);

/// Codec test helpers. Available under `cfg(test)` to this crate, and under
/// the `testing` feature to downstream crates that exercise their own codec
/// implementations in tests.
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use std::{fmt, io};

    use super::{Error as codec_error, StacksMessageCodec};

    /// Verify that `obj` round-trips through `consensus_serialize` /
    /// `consensus_deserialize` and matches the supplied byte representation.
    /// Also checks that truncating the serialized bytes by one byte produces
    /// an `UnexpectedEof` read error — parsing a shorter form successfully is
    /// treated as a hard failure.
    pub fn check_codec_and_corruption<T>(obj: &T, bytes: &[u8])
    where
        T: StacksMessageCodec + fmt::Debug + Clone + PartialEq,
    {
        // obj should serialize to bytes
        let mut write_buf: Vec<u8> = Vec::with_capacity(bytes.len());
        obj.consensus_serialize(&mut write_buf).unwrap();
        assert_eq!(write_buf, *bytes);

        // bytes should deserialize to obj
        let read_buf: Vec<u8> = write_buf.clone();
        match T::consensus_deserialize(&mut &read_buf[..]) {
            Ok(out) => assert_eq!(out, *obj),
            Err(e) => panic!("Failed to parse {obj:?} from {bytes:?}: {e:?}"),
        }

        // short message shouldn't parse, but should EOF
        if !write_buf.is_empty() {
            let mut short_buf = write_buf.clone();
            let short_len = short_buf.len() - 1;
            short_buf.truncate(short_len);

            match T::consensus_deserialize(&mut &short_buf[..]) {
                Ok(oops) => {
                    panic!(
                        "Parsed {oops:?} from a truncated buffer {:?}; expected an UnexpectedEof read error",
                        &write_buf[0..short_len]
                    );
                }
                Err(codec_error::ReadError(io_error)) => match io_error.kind() {
                    io::ErrorKind::UnexpectedEof => {}
                    _ => panic!("Got unexpected I/O error: {io_error:?}"),
                },
                Err(e) => panic!("Got unexpected Net error: {e:?}"),
            }
        }
    }
}
