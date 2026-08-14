use std::io;

use async_trait::async_trait;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{request_response, StreamProtocol};
use stacks_network_types::{EnvelopeLimits, NetworkEnvelope};

/// Length-prefix overhead for every application frame.
const FRAME_PREFIX_BYTES: usize = std::mem::size_of::<u32>();

#[derive(Clone, Debug)]
pub struct BoundedEnvelopeCodec {
    limits: EnvelopeLimits,
}

impl BoundedEnvelopeCodec {
    pub const fn new(limits: EnvelopeLimits) -> Self {
        Self { limits }
    }

    async fn read_frame<T>(&self, io: &mut T) -> io::Result<NetworkEnvelope>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut prefix = [0u8; FRAME_PREFIX_BYTES];
        io.read_exact(&mut prefix).await?;
        let frame_len = u32::from_be_bytes(prefix) as usize;
        if frame_len > self.limits.max_frame_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "frame length {frame_len} exceeds limit {}",
                    self.limits.max_frame_bytes
                ),
            ));
        }
        let mut frame = vec![0u8; frame_len];
        io.read_exact(&mut frame).await?;
        NetworkEnvelope::decode(&frame, self.limits)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    async fn write_frame<T>(&self, io: &mut T, envelope: NetworkEnvelope) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let frame = envelope.encode();
        if frame.len() > self.limits.max_frame_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "frame length {} exceeds limit {}",
                    frame.len(),
                    self.limits.max_frame_bytes
                ),
            ));
        }
        let frame_len = u32::try_from(frame.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "frame does not fit u32 length")
        })?;
        io.write_all(&frame_len.to_be_bytes()).await?;
        io.write_all(&frame).await?;
        io.close().await
    }
}

#[async_trait]
impl request_response::Codec for BoundedEnvelopeCodec {
    type Protocol = StreamProtocol;
    type Request = NetworkEnvelope;
    type Response = NetworkEnvelope;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        self.read_frame(io).await
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        self.read_frame(io).await
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        self.write_frame(io, request).await
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        self.write_frame(io, response).await
    }
}

#[cfg(test)]
mod tests {
    use libp2p::request_response::Codec;
    use stacks_network_types::wire::v1::EnvelopeKind;
    use stacks_network_types::ContentId;

    use super::*;

    fn envelope() -> NetworkEnvelope {
        NetworkEnvelope::new(
            1,
            EnvelopeKind::HelloRequest,
            0,
            ContentId::from_domain_bytes(b"codec-test", b"hello"),
            b"hello".to_vec(),
        )
    }

    #[tokio::test]
    async fn round_trip_is_bounded() {
        let protocol = StreamProtocol::new("/stacks/hello/1");
        let mut codec = BoundedEnvelopeCodec::new(EnvelopeLimits::HELLO);
        let mut bytes = futures::io::Cursor::new(Vec::new());
        codec
            .write_request(&protocol, &mut bytes, envelope())
            .await
            .unwrap();
        bytes.set_position(0);
        let decoded = codec.read_request(&protocol, &mut bytes).await.unwrap();
        assert_eq!(decoded.payload(), b"hello");
    }

    #[tokio::test]
    async fn rejects_length_before_allocating_frame() {
        let protocol = StreamProtocol::new("/stacks/hello/1");
        let mut codec = BoundedEnvelopeCodec::new(EnvelopeLimits::HELLO);
        let oversized = (EnvelopeLimits::HELLO.max_frame_bytes as u32 + 1).to_be_bytes();
        let mut bytes = futures::io::Cursor::new(oversized.to_vec());
        let error = codec.read_request(&protocol, &mut bytes).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
