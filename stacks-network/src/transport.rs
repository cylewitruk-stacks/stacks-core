use std::io;
use std::time::Duration;

use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::{transport::Boxed, upgrade};
use libp2p::{identity, noise, tcp, yamux, PeerId, Transport};

pub type StacksTransport = Boxed<(PeerId, StreamMuxerBox)>;

fn secure_transport<T>(transport: T, identity: &identity::Keypair) -> io::Result<StacksTransport>
where
    T: Transport + Send + Unpin + 'static,
    T::Output: futures::AsyncRead + futures::AsyncWrite + Send + Unpin + 'static,
    T::Error: Send + Sync + 'static,
    T::Dial: Send + 'static,
    T::ListenerUpgrade: Send + 'static,
{
    let noise = noise::Config::new(identity)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    Ok(transport
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(noise)
        .multiplex(yamux::Config::default())
        .timeout(Duration::from_secs(10))
        .boxed())
}

pub fn memory_transport(identity: &identity::Keypair) -> io::Result<StacksTransport> {
    secure_transport(
        libp2p::core::transport::MemoryTransport::default(),
        identity,
    )
}

pub fn tcp_transport(identity: &identity::Keypair) -> io::Result<StacksTransport> {
    let tcp = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true));
    let transport = libp2p::dns::tokio::Transport::system(tcp)?;
    secure_transport(transport, identity)
}
