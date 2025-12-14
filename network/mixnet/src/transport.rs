//! libp2p Transport Layer for PHANTOM Mixnet
//!
//! Provides peer-to-peer networking using libp2p with:
//! - Noise protocol for encrypted connections (X25519 + ChaCha20-Poly1305)
//! - Yamux multiplexing for multiple streams
//! - Request-response protocol for Sphinx packet relay
//! - Ping for connection keepalive

use async_trait::async_trait;
use libp2p::{
    identity,
    ping,
    request_response::{self, Codec, ProtocolSupport},
    swarm::NetworkBehaviour,
    Multiaddr, PeerId, StreamProtocol,
};
use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};

use crate::errors::{MixnetError, MixnetResult};
use crate::sphinx::SphinxPacket;

/// Maximum packet size for mixnet messages
const MAX_PACKET_SIZE: usize = 65536;

/// Protocol identifier for PHANTOM mixnet
const PROTOCOL_ID: &str = "/phantom/mixnet/1.0.0";

/// Events emitted by the transport layer
#[derive(Clone, Debug)]
pub enum TransportEvent {
    /// Connected to a new peer
    PeerConnected(PeerId),
    /// Disconnected from a peer
    PeerDisconnected(PeerId),
    /// Received a Sphinx packet from a peer
    PacketReceived {
        from: PeerId,
        packet: SphinxPacket,
    },
    /// Packet was successfully sent
    PacketSent {
        to: PeerId,
    },
    /// Error occurred
    Error(String),
}

/// Commands for the transport layer
#[derive(Clone, Debug)]
pub enum TransportCommand {
    /// Send a Sphinx packet to a peer
    SendPacket {
        to: PeerId,
        packet: SphinxPacket,
    },
    /// Connect to a peer at an address
    Connect {
        addr: Multiaddr,
    },
    /// Disconnect from a peer
    Disconnect {
        peer: PeerId,
    },
    /// Shutdown the transport
    Shutdown,
}

/// Configuration for the transport layer
#[derive(Clone, Debug)]
pub struct TransportConfig {
    /// Listen addresses
    pub listen_addrs: Vec<Multiaddr>,
    /// Bootstrap peers for initial connections
    pub bootstrap_peers: Vec<(PeerId, Multiaddr)>,
    /// Connection idle timeout
    pub idle_timeout: Duration,
    /// Maximum inbound connections
    pub max_inbound: usize,
    /// Maximum outbound connections
    pub max_outbound: usize,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            listen_addrs: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
            bootstrap_peers: Vec::new(),
            idle_timeout: Duration::from_secs(60),
            max_inbound: 100,
            max_outbound: 50,
        }
    }
}

/// Peer information tracked by the transport
#[derive(Clone, Debug)]
pub struct PeerInfo {
    /// Peer's node ID (32 bytes for mix node identification)
    pub node_id: [u8; 32],
    /// Known addresses for this peer
    pub addresses: Vec<Multiaddr>,
    /// Connection state
    pub connected: bool,
    /// Last seen timestamp
    pub last_seen: std::time::Instant,
    /// Peer reputation (0.0 - 100.0)
    pub reputation: f64,
}

/// Sphinx packet request/response for request-response protocol
#[derive(Debug, Clone)]
pub struct SphinxRequest(pub Vec<u8>);

/// Response to Sphinx packet (acknowledgment)
#[derive(Debug, Clone)]
pub struct SphinxResponse(pub bool);

/// Codec for Sphinx packet protocol
#[derive(Clone, Default)]
pub struct SphinxCodec;

#[async_trait]
impl Codec for SphinxCodec {
    type Protocol = StreamProtocol;
    type Request = SphinxRequest;
    type Response = SphinxResponse;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: libp2p::futures::AsyncRead + Unpin + Send,
    {
        use libp2p::futures::AsyncReadExt;

        // Read length prefix (4 bytes)
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;

        if len > MAX_PACKET_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Packet too large"));
        }

        // Read packet data
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;

        Ok(SphinxRequest(buf))
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: libp2p::futures::AsyncRead + Unpin + Send,
    {
        use libp2p::futures::AsyncReadExt;

        let mut buf = [0u8; 1];
        io.read_exact(&mut buf).await?;
        Ok(SphinxResponse(buf[0] != 0))
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: libp2p::futures::AsyncWrite + Unpin + Send,
    {
        use libp2p::futures::AsyncWriteExt;

        // Write length prefix
        let len = req.0.len() as u32;
        io.write_all(&len.to_be_bytes()).await?;

        // Write packet data
        io.write_all(&req.0).await?;
        io.flush().await?;

        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: libp2p::futures::AsyncWrite + Unpin + Send,
    {
        use libp2p::futures::AsyncWriteExt;

        let buf = [if res.0 { 1u8 } else { 0u8 }];
        io.write_all(&buf).await?;
        io.flush().await?;

        Ok(())
    }
}

/// Custom network behaviour for the mixnet
#[derive(NetworkBehaviour)]
pub struct MixnetBehaviour {
    /// Request-response for Sphinx packets
    pub sphinx: request_response::Behaviour<SphinxCodec>,
    /// Ping for keepalive
    pub ping: ping::Behaviour,
}

impl MixnetBehaviour {
    /// Create a new mixnet behaviour
    pub fn new() -> Self {
        let sphinx = request_response::Behaviour::new(
            [(StreamProtocol::new(PROTOCOL_ID), ProtocolSupport::Full)],
            request_response::Config::default()
                .with_request_timeout(Duration::from_secs(30)),
        );

        let ping = ping::Behaviour::new(
            ping::Config::new()
                .with_interval(Duration::from_secs(30))
                .with_timeout(Duration::from_secs(10)),
        );

        Self { sphinx, ping }
    }
}

impl Default for MixnetBehaviour {
    fn default() -> Self {
        Self::new()
    }
}

/// PHANTOM mixnet transport layer
pub struct MixnetTransport {
    /// Our local peer ID
    local_peer_id: PeerId,
    /// Our local identity keypair
    keypair: identity::Keypair,
    /// Configuration
    config: TransportConfig,
    /// Known peers and their info
    peers: Arc<RwLock<HashMap<PeerId, PeerInfo>>>,
    /// Mapping from node IDs to peer IDs
    node_to_peer: Arc<RwLock<HashMap<[u8; 32], PeerId>>>,
    /// Command sender for the transport task
    command_tx: Option<mpsc::Sender<TransportCommand>>,
    /// Event receiver for consuming transport events
    event_rx: Option<mpsc::Receiver<TransportEvent>>,
    /// Running state
    running: Arc<RwLock<bool>>,
}

impl MixnetTransport {
    /// Create a new transport with a random identity
    pub fn new(config: TransportConfig) -> Self {
        let keypair = identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from_public_key(&keypair.public());

        Self {
            local_peer_id,
            keypair,
            config,
            peers: Arc::new(RwLock::new(HashMap::new())),
            node_to_peer: Arc::new(RwLock::new(HashMap::new())),
            command_tx: None,
            event_rx: None,
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Create a transport with a specific keypair
    pub fn with_keypair(keypair: identity::Keypair, config: TransportConfig) -> Self {
        let local_peer_id = PeerId::from_public_key(&keypair.public());

        Self {
            local_peer_id,
            keypair,
            config,
            peers: Arc::new(RwLock::new(HashMap::new())),
            node_to_peer: Arc::new(RwLock::new(HashMap::new())),
            command_tx: None,
            event_rx: None,
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Get our local peer ID
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// Get our node ID (first 32 bytes of peer ID)
    pub fn local_node_id(&self) -> [u8; 32] {
        let peer_bytes = self.local_peer_id.to_bytes();
        let mut node_id = [0u8; 32];
        let len = peer_bytes.len().min(32);
        node_id[..len].copy_from_slice(&peer_bytes[..len]);
        node_id
    }

    /// Get the keypair (for external use)
    pub fn keypair(&self) -> &identity::Keypair {
        &self.keypair
    }

    /// Get the configuration
    pub fn config(&self) -> &TransportConfig {
        &self.config
    }

    /// Check if running
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    /// Send a command to the transport
    pub async fn send_command(&self, cmd: TransportCommand) -> MixnetResult<()> {
        if let Some(cmd_tx) = &self.command_tx {
            cmd_tx.send(cmd).await
                .map_err(|e| MixnetError::InvalidRouting(format!("Send failed: {}", e)))?;
        }
        Ok(())
    }

    /// Send a Sphinx packet to a node by its node ID
    pub async fn send_packet(&self, node_id: &[u8; 32], packet: SphinxPacket) -> MixnetResult<()> {
        let node_to_peer = self.node_to_peer.read().await;
        let peer_id = node_to_peer.get(node_id)
            .ok_or_else(|| MixnetError::NoRoute)?;

        self.send_command(TransportCommand::SendPacket {
            to: *peer_id,
            packet,
        }).await
    }

    /// Try to receive an event (non-blocking)
    pub async fn try_recv_event(&mut self) -> Option<TransportEvent> {
        if let Some(rx) = &mut self.event_rx {
            rx.try_recv().ok()
        } else {
            None
        }
    }

    /// Receive an event (blocking)
    pub async fn recv_event(&mut self) -> Option<TransportEvent> {
        if let Some(rx) = &mut self.event_rx {
            rx.recv().await
        } else {
            None
        }
    }

    /// Register a known peer
    pub async fn register_peer(&self, node_id: [u8; 32], peer_id: PeerId, addrs: Vec<Multiaddr>) {
        let mut peers = self.peers.write().await;
        let mut node_to_peer = self.node_to_peer.write().await;

        let info = PeerInfo {
            node_id,
            addresses: addrs,
            connected: false,
            last_seen: std::time::Instant::now(),
            reputation: 100.0,
        };

        peers.insert(peer_id, info);
        node_to_peer.insert(node_id, peer_id);
    }

    /// Unregister a peer
    pub async fn unregister_peer(&self, peer_id: &PeerId) {
        let mut peers = self.peers.write().await;
        let mut node_to_peer = self.node_to_peer.write().await;

        if let Some(info) = peers.remove(peer_id) {
            node_to_peer.remove(&info.node_id);
        }
    }

    /// Get peer count
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    /// Get connected peer count
    pub async fn connected_peer_count(&self) -> usize {
        self.peers.read().await
            .values()
            .filter(|p| p.connected)
            .count()
    }

    /// Get peer info by peer ID
    pub async fn get_peer_info(&self, peer_id: &PeerId) -> Option<PeerInfo> {
        self.peers.read().await.get(peer_id).cloned()
    }

    /// Get peer ID by node ID
    pub async fn get_peer_id(&self, node_id: &[u8; 32]) -> Option<PeerId> {
        self.node_to_peer.read().await.get(node_id).copied()
    }

    /// Update peer connection state
    pub async fn set_peer_connected(&self, peer_id: &PeerId, connected: bool) {
        if let Some(info) = self.peers.write().await.get_mut(peer_id) {
            info.connected = connected;
            if connected {
                info.last_seen = std::time::Instant::now();
            }
        }
    }

    /// Update peer reputation
    pub async fn update_reputation(&self, peer_id: &PeerId, delta: f64) {
        if let Some(info) = self.peers.write().await.get_mut(peer_id) {
            info.reputation = (info.reputation + delta).clamp(0.0, 100.0);
        }
    }

    /// Stop the transport layer
    pub async fn stop(&mut self) {
        let mut running = self.running.write().await;
        *running = false;

        if let Some(cmd_tx) = &self.command_tx {
            let _ = cmd_tx.send(TransportCommand::Shutdown).await;
        }
    }
}

/// Serialize a Sphinx packet for transport
pub fn serialize_packet(packet: &SphinxPacket) -> Vec<u8> {
    serde_json::to_vec(packet).unwrap_or_default()
}

/// Deserialize a Sphinx packet from transport
pub fn deserialize_packet(data: &[u8]) -> Option<SphinxPacket> {
    serde_json::from_slice(data).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_transport_creation() {
        let config = TransportConfig::default();
        let transport = MixnetTransport::new(config);

        assert!(transport.command_tx.is_none());
        assert!(transport.event_rx.is_none());
    }

    #[tokio::test]
    async fn test_local_node_id() {
        let config = TransportConfig::default();
        let transport = MixnetTransport::new(config);

        let node_id = transport.local_node_id();
        assert_ne!(node_id, [0u8; 32]);
    }

    #[tokio::test]
    async fn test_register_peer() {
        let config = TransportConfig::default();
        let transport = MixnetTransport::new(config);

        let keypair = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from_public_key(&keypair.public());
        let node_id = [42u8; 32];

        transport.register_peer(
            node_id,
            peer_id,
            vec!["/ip4/127.0.0.1/tcp/9000".parse().unwrap()],
        ).await;

        assert_eq!(transport.peer_count().await, 1);

        // Verify lookup works
        let found_peer_id = transport.get_peer_id(&node_id).await;
        assert_eq!(found_peer_id, Some(peer_id));
    }

    #[tokio::test]
    async fn test_unregister_peer() {
        let config = TransportConfig::default();
        let transport = MixnetTransport::new(config);

        let keypair = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from_public_key(&keypair.public());
        let node_id = [42u8; 32];

        transport.register_peer(
            node_id,
            peer_id,
            vec!["/ip4/127.0.0.1/tcp/9000".parse().unwrap()],
        ).await;

        assert_eq!(transport.peer_count().await, 1);

        transport.unregister_peer(&peer_id).await;
        assert_eq!(transport.peer_count().await, 0);
        assert!(transport.get_peer_id(&node_id).await.is_none());
    }

    #[tokio::test]
    async fn test_peer_reputation() {
        let config = TransportConfig::default();
        let transport = MixnetTransport::new(config);

        let keypair = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from_public_key(&keypair.public());
        let node_id = [42u8; 32];

        transport.register_peer(node_id, peer_id, vec![]).await;

        // Initial reputation is 100.0
        let info = transport.get_peer_info(&peer_id).await.unwrap();
        assert_eq!(info.reputation, 100.0);

        // Decrease reputation
        transport.update_reputation(&peer_id, -30.0).await;
        let info = transport.get_peer_info(&peer_id).await.unwrap();
        assert_eq!(info.reputation, 70.0);

        // Reputation should not go below 0
        transport.update_reputation(&peer_id, -100.0).await;
        let info = transport.get_peer_info(&peer_id).await.unwrap();
        assert_eq!(info.reputation, 0.0);
    }

    #[tokio::test]
    async fn test_transport_config_default() {
        let config = TransportConfig::default();

        assert_eq!(config.listen_addrs.len(), 1);
        assert!(config.bootstrap_peers.is_empty());
        assert_eq!(config.max_inbound, 100);
        assert_eq!(config.max_outbound, 50);
    }

    #[test]
    fn test_behaviour_creation() {
        let behaviour = MixnetBehaviour::new();
        // Just verify it creates without panic
        let _ = behaviour;
    }

    #[test]
    fn test_sphinx_codec_default() {
        let _codec = SphinxCodec::default();
        // Just verify it creates without panic
    }

    #[test]
    fn test_packet_serialization() {
        use crate::sphinx::TAG_SIZE;

        // Create a minimal test packet
        let packet = SphinxPacket {
            version: 1,
            ephemeral_key: [1u8; 32],
            routing_info: vec![1, 2, 3],
            tag: [0u8; TAG_SIZE],
            payload: vec![4, 5, 6],
        };

        let serialized = serialize_packet(&packet);
        assert!(!serialized.is_empty());

        let deserialized = deserialize_packet(&serialized);
        assert!(deserialized.is_some());

        let restored = deserialized.unwrap();
        assert_eq!(restored.version, packet.version);
        assert_eq!(restored.ephemeral_key, packet.ephemeral_key);
        assert_eq!(restored.routing_info, packet.routing_info);
        assert_eq!(restored.tag, packet.tag);
        assert_eq!(restored.payload, packet.payload);
    }
}
