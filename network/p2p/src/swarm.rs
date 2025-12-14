//! Swarm Manager for PHANTOM P2P Network
//!
//! Manages the libp2p swarm, handles events, and provides a high-level API
//! for network operations.

use futures::StreamExt;
use libp2p::{
    gossipsub,
    identify,
    kad,
    mdns,
    noise,
    ping,
    swarm::SwarmEvent,
    tcp, yamux,
    Multiaddr, PeerId, Swarm, SwarmBuilder,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, RwLock};
use tracing::{debug, error, info};

use crate::behaviour::{PhantomBehaviour, PhantomBehaviourEvent, Topics};
use crate::config::P2PConfig;
use crate::errors::{P2PError, P2PResult};
use crate::messages::NetworkMessage;

/// Commands for the swarm manager
#[derive(Debug)]
pub enum SwarmCommand {
    /// Connect to a peer at an address
    Connect {
        addr: Multiaddr,
        response: oneshot::Sender<P2PResult<PeerId>>,
    },
    /// Disconnect from a peer
    Disconnect {
        peer_id: PeerId,
    },
    /// Publish a message to a topic
    Publish {
        topic: String,
        message: NetworkMessage,
        response: oneshot::Sender<P2PResult<()>>,
    },
    /// Get connected peer count
    PeerCount {
        response: oneshot::Sender<usize>,
    },
    /// Get connected peers
    GetPeers {
        response: oneshot::Sender<Vec<PeerId>>,
    },
    /// Add bootstrap peer to Kademlia
    AddBootstrapPeer {
        peer_id: PeerId,
        addr: Multiaddr,
    },
    /// Shutdown the swarm
    Shutdown,
}

/// Events emitted by the swarm manager for application handling
#[derive(Clone, Debug)]
pub enum SwarmEvent_ {
    /// Connected to a new peer
    PeerConnected(PeerId),
    /// Disconnected from a peer
    PeerDisconnected(PeerId),
    /// Received a gossipsub message
    MessageReceived {
        peer_id: PeerId,
        topic: String,
        message: NetworkMessage,
    },
    /// Discovered new peers via mDNS
    PeersDiscovered(Vec<PeerId>),
    /// Listening on new address
    ListeningOn(Multiaddr),
    /// Error occurred
    Error(String),
}

/// Peer information tracked by the swarm
#[derive(Clone, Debug)]
pub struct PeerState {
    /// Peer ID
    pub peer_id: PeerId,
    /// Known addresses
    pub addresses: Vec<Multiaddr>,
    /// Connection state
    pub connected: bool,
    /// Last activity timestamp
    pub last_seen: Instant,
    /// Ping latency (if available)
    pub latency: Option<Duration>,
    /// Protocol version
    pub protocol_version: Option<String>,
    /// Agent version
    pub agent_version: Option<String>,
}

/// The swarm manager handles all P2P networking
pub struct SwarmManager {
    /// Our local peer ID
    local_peer_id: PeerId,
    /// Configuration
    config: P2PConfig,
    /// Command sender for the event loop
    command_tx: Option<mpsc::Sender<SwarmCommand>>,
    /// Event receiver for applications
    event_rx: Option<mpsc::Receiver<SwarmEvent_>>,
    /// Connected peers
    peers: Arc<RwLock<HashMap<PeerId, PeerState>>>,
    /// Running state
    running: Arc<RwLock<bool>>,
    /// Listening addresses
    listen_addrs: Arc<RwLock<Vec<Multiaddr>>>,
}

impl SwarmManager {
    /// Create a new swarm manager
    pub fn new(config: P2PConfig) -> Self {
        // Generate identity
        let keypair = libp2p::identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from_public_key(&keypair.public());

        info!("Created P2P node with peer ID: {}", local_peer_id);

        Self {
            local_peer_id,
            config,
            command_tx: None,
            event_rx: None,
            peers: Arc::new(RwLock::new(HashMap::new())),
            running: Arc::new(RwLock::new(false)),
            listen_addrs: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Get local peer ID
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// Start the swarm and return command/event channels
    pub async fn start(&mut self) -> P2PResult<()> {
        if *self.running.read().await {
            return Err(P2PError::AlreadyRunning);
        }

        // Create channels
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let (event_tx, event_rx) = mpsc::channel(256);

        self.command_tx = Some(cmd_tx);
        self.event_rx = Some(event_rx);

        // Clone what we need for the task
        let config = self.config.clone();
        let local_peer_id = self.local_peer_id;
        let peers = self.peers.clone();
        let running = self.running.clone();
        let listen_addrs = self.listen_addrs.clone();

        // Spawn the event loop
        tokio::spawn(async move {
            if let Err(e) = run_swarm_loop(
                config,
                local_peer_id,
                cmd_rx,
                event_tx,
                peers,
                running.clone(),
                listen_addrs,
            ).await {
                error!("Swarm loop error: {}", e);
            }
            *running.write().await = false;
        });

        *self.running.write().await = true;
        Ok(())
    }

    /// Stop the swarm
    pub async fn stop(&self) -> P2PResult<()> {
        if let Some(cmd_tx) = &self.command_tx {
            let _ = cmd_tx.send(SwarmCommand::Shutdown).await;
        }
        Ok(())
    }

    /// Check if running
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    /// Send a command to the swarm
    async fn send_command(&self, cmd: SwarmCommand) -> P2PResult<()> {
        let cmd_tx = self.command_tx.as_ref()
            .ok_or(P2PError::NotStarted)?;
        cmd_tx.send(cmd).await
            .map_err(|e| P2PError::Channel(e.to_string()))?;
        Ok(())
    }

    /// Connect to a peer
    pub async fn connect(&self, addr: Multiaddr) -> P2PResult<PeerId> {
        let (tx, rx) = oneshot::channel();
        self.send_command(SwarmCommand::Connect { addr, response: tx }).await?;
        rx.await.map_err(|e| P2PError::Channel(e.to_string()))?
    }

    /// Disconnect from a peer
    pub async fn disconnect(&self, peer_id: PeerId) -> P2PResult<()> {
        self.send_command(SwarmCommand::Disconnect { peer_id }).await
    }

    /// Publish a message to a topic
    pub async fn publish(&self, topic: &str, message: NetworkMessage) -> P2PResult<()> {
        let (tx, rx) = oneshot::channel();
        self.send_command(SwarmCommand::Publish {
            topic: topic.to_string(),
            message,
            response: tx,
        }).await?;
        rx.await.map_err(|e| P2PError::Channel(e.to_string()))?
    }

    /// Publish a transaction
    pub async fn publish_transaction(&self, message: NetworkMessage) -> P2PResult<()> {
        self.publish(&self.config.tx_topic, message).await
    }

    /// Publish a state update
    pub async fn publish_state_update(&self, message: NetworkMessage) -> P2PResult<()> {
        self.publish(&self.config.state_topic, message).await
    }

    /// Publish a consensus message
    pub async fn publish_consensus(&self, message: NetworkMessage) -> P2PResult<()> {
        self.publish(&self.config.consensus_topic, message).await
    }

    /// Get connected peer count
    pub async fn peer_count(&self) -> P2PResult<usize> {
        let (tx, rx) = oneshot::channel();
        self.send_command(SwarmCommand::PeerCount { response: tx }).await?;
        rx.await.map_err(|e| P2PError::Channel(e.to_string()))
    }

    /// Get connected peers
    pub async fn peers(&self) -> P2PResult<Vec<PeerId>> {
        let (tx, rx) = oneshot::channel();
        self.send_command(SwarmCommand::GetPeers { response: tx }).await?;
        rx.await.map_err(|e| P2PError::Channel(e.to_string()))
    }

    /// Add a bootstrap peer
    pub async fn add_bootstrap_peer(&self, peer_id: PeerId, addr: Multiaddr) -> P2PResult<()> {
        self.send_command(SwarmCommand::AddBootstrapPeer { peer_id, addr }).await
    }

    /// Try to receive the next event
    pub async fn try_recv_event(&mut self) -> Option<SwarmEvent_> {
        if let Some(rx) = &mut self.event_rx {
            rx.try_recv().ok()
        } else {
            None
        }
    }

    /// Receive the next event (blocking)
    pub async fn recv_event(&mut self) -> Option<SwarmEvent_> {
        if let Some(rx) = &mut self.event_rx {
            rx.recv().await
        } else {
            None
        }
    }

    /// Get peer state
    pub async fn get_peer(&self, peer_id: &PeerId) -> Option<PeerState> {
        self.peers.read().await.get(peer_id).cloned()
    }

    /// Get all peer states
    pub async fn get_all_peers(&self) -> Vec<PeerState> {
        self.peers.read().await.values().cloned().collect()
    }

    /// Get listening addresses
    pub async fn listening_addresses(&self) -> Vec<Multiaddr> {
        self.listen_addrs.read().await.clone()
    }
}

/// Run the main swarm event loop
async fn run_swarm_loop(
    config: P2PConfig,
    local_peer_id: PeerId,
    mut cmd_rx: mpsc::Receiver<SwarmCommand>,
    event_tx: mpsc::Sender<SwarmEvent_>,
    peers: Arc<RwLock<HashMap<PeerId, PeerState>>>,
    running: Arc<RwLock<bool>>,
    listen_addrs: Arc<RwLock<Vec<Multiaddr>>>,
) -> P2PResult<()> {
    // Build the swarm
    let mut swarm = build_swarm(local_peer_id, &config)?;
    let _topics = Topics::from_config(&config);

    // Start listening
    for addr in &config.listen_addrs {
        swarm.listen_on(addr.clone())
            .map_err(|e| P2PError::Transport(e.to_string()))?;
    }

    // Subscribe to topics
    swarm.behaviour_mut().subscribe(&config.tx_topic);
    swarm.behaviour_mut().subscribe(&config.state_topic);
    swarm.behaviour_mut().subscribe(&config.consensus_topic);

    // Add bootstrap peers
    for (peer_id, addr) in &config.bootstrap_peers {
        swarm.behaviour_mut().add_kad_address(peer_id, addr.clone());
        let _ = swarm.dial(addr.clone());
    }

    // Bootstrap Kademlia if enabled
    if config.enable_kademlia && !config.bootstrap_peers.is_empty() {
        let _ = swarm.behaviour_mut().bootstrap();
    }

    info!("P2P swarm started, local peer: {}", local_peer_id);

    loop {
        tokio::select! {
            // Handle swarm events
            event = swarm.select_next_some() => {
                handle_swarm_event(
                    event,
                    &mut swarm,
                    &event_tx,
                    &peers,
                    &listen_addrs,
                    &config,
                ).await;
            }

            // Handle commands
            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    SwarmCommand::Shutdown => {
                        info!("Shutting down P2P swarm");
                        break;
                    }
                    SwarmCommand::Connect { addr, response } => {
                        let result = swarm.dial(addr.clone())
                            .map(|_| local_peer_id) // Note: actual peer ID comes from connection
                            .map_err(|e| P2PError::Connection(e.to_string()));
                        let _ = response.send(result);
                    }
                    SwarmCommand::Disconnect { peer_id } => {
                        let _ = swarm.disconnect_peer_id(peer_id);
                    }
                    SwarmCommand::Publish { topic, message, response } => {
                        let data = message.to_bytes();
                        let result = swarm.behaviour_mut()
                            .publish(&topic, data)
                            .map(|_| ())
                            .map_err(|e| P2PError::Protocol(format!("{:?}", e)));
                        let _ = response.send(result);
                    }
                    SwarmCommand::PeerCount { response } => {
                        let count = peers.read().await
                            .values()
                            .filter(|p| p.connected)
                            .count();
                        let _ = response.send(count);
                    }
                    SwarmCommand::GetPeers { response } => {
                        let peer_ids: Vec<PeerId> = peers.read().await
                            .values()
                            .filter(|p| p.connected)
                            .map(|p| p.peer_id)
                            .collect();
                        let _ = response.send(peer_ids);
                    }
                    SwarmCommand::AddBootstrapPeer { peer_id, addr } => {
                        swarm.behaviour_mut().add_kad_address(&peer_id, addr.clone());
                        let _ = swarm.dial(addr);
                    }
                }
            }
        }
    }

    *running.write().await = false;
    Ok(())
}

/// Build the libp2p swarm
fn build_swarm(
    _local_peer_id: PeerId,
    config: &P2PConfig,
) -> P2PResult<Swarm<PhantomBehaviour>> {
    // Note: We generate a new keypair for the swarm; in production,
    // this should accept a keypair parameter to maintain consistent identity

    let swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| P2PError::Transport(e.to_string()))?
        .with_behaviour(|key| {
            let peer_id = key.public().to_peer_id();
            PhantomBehaviour::new(peer_id, config)
        })
        .map_err(|e| P2PError::Protocol(e.to_string()))?
        .with_swarm_config(|c| {
            c.with_idle_connection_timeout(config.idle_timeout)
        })
        .build();

    Ok(swarm)
}

/// Handle swarm events
async fn handle_swarm_event(
    event: SwarmEvent<PhantomBehaviourEvent>,
    swarm: &mut Swarm<PhantomBehaviour>,
    event_tx: &mpsc::Sender<SwarmEvent_>,
    peers: &Arc<RwLock<HashMap<PeerId, PeerState>>>,
    listen_addrs: &Arc<RwLock<Vec<Multiaddr>>>,
    _config: &P2PConfig,
) {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            info!("Listening on {}", address);
            listen_addrs.write().await.push(address.clone());
            let _ = event_tx.send(SwarmEvent_::ListeningOn(address)).await;
        }

        SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
            info!("Connected to peer: {}", peer_id);
            let mut peers_guard = peers.write().await;
            peers_guard.entry(peer_id).or_insert_with(|| PeerState {
                peer_id,
                addresses: vec![endpoint.get_remote_address().clone()],
                connected: true,
                last_seen: Instant::now(),
                latency: None,
                protocol_version: None,
                agent_version: None,
            }).connected = true;
            drop(peers_guard);
            let _ = event_tx.send(SwarmEvent_::PeerConnected(peer_id)).await;
        }

        SwarmEvent::ConnectionClosed { peer_id, .. } => {
            info!("Disconnected from peer: {}", peer_id);
            if let Some(peer) = peers.write().await.get_mut(&peer_id) {
                peer.connected = false;
            }
            let _ = event_tx.send(SwarmEvent_::PeerDisconnected(peer_id)).await;
        }

        SwarmEvent::Behaviour(PhantomBehaviourEvent::Gossipsub(gossipsub::Event::Message {
            propagation_source,
            message_id,
            message,
        })) => {
            debug!("Received gossipsub message from {}: {:?}", propagation_source, message_id);
            if let Some(network_msg) = NetworkMessage::from_bytes(&message.data) {
                let topic = message.topic.to_string();
                let _ = event_tx.send(SwarmEvent_::MessageReceived {
                    peer_id: propagation_source,
                    topic,
                    message: network_msg,
                }).await;
            }
        }

        SwarmEvent::Behaviour(PhantomBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
            let discovered: Vec<PeerId> = list.into_iter().map(|(peer_id, addr)| {
                swarm.behaviour_mut().add_kad_address(&peer_id, addr.clone());
                if swarm.dial(addr).is_ok() {
                    info!("Discovered and dialing peer: {}", peer_id);
                }
                peer_id
            }).collect();

            if !discovered.is_empty() {
                let _ = event_tx.send(SwarmEvent_::PeersDiscovered(discovered)).await;
            }
        }

        SwarmEvent::Behaviour(PhantomBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
            for (peer_id, _addr) in list {
                debug!("mDNS peer expired: {}", peer_id);
            }
        }

        SwarmEvent::Behaviour(PhantomBehaviourEvent::Ping(ping::Event {
            peer,
            result: Ok(rtt),
            ..
        })) => {
            debug!("Ping to {} succeeded: {:?}", peer, rtt);
            if let Some(peer_state) = peers.write().await.get_mut(&peer) {
                peer_state.latency = Some(rtt);
                peer_state.last_seen = Instant::now();
            }
        }

        SwarmEvent::Behaviour(PhantomBehaviourEvent::Identify(identify::Event::Received {
            peer_id,
            info,
            ..
        })) => {
            debug!("Identified peer {}: {:?}", peer_id, info.agent_version);

            // Clone addresses for Kademlia before moving to peer state
            let addrs_for_kad = info.listen_addrs.clone();

            let mut peers_guard = peers.write().await;
            if let Some(peer_state) = peers_guard.get_mut(&peer_id) {
                peer_state.protocol_version = Some(info.protocol_version);
                peer_state.agent_version = Some(info.agent_version);
                peer_state.addresses = info.listen_addrs;
            }
            drop(peers_guard);

            // Add addresses to Kademlia
            for addr in addrs_for_kad {
                swarm.behaviour_mut().add_kad_address(&peer_id, addr);
            }
        }

        SwarmEvent::Behaviour(PhantomBehaviourEvent::Kademlia(kad::Event::RoutingUpdated {
            peer,
            is_new_peer,
            ..
        })) => {
            if is_new_peer {
                debug!("New Kademlia peer: {}", peer);
            }
        }

        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_swarm_manager_creation() {
        let config = P2PConfig::local();
        let manager = SwarmManager::new(config);

        assert!(manager.command_tx.is_none());
        assert!(manager.event_rx.is_none());
    }

    #[tokio::test]
    async fn test_peer_state() {
        let peer_state = PeerState {
            peer_id: PeerId::random(),
            addresses: vec![],
            connected: true,
            last_seen: Instant::now(),
            latency: Some(Duration::from_millis(50)),
            protocol_version: Some("/phantom/id/1.0.0".to_string()),
            agent_version: Some("phantom/0.1.0".to_string()),
        };

        assert!(peer_state.connected);
        assert!(peer_state.latency.is_some());
    }

    #[test]
    fn test_swarm_command_variants() {
        // Just verify the enum variants exist
        let _: SwarmCommand = SwarmCommand::Shutdown;
        let _: SwarmCommand = SwarmCommand::Disconnect { peer_id: PeerId::random() };
    }
}
