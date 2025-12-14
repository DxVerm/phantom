//! Custom libp2p NetworkBehaviour for PHANTOM
//!
//! Composes multiple protocols:
//! - Gossipsub for message propagation
//! - Kademlia DHT for peer routing and content discovery
//! - mDNS for local peer discovery
//! - Ping for connection keepalive
//! - Identify for peer information exchange

use libp2p::{
    gossipsub::{self, IdentTopic, MessageAuthenticity, MessageId, ValidationMode},
    identify,
    kad::{self, store::MemoryStore},
    mdns,
    ping,
    swarm::NetworkBehaviour,
    PeerId,
};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;

use crate::config::P2PConfig;

/// Custom network behaviour combining all PHANTOM protocols
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "PhantomBehaviourEvent")]
pub struct PhantomBehaviour {
    /// Gossipsub for pub/sub messaging
    pub gossipsub: gossipsub::Behaviour,
    /// Kademlia DHT for peer routing (optional)
    pub kademlia: kad::Behaviour<MemoryStore>,
    /// mDNS for local peer discovery (optional)
    pub mdns: mdns::tokio::Behaviour,
    /// Ping for connection keepalive
    pub ping: ping::Behaviour,
    /// Identify for peer information
    pub identify: identify::Behaviour,
}

/// Events emitted by the combined behaviour
#[derive(Debug)]
pub enum PhantomBehaviourEvent {
    Gossipsub(gossipsub::Event),
    Kademlia(kad::Event),
    Mdns(mdns::Event),
    Ping(ping::Event),
    Identify(identify::Event),
}

impl From<gossipsub::Event> for PhantomBehaviourEvent {
    fn from(event: gossipsub::Event) -> Self {
        PhantomBehaviourEvent::Gossipsub(event)
    }
}

impl From<kad::Event> for PhantomBehaviourEvent {
    fn from(event: kad::Event) -> Self {
        PhantomBehaviourEvent::Kademlia(event)
    }
}

impl From<mdns::Event> for PhantomBehaviourEvent {
    fn from(event: mdns::Event) -> Self {
        PhantomBehaviourEvent::Mdns(event)
    }
}

impl From<ping::Event> for PhantomBehaviourEvent {
    fn from(event: ping::Event) -> Self {
        PhantomBehaviourEvent::Ping(event)
    }
}

impl From<identify::Event> for PhantomBehaviourEvent {
    fn from(event: identify::Event) -> Self {
        PhantomBehaviourEvent::Identify(event)
    }
}

impl PhantomBehaviour {
    /// Create a new PhantomBehaviour
    pub fn new(local_peer_id: PeerId, config: &P2PConfig) -> Self {
        // Create gossipsub with custom config
        let gossipsub = Self::create_gossipsub(local_peer_id, config);

        // Create Kademlia DHT
        let kademlia = Self::create_kademlia(local_peer_id, config);

        // Create mDNS
        let mdns = mdns::tokio::Behaviour::new(
            mdns::Config::default(),
            local_peer_id,
        ).expect("Failed to create mDNS behaviour");

        // Create ping
        let ping = ping::Behaviour::new(
            ping::Config::new()
                .with_interval(config.ping_interval)
                .with_timeout(Duration::from_secs(20)),
        );

        // Create identify
        let identify = identify::Behaviour::new(
            identify::Config::new(
                "/phantom/id/1.0.0".to_string(),
                libp2p::identity::Keypair::generate_ed25519().public(),
            )
            .with_agent_version(format!("phantom/{}", env!("CARGO_PKG_VERSION"))),
        );

        Self {
            gossipsub,
            kademlia,
            mdns,
            ping,
            identify,
        }
    }

    /// Create gossipsub behaviour with PHANTOM-specific config
    fn create_gossipsub(_local_peer_id: PeerId, config: &P2PConfig) -> gossipsub::Behaviour {
        // Custom message ID function based on content hash
        let message_id_fn = |message: &gossipsub::Message| {
            let mut hasher = DefaultHasher::new();
            message.data.hash(&mut hasher);
            message.topic.hash(&mut hasher);
            MessageId::from(hasher.finish().to_be_bytes().to_vec())
        };

        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(config.gossipsub_heartbeat)
            .validation_mode(ValidationMode::Strict)
            .message_id_fn(message_id_fn)
            .max_transmit_size(config.max_message_size)
            .duplicate_cache_time(Duration::from_secs(60))
            .history_length(5)
            .history_gossip(3)
            .mesh_n(6)
            .mesh_n_low(4)
            .mesh_n_high(12)
            .mesh_outbound_min(2)
            .fanout_ttl(Duration::from_secs(60))
            .build()
            .expect("Valid gossipsub config");

        gossipsub::Behaviour::new(
            MessageAuthenticity::Signed(libp2p::identity::Keypair::generate_ed25519()),
            gossipsub_config,
        ).expect("Valid gossipsub behaviour")
    }

    /// Create Kademlia DHT behaviour
    fn create_kademlia(local_peer_id: PeerId, config: &P2PConfig) -> kad::Behaviour<MemoryStore> {
        let store = MemoryStore::new(local_peer_id);

        let mut kad_config = kad::Config::default();
        kad_config.set_replication_factor(
            std::num::NonZeroUsize::new(config.kademlia_replication).unwrap()
        );
        kad_config.set_query_timeout(Duration::from_secs(60));

        kad::Behaviour::with_config(local_peer_id, store, kad_config)
    }

    /// Subscribe to a gossipsub topic
    pub fn subscribe(&mut self, topic: &str) -> bool {
        let topic = IdentTopic::new(topic);
        self.gossipsub.subscribe(&topic).is_ok()
    }

    /// Unsubscribe from a gossipsub topic
    pub fn unsubscribe(&mut self, topic: &str) -> bool {
        let topic = IdentTopic::new(topic);
        self.gossipsub.unsubscribe(&topic).is_ok()
    }

    /// Publish a message to a topic
    pub fn publish(&mut self, topic: &str, data: Vec<u8>) -> Result<gossipsub::MessageId, gossipsub::PublishError> {
        let topic = IdentTopic::new(topic);
        self.gossipsub.publish(topic, data)
    }

    /// Add a peer to the Kademlia routing table
    pub fn add_kad_address(&mut self, peer_id: &PeerId, addr: libp2p::Multiaddr) {
        self.kademlia.add_address(peer_id, addr);
    }

    /// Bootstrap Kademlia from known peers
    pub fn bootstrap(&mut self) -> Result<kad::QueryId, kad::NoKnownPeers> {
        self.kademlia.bootstrap()
    }

    /// Get peers in a gossipsub topic mesh
    pub fn mesh_peers(&self, topic: &str) -> Vec<&PeerId> {
        let topic_hash = IdentTopic::new(topic).hash();
        self.gossipsub.mesh_peers(&topic_hash).collect()
    }

    /// Get all connected peers
    pub fn all_peers(&self) -> Vec<&PeerId> {
        self.gossipsub.all_peers().map(|(p, _)| p).collect()
    }
}

/// Gossipsub topics for PHANTOM network
pub struct Topics {
    /// Transaction propagation
    pub transactions: IdentTopic,
    /// State updates
    pub state: IdentTopic,
    /// Consensus messages
    pub consensus: IdentTopic,
}

impl Topics {
    /// Create topics from config
    pub fn from_config(config: &P2PConfig) -> Self {
        Self {
            transactions: IdentTopic::new(&config.tx_topic),
            state: IdentTopic::new(&config.state_topic),
            consensus: IdentTopic::new(&config.consensus_topic),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_topics_creation() {
        let config = P2PConfig::default();
        let topics = Topics::from_config(&config);

        assert_eq!(topics.transactions.to_string(), config.tx_topic);
        assert_eq!(topics.state.to_string(), config.state_topic);
        assert_eq!(topics.consensus.to_string(), config.consensus_topic);
    }

    #[test]
    fn test_behaviour_event_conversion() {
        // Test that event conversions work
        let ping_event = ping::Event {
            peer: PeerId::random(),
            connection: libp2p::swarm::ConnectionId::new_unchecked(0),
            result: Ok(Duration::from_millis(50)),
        };

        let event: PhantomBehaviourEvent = ping_event.into();
        assert!(matches!(event, PhantomBehaviourEvent::Ping(_)));
    }
}
