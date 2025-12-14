//! P2P Network Configuration

use libp2p::{Multiaddr, PeerId};
use std::time::Duration;

/// P2P network configuration
#[derive(Clone, Debug)]
pub struct P2PConfig {
    /// Node name for identification
    pub node_name: String,
    /// Listen addresses
    pub listen_addrs: Vec<Multiaddr>,
    /// Bootstrap peers for initial connections
    pub bootstrap_peers: Vec<(PeerId, Multiaddr)>,
    /// Enable mDNS for local peer discovery
    pub enable_mdns: bool,
    /// Enable Kademlia DHT for peer routing
    pub enable_kademlia: bool,
    /// Gossipsub topic for transactions
    pub tx_topic: String,
    /// Gossipsub topic for blocks/state updates
    pub state_topic: String,
    /// Gossipsub topic for consensus messages
    pub consensus_topic: String,
    /// Maximum inbound connections
    pub max_inbound: u32,
    /// Maximum outbound connections
    pub max_outbound: u32,
    /// Connection idle timeout
    pub idle_timeout: Duration,
    /// Ping interval
    pub ping_interval: Duration,
    /// Kademlia replication factor
    pub kademlia_replication: usize,
    /// Gossipsub heartbeat interval
    pub gossipsub_heartbeat: Duration,
    /// Maximum message size
    pub max_message_size: usize,
}

impl Default for P2PConfig {
    fn default() -> Self {
        Self {
            node_name: "phantom-node".to_string(),
            listen_addrs: vec![
                "/ip4/0.0.0.0/tcp/0".parse().unwrap(),
                "/ip6/::/tcp/0".parse().unwrap(),
            ],
            bootstrap_peers: Vec::new(),
            enable_mdns: true,
            enable_kademlia: true,
            tx_topic: "phantom/transactions/1.0.0".to_string(),
            state_topic: "phantom/state/1.0.0".to_string(),
            consensus_topic: "phantom/consensus/1.0.0".to_string(),
            max_inbound: 100,
            max_outbound: 50,
            idle_timeout: Duration::from_secs(60),
            ping_interval: Duration::from_secs(30),
            kademlia_replication: 20,
            gossipsub_heartbeat: Duration::from_secs(1),
            max_message_size: 1024 * 1024, // 1MB
        }
    }
}

impl P2PConfig {
    /// Create a config for local development/testing
    pub fn local() -> Self {
        Self {
            node_name: "phantom-local".to_string(),
            listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
            enable_mdns: true,
            enable_kademlia: false,
            ..Default::default()
        }
    }

    /// Create a config for testnet
    pub fn testnet() -> Self {
        Self {
            node_name: "phantom-testnet".to_string(),
            enable_mdns: false,
            enable_kademlia: true,
            ..Default::default()
        }
    }

    /// Create a config for mainnet
    pub fn mainnet() -> Self {
        Self {
            node_name: "phantom-mainnet".to_string(),
            enable_mdns: false,
            enable_kademlia: true,
            max_inbound: 200,
            max_outbound: 100,
            ..Default::default()
        }
    }

    /// Add a bootstrap peer
    pub fn with_bootstrap(mut self, peer_id: PeerId, addr: Multiaddr) -> Self {
        self.bootstrap_peers.push((peer_id, addr));
        self
    }

    /// Set listen addresses
    pub fn with_listen_addrs(mut self, addrs: Vec<Multiaddr>) -> Self {
        self.listen_addrs = addrs;
        self
    }

    /// Set node name
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.node_name = name.into();
        self
    }
}
