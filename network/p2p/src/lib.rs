//! PHANTOM P2P Networking Layer
//!
//! Provides peer-to-peer networking for the PHANTOM network using libp2p.
//!
//! # Features
//!
//! - **Gossipsub** for efficient message propagation (transactions, state, consensus)
//! - **Kademlia DHT** for peer routing and content discovery
//! - **mDNS** for local network peer discovery
//! - **Noise protocol** for encrypted connections
//! - **Yamux** for stream multiplexing
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Application Layer                         │
//! │     (Wallet, Consensus, State Sync, Contract Execution)     │
//! ├─────────────────────────────────────────────────────────────┤
//! │                    SwarmManager API                          │
//! │  publish() │ subscribe() │ connect() │ recv_event()         │
//! ├─────────────────────────────────────────────────────────────┤
//! │                  PhantomBehaviour                            │
//! │  ┌───────────┐ ┌──────────┐ ┌──────┐ ┌────────┐ ┌────────┐ │
//! │  │ Gossipsub │ │ Kademlia │ │ mDNS │ │  Ping  │ │Identify│ │
//! │  └───────────┘ └──────────┘ └──────┘ └────────┘ └────────┘ │
//! ├─────────────────────────────────────────────────────────────┤
//! │                  libp2p Transport                            │
//! │              TCP + Noise + Yamux                             │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use phantom_p2p::{SwarmManager, P2PConfig, NetworkMessage, TransactionMessage};
//!
//! #[tokio::main]
//! async fn main() {
//!     // Create and start the P2P network
//!     let config = P2PConfig::local();
//!     let mut manager = SwarmManager::new(config);
//!     manager.start().await.unwrap();
//!
//!     // Publish a transaction
//!     let tx_msg = TransactionMessage::new(
//!         [1u8; 32],  // tx_id
//!         vec![1, 2, 3],  // encrypted_data
//!         [2u8; 32],  // nullifier
//!         vec![4, 5, 6],  // proof
//!     );
//!     manager.publish_transaction(NetworkMessage::Transaction(tx_msg)).await.unwrap();
//!
//!     // Handle incoming events
//!     while let Some(event) = manager.recv_event().await {
//!         println!("Received event: {:?}", event);
//!     }
//! }
//! ```
//!
//! # Topics
//!
//! The network uses three gossipsub topics:
//! - `phantom/transactions/1.0.0` - Encrypted transaction propagation
//! - `phantom/state/1.0.0` - State fragment updates
//! - `phantom/consensus/1.0.0` - CWA consensus messages

pub mod behaviour;
pub mod config;
pub mod errors;
pub mod messages;
pub mod swarm;
pub mod sync;

// Re-exports
pub use behaviour::{PhantomBehaviour, PhantomBehaviourEvent, Topics};
pub use config::P2PConfig;
pub use errors::{P2PError, P2PResult};
pub use messages::{
    Attestation, ConsensusMessage, ConsensusMessageType, HeartbeatMessage,
    NetworkMessage, PeerAnnounceMessage, PeerCapabilities, StateFragmentType,
    StateUpdateMessage, TransactionMessage,
};
pub use swarm::{PeerState, SwarmCommand, SwarmEvent_, SwarmManager};
pub use sync::{
    EncryptedFragment, MerkleProof, MerkleNode, MerklePosition,
    StateSnapshot, StateSyncManager, SyncConfig, SyncEvent, SyncRequest,
    SyncResponse, SyncSession, SyncSessionId, SyncSessionState, SyncStats,
};

// Re-export libp2p types that users might need
pub use libp2p::{Multiaddr, PeerId};

/// Prelude for convenient imports
pub mod prelude {
    pub use crate::behaviour::{PhantomBehaviour, Topics};
    pub use crate::config::P2PConfig;
    pub use crate::errors::{P2PError, P2PResult};
    pub use crate::messages::{NetworkMessage, TransactionMessage, StateUpdateMessage, ConsensusMessage};
    pub use crate::swarm::{SwarmManager, SwarmEvent_, PeerState};
    pub use crate::sync::{StateSyncManager, SyncConfig, SyncEvent, StateSnapshot, EncryptedFragment};
    pub use libp2p::{Multiaddr, PeerId};
}

/// Protocol version constants
pub mod protocol {
    /// PHANTOM protocol version
    pub const VERSION: &str = "1.0.0";
    /// Protocol identifier prefix
    pub const ID_PREFIX: &str = "/phantom";
    /// Transaction protocol ID
    pub const TRANSACTIONS: &str = "/phantom/transactions/1.0.0";
    /// State sync protocol ID
    pub const STATE: &str = "/phantom/state/1.0.0";
    /// Consensus protocol ID
    pub const CONSENSUS: &str = "/phantom/consensus/1.0.0";
    /// Identify protocol ID
    pub const IDENTIFY: &str = "/phantom/id/1.0.0";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prelude_imports() {
        // Verify prelude types are accessible
        let _ = P2PConfig::default();
        let _ = P2PError::NotStarted;
    }

    #[test]
    fn test_protocol_constants() {
        assert!(protocol::VERSION.len() > 0);
        assert!(protocol::TRANSACTIONS.starts_with(protocol::ID_PREFIX));
        assert!(protocol::STATE.starts_with(protocol::ID_PREFIX));
        assert!(protocol::CONSENSUS.starts_with(protocol::ID_PREFIX));
    }

    #[test]
    fn test_network_message_variants() {
        let tx_msg = TransactionMessage::new(
            [1u8; 32],
            vec![1, 2, 3],
            [2u8; 32],
            vec![4, 5, 6],
        );
        let msg = NetworkMessage::Transaction(tx_msg);
        assert_eq!(msg.message_type(), "transaction");

        let hb_msg = HeartbeatMessage {
            node_id: [0u8; 32],
            sequence: 1,
            height: 100,
            timestamp: 12345,
        };
        let msg = NetworkMessage::Heartbeat(hb_msg);
        assert_eq!(msg.message_type(), "heartbeat");
    }

    #[test]
    fn test_config_presets() {
        let local = P2PConfig::local();
        assert!(local.enable_mdns);

        let testnet = P2PConfig::testnet();
        assert!(!testnet.enable_mdns);
        assert!(testnet.enable_kademlia);

        let mainnet = P2PConfig::mainnet();
        assert!(mainnet.max_inbound > testnet.max_inbound);
    }
}
