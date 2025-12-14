//! P2P Network Message Types
//!
//! Defines the message types exchanged over the gossipsub network.

use serde::{Deserialize, Serialize};

/// Message types for the P2P network
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NetworkMessage {
    /// Encrypted transaction
    Transaction(TransactionMessage),
    /// State update/sync message
    StateUpdate(StateUpdateMessage),
    /// Consensus message (CWA attestations)
    Consensus(ConsensusMessage),
    /// Peer announcement
    PeerAnnounce(PeerAnnounceMessage),
    /// Heartbeat for liveness
    Heartbeat(HeartbeatMessage),
}

/// Encrypted transaction message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionMessage {
    /// Transaction ID (hash)
    pub tx_id: [u8; 32],
    /// Encrypted transaction data
    pub encrypted_data: Vec<u8>,
    /// Nullifier (for double-spend prevention)
    pub nullifier: [u8; 32],
    /// ZK proof of validity
    pub proof: Vec<u8>,
    /// Timestamp
    pub timestamp: u64,
    /// Sender's ephemeral public key (for mixnet routing)
    pub ephemeral_key: [u8; 32],
}

impl TransactionMessage {
    /// Create a new transaction message
    pub fn new(
        tx_id: [u8; 32],
        encrypted_data: Vec<u8>,
        nullifier: [u8; 32],
        proof: Vec<u8>,
    ) -> Self {
        Self {
            tx_id,
            encrypted_data,
            nullifier,
            proof,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            ephemeral_key: [0u8; 32],
        }
    }

    /// Compute message hash
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.tx_id);
        hasher.update(&self.nullifier);
        hasher.update(&self.timestamp.to_le_bytes());
        *hasher.finalize().as_bytes()
    }
}

/// State update message for synchronization
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateUpdateMessage {
    /// State fragment ID
    pub fragment_id: [u8; 32],
    /// Fragment type
    pub fragment_type: StateFragmentType,
    /// Encrypted fragment data
    pub encrypted_data: Vec<u8>,
    /// Version/sequence number
    pub version: u64,
    /// Merkle proof of inclusion (if applicable)
    pub merkle_proof: Option<Vec<[u8; 32]>>,
    /// Attestation signatures
    pub attestations: Vec<Attestation>,
}

/// Types of state fragments
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum StateFragmentType {
    /// Account balance update
    Balance,
    /// Contract state update
    Contract,
    /// Nullifier tree update
    Nullifier,
    /// Witness set update
    Witness,
    /// Global state commitment
    StateRoot,
}

/// Attestation from a witness validator
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attestation {
    /// Validator's public key
    pub validator_key: [u8; 32],
    /// Signature over the fragment
    pub signature: Vec<u8>,
    /// Timestamp
    pub timestamp: u64,
}

/// Consensus message for CWA protocol
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusMessage {
    /// Message type
    pub msg_type: ConsensusMessageType,
    /// Round number
    pub round: u64,
    /// Sender validator ID
    pub validator_id: [u8; 32],
    /// Message payload
    pub payload: Vec<u8>,
    /// Signature
    pub signature: Vec<u8>,
}

/// Types of consensus messages
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConsensusMessageType {
    /// Witness selection VRF proof
    WitnessSelection,
    /// Attestation vote
    Attestation,
    /// Threshold signature share
    ThresholdShare,
    /// Final threshold signature
    ThresholdComplete,
    /// View change request
    ViewChange,
}

/// Peer announcement for discovery
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerAnnounceMessage {
    /// Peer's node ID
    pub node_id: [u8; 32],
    /// Peer's public key
    pub public_key: [u8; 32],
    /// Advertised addresses
    pub addresses: Vec<String>,
    /// Peer capabilities
    pub capabilities: PeerCapabilities,
    /// Version string
    pub version: String,
    /// Timestamp
    pub timestamp: u64,
    /// Signature over announcement
    pub signature: Vec<u8>,
}

/// Peer capabilities flags
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PeerCapabilities {
    /// Can act as mix node
    pub mix_node: bool,
    /// Can act as witness validator
    pub validator: bool,
    /// Supports full state sync
    pub full_node: bool,
    /// Light client only
    pub light_client: bool,
    /// Supports encrypted mempool
    pub encrypted_mempool: bool,
}

/// Heartbeat for liveness checking
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeartbeatMessage {
    /// Sender node ID
    pub node_id: [u8; 32],
    /// Sequence number
    pub sequence: u64,
    /// Current block/state height
    pub height: u64,
    /// Timestamp
    pub timestamp: u64,
}

impl NetworkMessage {
    /// Serialize message to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Deserialize message from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        bincode::deserialize(data).ok()
    }

    /// Get message type as string
    pub fn message_type(&self) -> &'static str {
        match self {
            NetworkMessage::Transaction(_) => "transaction",
            NetworkMessage::StateUpdate(_) => "state_update",
            NetworkMessage::Consensus(_) => "consensus",
            NetworkMessage::PeerAnnounce(_) => "peer_announce",
            NetworkMessage::Heartbeat(_) => "heartbeat",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_message() {
        let msg = TransactionMessage::new(
            [1u8; 32],
            vec![1, 2, 3, 4],
            [2u8; 32],
            vec![5, 6, 7, 8],
        );

        assert_eq!(msg.tx_id, [1u8; 32]);
        assert_eq!(msg.nullifier, [2u8; 32]);
        assert!(msg.timestamp > 0);

        let hash = msg.hash();
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_network_message_serialization() {
        let tx_msg = TransactionMessage::new(
            [1u8; 32],
            vec![1, 2, 3],
            [2u8; 32],
            vec![4, 5, 6],
        );

        let msg = NetworkMessage::Transaction(tx_msg);
        let bytes = msg.to_bytes();
        assert!(!bytes.is_empty());

        let restored = NetworkMessage::from_bytes(&bytes);
        assert!(restored.is_some());
        assert_eq!(restored.unwrap().message_type(), "transaction");
    }

    #[test]
    fn test_peer_capabilities() {
        let caps = PeerCapabilities {
            mix_node: true,
            validator: true,
            full_node: true,
            light_client: false,
            encrypted_mempool: true,
        };

        assert!(caps.mix_node);
        assert!(caps.validator);
        assert!(!caps.light_client);
    }

    #[test]
    fn test_state_fragment_types() {
        assert_ne!(StateFragmentType::Balance, StateFragmentType::Contract);
        assert_eq!(StateFragmentType::Nullifier, StateFragmentType::Nullifier);
    }
}
