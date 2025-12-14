//! RPC Request and Response Types

use serde::{Deserialize, Serialize};

/// Node information response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeInfo {
    /// Node version
    pub version: String,
    /// Network name (mainnet, testnet, local)
    pub network: String,
    /// Node peer ID
    pub peer_id: String,
    /// Whether node is running
    pub is_running: bool,
    /// Whether node is a validator
    pub is_validator: bool,
    /// Validator stake (if validator)
    pub validator_stake: Option<u64>,
    /// Current block height/epoch
    pub epoch: u64,
    /// Current consensus round
    pub round: u64,
    /// State merkle root (hex)
    pub state_root: String,
    /// Number of connected peers
    pub peer_count: usize,
    /// Mempool transaction count
    pub mempool_size: usize,
}

/// Sync status response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatus {
    /// Whether currently syncing
    pub syncing: bool,
    /// Current epoch
    pub current_epoch: u64,
    /// Highest known epoch
    pub highest_epoch: u64,
    /// Sync progress (0.0 - 1.0)
    pub progress: f64,
    /// Number of peers syncing from
    pub sync_peers: usize,
}

/// Transaction submission request
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendTransactionRequest {
    /// Recipient address (hex)
    pub to: String,
    /// Amount in smallest units
    pub amount: u64,
    /// Priority fee (optional)
    #[serde(default)]
    pub fee: u64,
    /// Memo/note (optional)
    #[serde(default)]
    pub memo: Option<String>,
}

/// Transaction submission response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendTransactionResponse {
    /// Transaction ID (hex)
    pub tx_id: String,
    /// Transaction status
    pub status: String,
}

/// Transaction status response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionInfo {
    /// Transaction ID (hex)
    pub tx_id: String,
    /// Status: pending, mempool, attesting, finalized, failed
    pub status: String,
    /// Number of attestations received
    pub attestation_count: usize,
    /// Required attestation threshold
    pub threshold: usize,
    /// Block/epoch included in (if finalized)
    pub epoch: Option<u64>,
    /// Timestamp of last status change
    pub timestamp: u64,
}

/// Balance response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BalanceResponse {
    /// Confirmed balance
    pub confirmed: u64,
    /// Pending (unconfirmed) balance
    pub pending: u64,
    /// Total (confirmed + pending)
    pub total: u64,
}

/// Validator info
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidatorInfo {
    /// Validator ID (hex)
    pub id: String,
    /// Stake amount
    pub stake: u64,
    /// Is active in current round
    pub is_active: bool,
    /// Attestations provided
    pub attestation_count: u64,
}

/// Raw transaction submission
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawTransactionRequest {
    /// Raw transaction bytes (hex encoded)
    pub data: String,
}

/// State proof request
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateProofRequest {
    /// Commitment hash (hex)
    pub commitment: String,
}

/// State proof response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateProofResponse {
    /// Merkle root (hex)
    pub root: String,
    /// Merkle path (array of hex hashes)
    pub path: Vec<String>,
    /// Path indices (left/right)
    pub indices: Vec<bool>,
    /// Whether commitment exists in state
    pub exists: bool,
}

/// Mempool info
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MempoolInfo {
    /// Number of pending transactions
    pub size: usize,
    /// Total bytes of pending transactions
    pub bytes: usize,
    /// Maximum mempool size
    pub max_size: usize,
    /// Minimum fee for inclusion
    pub min_fee: u64,
}

/// Network peers info
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerInfo {
    /// Peer ID
    pub peer_id: String,
    /// Remote address
    pub address: String,
    /// Connection direction (inbound/outbound)
    pub direction: String,
    /// Latency in milliseconds
    pub latency_ms: u64,
}
