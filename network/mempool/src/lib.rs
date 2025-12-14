//! Encrypted Mempool with Threshold Encryption for MEV Protection
//!
//! This module implements a privacy-preserving transaction pool where transactions
//! remain encrypted until a threshold of validators agree to decrypt them. This
//! prevents Maximal Extractable Value (MEV) attacks by keeping transaction contents
//! hidden until inclusion time.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Encrypted Mempool                             │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
//! │  │ Encrypted   │  │ Encrypted   │  │ Encrypted   │  ...        │
//! │  │ Transaction │  │ Transaction │  │ Transaction │             │
//! │  │ (hidden)    │  │ (hidden)    │  │ (hidden)    │             │
//! │  └─────────────┘  └─────────────┘  └─────────────┘             │
//! │         │                │                │                     │
//! │         ▼                ▼                ▼                     │
//! │  ┌───────────────────────────────────────────────────────────┐ │
//! │  │            Threshold Decryption (k-of-n)                  │ │
//! │  │  Share₁ + Share₂ + ... + Shareₖ → Decrypted Transaction   │ │
//! │  └───────────────────────────────────────────────────────────┘ │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

pub mod errors;
pub mod threshold_encryption;

pub use errors::{MempoolError, MempoolResult};
pub use threshold_encryption::{
    DecryptionShare, EncryptionKeyShare, ThresholdCiphertext, ThresholdEncryption,
    ThresholdEncryptionParams,
};

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Unique identifier for an encrypted transaction in the mempool
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EncryptedTxId([u8; 32]);

impl EncryptedTxId {
    /// Create a new transaction ID from a ciphertext
    pub fn from_ciphertext(ciphertext: &ThresholdCiphertext) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(&ciphertext.encrypted_data);
        hasher.update(&ciphertext.nonce);
        let hash = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(hash.as_bytes());
        Self(id)
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for EncryptedTxId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.to_hex()[..16])
    }
}

/// An encrypted transaction entry in the mempool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedTransaction {
    /// Unique identifier derived from ciphertext
    pub id: EncryptedTxId,
    /// The threshold-encrypted transaction data
    pub ciphertext: ThresholdCiphertext,
    /// Collected decryption shares from validators
    pub decryption_shares: BTreeMap<u32, DecryptionShare>,
    /// Timestamp when the transaction was added (for expiry)
    #[serde(skip)]
    pub added_at: Option<Instant>,
    /// Unix timestamp for serialization
    pub added_timestamp_ms: u64,
    /// Priority fee (encrypted but derivable from ZK proof)
    pub priority_fee: u64,
    /// Whether decryption is complete
    pub decrypted: bool,
    /// The decrypted transaction data (only set after threshold is met)
    pub plaintext: Option<Vec<u8>>,
}

impl EncryptedTransaction {
    /// Create a new encrypted transaction
    pub fn new(ciphertext: ThresholdCiphertext, priority_fee: u64) -> Self {
        let id = EncryptedTxId::from_ciphertext(&ciphertext);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            id,
            ciphertext,
            decryption_shares: BTreeMap::new(),
            added_at: Some(Instant::now()),
            added_timestamp_ms: now,
            priority_fee,
            decrypted: false,
            plaintext: None,
        }
    }

    /// Add a decryption share from a validator
    pub fn add_share(&mut self, share: DecryptionShare) -> MempoolResult<()> {
        if self.decrypted {
            return Err(MempoolError::InvalidDecryptionShare(
                "Transaction already decrypted".to_string(),
            ));
        }

        let validator_idx = share.index as u32;
        if self.decryption_shares.contains_key(&validator_idx) {
            return Err(MempoolError::DuplicateTransaction(format!(
                "Share from validator {} already exists",
                validator_idx
            )));
        }

        self.decryption_shares.insert(validator_idx, share);
        Ok(())
    }

    /// Check if we have enough shares to decrypt
    pub fn has_threshold(&self, threshold: usize) -> bool {
        self.decryption_shares.len() >= threshold
    }

    /// Get the number of collected shares
    pub fn share_count(&self) -> usize {
        self.decryption_shares.len()
    }

    /// Get the age of this transaction
    pub fn age(&self) -> Duration {
        self.added_at
            .map(|t| t.elapsed())
            .unwrap_or(Duration::ZERO)
    }
}

/// Simple configuration for the encrypted mempool
#[derive(Debug, Clone)]
pub struct MempoolConfig {
    /// Maximum number of encrypted transactions
    pub max_transactions: usize,
    /// Transaction expiry time
    pub transaction_ttl: Duration,
    /// Total number of validators
    pub total_validators: usize,
    /// Threshold required for decryption
    pub threshold: usize,
    /// Minimum priority fee
    pub min_priority_fee: u64,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_transactions: 10_000,
            transaction_ttl: Duration::from_secs(300), // 5 minutes
            total_validators: 5,
            threshold: 3,
            min_priority_fee: 0,
        }
    }
}

/// The encrypted mempool state
struct MempoolState {
    /// Encrypted transactions indexed by ID
    transactions: HashMap<EncryptedTxId, EncryptedTransaction>,
    /// Transactions ordered by priority fee for block building
    by_priority: BTreeMap<(u64, EncryptedTxId), EncryptedTxId>,
}

impl MempoolState {
    fn new() -> Self {
        Self {
            transactions: HashMap::new(),
            by_priority: BTreeMap::new(),
        }
    }
}

/// The encrypted mempool with threshold encryption for MEV protection
pub struct EncryptedMempool {
    /// Mempool configuration
    config: MempoolConfig,
    /// Threshold encryption scheme
    encryption: ThresholdEncryption,
    /// Key shares for validators
    key_shares: Vec<EncryptionKeyShare>,
    /// Internal state protected by RwLock
    state: Arc<RwLock<MempoolState>>,
}

impl EncryptedMempool {
    /// Create a new encrypted mempool
    pub fn new(config: MempoolConfig) -> MempoolResult<Self> {
        let (encryption, key_shares) = ThresholdEncryption::new(
            config.total_validators,
            config.threshold,
        )?;

        Ok(Self {
            config,
            encryption,
            key_shares,
            state: Arc::new(RwLock::new(MempoolState::new())),
        })
    }

    /// Create with default configuration
    pub fn with_defaults() -> MempoolResult<Self> {
        Self::new(MempoolConfig::default())
    }

    /// Get the threshold encryption scheme
    pub fn encryption(&self) -> &ThresholdEncryption {
        &self.encryption
    }

    /// Get the key shares (for validators)
    pub fn key_shares(&self) -> &[EncryptionKeyShare] {
        &self.key_shares
    }

    /// Get the threshold required for decryption
    pub fn threshold(&self) -> usize {
        self.config.threshold
    }

    /// Encrypt a transaction for submission to the mempool
    pub fn encrypt_transaction(&self, plaintext: &[u8]) -> MempoolResult<ThresholdCiphertext> {
        self.encryption.encrypt(plaintext)
    }

    /// Submit an encrypted transaction to the mempool
    pub async fn submit(
        &self,
        ciphertext: ThresholdCiphertext,
        priority_fee: u64,
    ) -> MempoolResult<EncryptedTxId> {
        // Check minimum fee
        if priority_fee < self.config.min_priority_fee {
            return Err(MempoolError::InvalidEncryptedTransaction(format!(
                "Priority fee {} below minimum {}",
                priority_fee, self.config.min_priority_fee
            )));
        }

        let mut state = self.state.write().await;

        // Check capacity
        if state.transactions.len() >= self.config.max_transactions {
            return Err(MempoolError::MempoolFull {
                capacity: self.config.max_transactions,
                current: state.transactions.len(),
            });
        }

        let tx = EncryptedTransaction::new(ciphertext, priority_fee);
        let id = tx.id;

        // Check for duplicates
        if state.transactions.contains_key(&id) {
            return Err(MempoolError::DuplicateTransaction(id.to_hex()));
        }

        // Add to indexes
        state.by_priority.insert((priority_fee, id), id);
        state.transactions.insert(id, tx);

        Ok(id)
    }

    /// Get an encrypted transaction by ID
    pub async fn get(&self, id: &EncryptedTxId) -> MempoolResult<EncryptedTransaction> {
        let state = self.state.read().await;
        state
            .transactions
            .get(id)
            .cloned()
            .ok_or_else(|| MempoolError::TransactionNotFound(id.to_hex()))
    }

    /// Submit a decryption share for a transaction
    pub async fn submit_share(
        &self,
        tx_id: &EncryptedTxId,
        share: DecryptionShare,
    ) -> MempoolResult<bool> {
        let mut state = self.state.write().await;

        let tx = state
            .transactions
            .get_mut(tx_id)
            .ok_or_else(|| MempoolError::TransactionNotFound(tx_id.to_hex()))?;

        // Verify the share
        if !self.encryption.verify_share(&share, &tx.ciphertext) {
            return Err(MempoolError::InvalidDecryptionShare(format!(
                "Share from validator {} failed verification",
                share.index
            )));
        }

        // Add the share
        tx.add_share(share)?;

        // Check if we can decrypt now
        let threshold = self.config.threshold;
        Ok(tx.has_threshold(threshold))
    }

    /// Attempt to decrypt a transaction if threshold is met
    pub async fn try_decrypt(&self, tx_id: &EncryptedTxId) -> MempoolResult<Option<Vec<u8>>> {
        let mut state = self.state.write().await;

        let tx = state
            .transactions
            .get_mut(tx_id)
            .ok_or_else(|| MempoolError::TransactionNotFound(tx_id.to_hex()))?;

        if tx.decrypted {
            return Ok(tx.plaintext.clone());
        }

        let threshold = self.config.threshold;
        if !tx.has_threshold(threshold) {
            return Ok(None);
        }

        // Collect shares
        let shares: Vec<DecryptionShare> = tx.decryption_shares.values().cloned().collect();

        // Attempt decryption
        let plaintext = self.encryption.decrypt(&tx.ciphertext, &shares)?;

        tx.decrypted = true;
        tx.plaintext = Some(plaintext.clone());

        Ok(Some(plaintext))
    }

    /// Get the highest-priority transactions ready for inclusion
    pub async fn get_pending(&self, limit: usize) -> Vec<EncryptedTransaction> {
        let state = self.state.read().await;

        state
            .by_priority
            .iter()
            .rev() // Highest priority first
            .take(limit)
            .filter_map(|(_, id)| state.transactions.get(id).cloned())
            .collect()
    }

    /// Get transactions that have been decrypted
    pub async fn get_decrypted(&self, limit: usize) -> Vec<EncryptedTransaction> {
        let state = self.state.read().await;

        state
            .by_priority
            .iter()
            .rev()
            .filter_map(|(_, id)| state.transactions.get(id))
            .filter(|tx| tx.decrypted)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Remove a transaction from the mempool (after inclusion in a block)
    pub async fn remove(&self, tx_id: &EncryptedTxId) -> MempoolResult<EncryptedTransaction> {
        let mut state = self.state.write().await;

        let tx = state
            .transactions
            .remove(tx_id)
            .ok_or_else(|| MempoolError::TransactionNotFound(tx_id.to_hex()))?;

        state.by_priority.remove(&(tx.priority_fee, *tx_id));

        Ok(tx)
    }

    /// Remove expired transactions
    pub async fn prune_expired(&self) -> Vec<EncryptedTxId> {
        let mut state = self.state.write().await;
        let ttl = self.config.transaction_ttl;

        let expired: Vec<EncryptedTxId> = state
            .transactions
            .iter()
            .filter(|(_, tx)| tx.age() > ttl)
            .map(|(id, _)| *id)
            .collect();

        for id in &expired {
            if let Some(tx) = state.transactions.remove(id) {
                state.by_priority.remove(&(tx.priority_fee, *id));
            }
        }

        expired
    }

    /// Get mempool statistics
    pub async fn stats(&self) -> MempoolStats {
        let state = self.state.read().await;

        let total = state.transactions.len();
        let decrypted = state.transactions.values().filter(|tx| tx.decrypted).count();
        let pending_decryption = total - decrypted;

        let total_fees: u64 = state.transactions.values().map(|tx| tx.priority_fee).sum();

        MempoolStats {
            total_transactions: total,
            decrypted_transactions: decrypted,
            pending_decryption,
            total_priority_fees: total_fees,
            capacity: self.config.max_transactions,
            threshold: self.config.threshold,
            total_validators: self.config.total_validators,
        }
    }

    /// Get the number of transactions in the mempool
    pub async fn len(&self) -> usize {
        self.state.read().await.transactions.len()
    }

    /// Check if the mempool is empty
    pub async fn is_empty(&self) -> bool {
        self.state.read().await.transactions.is_empty()
    }
}

/// Statistics about the encrypted mempool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolStats {
    /// Total number of encrypted transactions
    pub total_transactions: usize,
    /// Number of transactions that have been decrypted
    pub decrypted_transactions: usize,
    /// Number of transactions awaiting decryption
    pub pending_decryption: usize,
    /// Sum of all priority fees
    pub total_priority_fees: u64,
    /// Maximum capacity
    pub capacity: usize,
    /// Decryption threshold
    pub threshold: usize,
    /// Total validators in committee
    pub total_validators: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mempool_creation() {
        let mempool = EncryptedMempool::with_defaults().unwrap();
        assert!(mempool.is_empty().await);

        let stats = mempool.stats().await;
        assert_eq!(stats.total_transactions, 0);
        assert_eq!(stats.threshold, 3);
        assert_eq!(stats.total_validators, 5);
    }

    #[tokio::test]
    async fn test_submit_encrypted_transaction() {
        let mempool = EncryptedMempool::with_defaults().unwrap();

        // Encrypt a transaction
        let tx_data = b"transfer 100 tokens to Alice";
        let ciphertext = mempool.encrypt_transaction(tx_data).unwrap();

        // Submit to mempool
        let tx_id = mempool.submit(ciphertext, 1000).await.unwrap();

        // Verify it's in the mempool
        assert_eq!(mempool.len().await, 1);

        let tx = mempool.get(&tx_id).await.unwrap();
        assert_eq!(tx.priority_fee, 1000);
        assert!(!tx.decrypted);
        assert_eq!(tx.share_count(), 0);
    }

    #[tokio::test]
    async fn test_duplicate_rejection() {
        let mempool = EncryptedMempool::with_defaults().unwrap();

        let tx_data = b"unique transaction";
        let ciphertext = mempool.encrypt_transaction(tx_data).unwrap();

        // First submission succeeds
        mempool.submit(ciphertext.clone(), 100).await.unwrap();

        // Duplicate should fail
        let result = mempool.submit(ciphertext, 100).await;
        assert!(matches!(result, Err(MempoolError::DuplicateTransaction(_))));
    }

    #[tokio::test]
    async fn test_threshold_decryption_flow() {
        // Create mempool with threshold 2-of-3
        let config = MempoolConfig {
            threshold: 2,
            total_validators: 3,
            ..Default::default()
        };
        let mempool = EncryptedMempool::new(config).unwrap();

        // Submit encrypted transaction
        let tx_data = b"private transfer to Bob";
        let ciphertext = mempool.encrypt_transaction(tx_data).unwrap();
        let tx_id = mempool.submit(ciphertext.clone(), 500).await.unwrap();

        // Generate decryption shares from validators
        let key_shares = mempool.key_shares();
        let dec_shares: Vec<_> = key_shares.iter()
            .take(2)
            .map(|ks| ks.create_decryption_share(&ciphertext).unwrap())
            .collect();

        // Submit first share - threshold not met yet
        let ready = mempool.submit_share(&tx_id, dec_shares[0].clone()).await.unwrap();
        assert!(!ready);

        // Submit second share - threshold met
        let ready = mempool.submit_share(&tx_id, dec_shares[1].clone()).await.unwrap();
        assert!(ready);

        // Now we can decrypt
        let plaintext = mempool.try_decrypt(&tx_id).await.unwrap();
        assert!(plaintext.is_some());
        assert_eq!(plaintext.unwrap(), tx_data);

        // Verify transaction is marked as decrypted
        let tx = mempool.get(&tx_id).await.unwrap();
        assert!(tx.decrypted);
    }

    #[tokio::test]
    async fn test_priority_ordering() {
        let mempool = EncryptedMempool::with_defaults().unwrap();

        // Submit transactions with different priorities
        let priorities = [100u64, 500, 200, 1000, 50];
        let mut tx_ids = Vec::new();

        for (i, &priority) in priorities.iter().enumerate() {
            let tx_data = format!("transaction {}", i);
            let ciphertext = mempool.encrypt_transaction(tx_data.as_bytes()).unwrap();
            let tx_id = mempool.submit(ciphertext, priority).await.unwrap();
            tx_ids.push(tx_id);
        }

        // Get pending transactions - should be ordered by priority (highest first)
        let pending = mempool.get_pending(5).await;
        let fees: Vec<u64> = pending.iter().map(|tx| tx.priority_fee).collect();
        assert_eq!(fees, vec![1000, 500, 200, 100, 50]);
    }

    #[tokio::test]
    async fn test_mempool_capacity() {
        let config = MempoolConfig {
            max_transactions: 3,
            ..Default::default()
        };
        let mempool = EncryptedMempool::new(config).unwrap();

        // Fill the mempool
        for i in 0..3 {
            let tx_data = format!("tx {}", i);
            let ciphertext = mempool.encrypt_transaction(tx_data.as_bytes()).unwrap();
            mempool.submit(ciphertext, i as u64).await.unwrap();
        }

        // Next submission should fail
        let tx_data = b"one more";
        let ciphertext = mempool.encrypt_transaction(tx_data).unwrap();
        let result = mempool.submit(ciphertext, 100).await;

        assert!(matches!(
            result,
            Err(MempoolError::MempoolFull {
                capacity: 3,
                current: 3
            })
        ));
    }

    #[tokio::test]
    async fn test_remove_transaction() {
        let mempool = EncryptedMempool::with_defaults().unwrap();

        let tx_data = b"removable transaction";
        let ciphertext = mempool.encrypt_transaction(tx_data).unwrap();
        let tx_id = mempool.submit(ciphertext, 100).await.unwrap();

        assert_eq!(mempool.len().await, 1);

        // Remove the transaction
        let removed = mempool.remove(&tx_id).await.unwrap();
        assert_eq!(removed.priority_fee, 100);

        assert!(mempool.is_empty().await);

        // Should not be found anymore
        let result = mempool.get(&tx_id).await;
        assert!(matches!(result, Err(MempoolError::TransactionNotFound(_))));
    }

    #[tokio::test]
    async fn test_stats() {
        let config = MempoolConfig {
            threshold: 2,
            total_validators: 3,
            ..Default::default()
        };
        let mempool = EncryptedMempool::new(config).unwrap();

        // Add some transactions
        for i in 0..5 {
            let tx_data = format!("tx {}", i);
            let ciphertext = mempool.encrypt_transaction(tx_data.as_bytes()).unwrap();
            mempool.submit(ciphertext, (i + 1) * 100).await.unwrap();
        }

        // Decrypt one transaction
        let pending = mempool.get_pending(1).await;
        let tx_id = pending[0].id;
        let ciphertext = pending[0].ciphertext.clone();

        let key_shares = mempool.key_shares();
        let dec_shares: Vec<_> = key_shares.iter()
            .take(2)
            .map(|ks| ks.create_decryption_share(&ciphertext).unwrap())
            .collect();
        mempool.submit_share(&tx_id, dec_shares[0].clone()).await.unwrap();
        mempool.submit_share(&tx_id, dec_shares[1].clone()).await.unwrap();
        mempool.try_decrypt(&tx_id).await.unwrap();

        let stats = mempool.stats().await;
        assert_eq!(stats.total_transactions, 5);
        assert_eq!(stats.decrypted_transactions, 1);
        assert_eq!(stats.pending_decryption, 4);
        assert_eq!(stats.total_priority_fees, 100 + 200 + 300 + 400 + 500);
        assert_eq!(stats.threshold, 2);
        assert_eq!(stats.total_validators, 3);
    }

    #[test]
    fn test_encrypted_tx_id() {
        let (encryption, _shares) = ThresholdEncryption::new(3, 2).unwrap();
        let ciphertext = encryption.encrypt(b"test data").unwrap();

        let id1 = EncryptedTxId::from_ciphertext(&ciphertext);
        let id2 = EncryptedTxId::from_ciphertext(&ciphertext);

        // Same ciphertext should produce same ID
        assert_eq!(id1, id2);

        // Different ciphertext should produce different ID
        let ciphertext2 = encryption.encrypt(b"different data").unwrap();
        let id3 = EncryptedTxId::from_ciphertext(&ciphertext2);
        assert_ne!(id1, id3);

        // Hex representation
        assert_eq!(id1.to_hex().len(), 64);
    }
}
