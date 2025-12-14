//! Complete Transaction Lifecycle
//!
//! Orchestrates the full transaction flow:
//! 1. Create - Build transaction with inputs/outputs
//! 2. Sign - Generate binding signature with spending keys
//! 3. Prove - Generate ZK proof (Nova or Groth16)
//! 4. Propagate - Submit to encrypted mempool and P2P network
//! 5. Confirm - Wait for witness attestation

use crate::{
    HDWallet, SpendKey, StealthAddress, ViewKey,
    transaction::{
        NoteManager, OwnedNote, Transaction, TransactionBuilder,
        TransactionConfig, TransactionError, TransactionInput,
        TransactionOutput, TransactionVerifier,
    },
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{mpsc, RwLock};

/// Errors during transaction lifecycle
#[derive(Debug, Error)]
pub enum LifecycleError {
    #[error("Transaction error: {0}")]
    Transaction(#[from] TransactionError),
    #[error("Wallet not initialized")]
    WalletNotInitialized,
    #[error("Insufficient funds: have {have}, need {need}")]
    InsufficientFunds { have: u64, need: u64 },
    #[error("No notes available")]
    NoNotesAvailable,
    #[error("Propagation failed: {0}")]
    PropagationFailed(String),
    #[error("Confirmation timeout")]
    ConfirmationTimeout,
    #[error("Transaction rejected: {0}")]
    Rejected(String),
    #[error("State error: {0}")]
    StateError(String),
    #[error("Network error: {0}")]
    NetworkError(String),
}

/// Result type for lifecycle operations
pub type LifecycleResult<T> = Result<T, LifecycleError>;

/// Transaction status in the lifecycle
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionStatus {
    /// Transaction created but not yet signed
    Created,
    /// Transaction signed with binding signature
    Signed,
    /// ZK proof generated
    Proved,
    /// Submitted to mempool
    Submitted,
    /// Propagated to P2P network
    Propagated,
    /// Waiting for witness attestation
    Pending,
    /// Confirmed by witness threshold
    Confirmed { attestation_count: usize },
    /// Rejected by network
    Rejected { reason: String },
    /// Failed to process
    Failed { error: String },
}

/// A transaction in progress through the lifecycle
#[derive(Clone, Debug)]
pub struct PendingTransaction {
    /// Transaction ID (hash)
    pub tx_id: [u8; 32],
    /// The transaction
    pub transaction: Transaction,
    /// Current status
    pub status: TransactionStatus,
    /// Created timestamp
    pub created_at: u64,
    /// Last status update
    pub updated_at: u64,
    /// Attestations received
    pub attestations: Vec<TransactionAttestation>,
}

/// An attestation from a witness validator
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionAttestation {
    /// Validator public key
    pub validator_key: [u8; 32],
    /// Signature over transaction
    pub signature: Vec<u8>,
    /// Timestamp
    pub timestamp: u64,
}

/// Configuration for transaction lifecycle
#[derive(Clone, Debug)]
pub struct LifecycleConfig {
    /// Use Groth16 (faster single proof) vs Nova (batch-able)
    pub use_groth16: bool,
    /// Confirmation threshold (number of attestations)
    pub confirmation_threshold: usize,
    /// Timeout waiting for confirmation (seconds)
    pub confirmation_timeout: u64,
    /// Maximum fee to pay
    pub max_fee: u64,
    /// Retry failed submissions
    pub retry_count: u32,
    /// Auto-propagate after proving
    pub auto_propagate: bool,
}

impl Default for LifecycleConfig {
    fn default() -> Self {
        Self {
            use_groth16: true,
            confirmation_threshold: 3, // 3 witness attestations
            confirmation_timeout: 300, // 5 minutes
            max_fee: 100_000,
            retry_count: 3,
            auto_propagate: true,
        }
    }
}

/// Callbacks for lifecycle events
#[async_trait::async_trait]
pub trait LifecycleCallback: Send + Sync {
    /// Called when transaction is created
    async fn on_created(&self, tx_id: [u8; 32]);
    /// Called when transaction is signed
    async fn on_signed(&self, tx_id: [u8; 32]);
    /// Called when proof is generated
    async fn on_proved(&self, tx_id: [u8; 32]);
    /// Called when submitted to mempool
    async fn on_submitted(&self, tx_id: [u8; 32]);
    /// Called when propagated to network
    async fn on_propagated(&self, tx_id: [u8; 32]);
    /// Called when attestation received
    async fn on_attestation(&self, tx_id: [u8; 32], count: usize);
    /// Called when confirmed
    async fn on_confirmed(&self, tx_id: [u8; 32], attestation_count: usize);
    /// Called when rejected
    async fn on_rejected(&self, tx_id: [u8; 32], reason: &str);
    /// Called on failure
    async fn on_failed(&self, tx_id: [u8; 32], error: &str);
}

/// Default no-op callback
pub struct NoOpCallback;

#[async_trait::async_trait]
impl LifecycleCallback for NoOpCallback {
    async fn on_created(&self, _tx_id: [u8; 32]) {}
    async fn on_signed(&self, _tx_id: [u8; 32]) {}
    async fn on_proved(&self, _tx_id: [u8; 32]) {}
    async fn on_submitted(&self, _tx_id: [u8; 32]) {}
    async fn on_propagated(&self, _tx_id: [u8; 32]) {}
    async fn on_attestation(&self, _tx_id: [u8; 32], _count: usize) {}
    async fn on_confirmed(&self, _tx_id: [u8; 32], _attestation_count: usize) {}
    async fn on_rejected(&self, _tx_id: [u8; 32], _reason: &str) {}
    async fn on_failed(&self, _tx_id: [u8; 32], _error: &str) {}
}

/// Transaction propagation interface
#[async_trait::async_trait]
pub trait TransactionPropagator: Send + Sync {
    /// Submit transaction to mempool
    async fn submit_to_mempool(&self, tx: &Transaction) -> Result<(), String>;
    /// Propagate to P2P network
    async fn propagate(&self, tx: &Transaction) -> Result<(), String>;
}

/// State query interface
#[async_trait::async_trait]
pub trait StateProvider: Send + Sync {
    /// Get current merkle root
    async fn get_merkle_root(&self) -> [u8; 32];
    /// Get merkle proof for a commitment
    async fn get_merkle_proof(&self, commitment: &[u8; 32]) -> Option<(Vec<[u8; 32]>, Vec<bool>)>;
    /// Check if nullifier exists (spent)
    async fn nullifier_exists(&self, nullifier: &[u8; 32]) -> bool;
    /// Get current epoch
    async fn get_epoch(&self) -> u64;
}

/// Transaction lifecycle manager
pub struct TransactionLifecycle {
    /// Configuration
    config: LifecycleConfig,
    /// Note manager for tracking owned notes
    note_manager: Arc<RwLock<NoteManager>>,
    /// Pending transactions
    pending: Arc<RwLock<HashMap<[u8; 32], PendingTransaction>>>,
    /// Transaction builder
    builder: Arc<RwLock<TransactionBuilder>>,
    /// Transaction verifier
    verifier: Arc<RwLock<Option<TransactionVerifier>>>,
    /// Lifecycle callback
    callback: Arc<dyn LifecycleCallback>,
    /// Transaction propagator
    propagator: Option<Arc<dyn TransactionPropagator>>,
    /// State provider
    state_provider: Option<Arc<dyn StateProvider>>,
    /// View key for scanning incoming transactions
    view_key: Option<ViewKey>,
    /// Spend key for signing
    spend_key: Option<SpendKey>,
    /// Event sender for internal notifications
    event_tx: Option<mpsc::Sender<LifecycleEvent>>,
}

/// Internal lifecycle events
#[derive(Clone, Debug)]
pub enum LifecycleEvent {
    /// Transaction created
    Created { tx_id: [u8; 32] },
    /// Transaction signed
    Signed { tx_id: [u8; 32] },
    /// Proof generated
    Proved { tx_id: [u8; 32] },
    /// Submitted to mempool
    Submitted { tx_id: [u8; 32] },
    /// Propagated to network
    Propagated { tx_id: [u8; 32] },
    /// Attestation received
    Attestation { tx_id: [u8; 32], count: usize },
    /// Transaction confirmed
    Confirmed { tx_id: [u8; 32], attestation_count: usize },
    /// Transaction rejected
    Rejected { tx_id: [u8; 32], reason: String },
    /// Error occurred
    Error { tx_id: [u8; 32], error: String },
}

impl TransactionLifecycle {
    /// Create a new transaction lifecycle manager
    pub fn new(config: LifecycleConfig) -> Self {
        Self {
            config,
            note_manager: Arc::new(RwLock::new(NoteManager::new())),
            pending: Arc::new(RwLock::new(HashMap::new())),
            builder: Arc::new(RwLock::new(TransactionBuilder::new())),
            verifier: Arc::new(RwLock::new(None)),
            callback: Arc::new(NoOpCallback),
            propagator: None,
            state_provider: None,
            view_key: None,
            spend_key: None,
            event_tx: None,
        }
    }

    /// Set the lifecycle callback
    pub fn with_callback(mut self, callback: Arc<dyn LifecycleCallback>) -> Self {
        self.callback = callback;
        self
    }

    /// Set the transaction propagator
    pub fn with_propagator(mut self, propagator: Arc<dyn TransactionPropagator>) -> Self {
        self.propagator = Some(propagator);
        self
    }

    /// Set the state provider
    pub fn with_state_provider(mut self, provider: Arc<dyn StateProvider>) -> Self {
        self.state_provider = Some(provider);
        self
    }

    /// Set wallet keys
    pub fn with_keys(mut self, view_key: ViewKey, spend_key: SpendKey) -> Self {
        self.view_key = Some(view_key);
        self.spend_key = Some(spend_key);
        self
    }

    /// Initialize from HD wallet
    pub fn from_hd_wallet(mut self, wallet: &HDWallet) -> LifecycleResult<Self> {
        // Derive view and spend keys from the wallet's first address (change=0, index=0)
        self.view_key = Some(
            wallet.view_key_at(0, 0)
                .map_err(|e| LifecycleError::StateError(e.to_string()))?
        );
        self.spend_key = Some(
            wallet.spend_key_at(0, 0)
                .map_err(|e| LifecycleError::StateError(e.to_string()))?
        );
        Ok(self)
    }

    /// Get the note manager
    pub fn note_manager(&self) -> Arc<RwLock<NoteManager>> {
        self.note_manager.clone()
    }

    /// Get total balance
    pub async fn balance(&self) -> u64 {
        self.note_manager.read().await.balance()
    }

    /// Create a simple payment transaction
    pub async fn create_payment(
        &self,
        recipient: StealthAddress,
        amount: u64,
        change_address: StealthAddress,
    ) -> LifecycleResult<[u8; 32]> {
        // Check balance
        let balance = self.balance().await;
        if balance < amount {
            return Err(LifecycleError::InsufficientFunds {
                have: balance,
                need: amount,
            });
        }

        // Get merkle root from state
        let merkle_root = if let Some(ref provider) = self.state_provider {
            provider.get_merkle_root().await
        } else {
            [0u8; 32]
        };

        // Select notes
        let note_manager = self.note_manager.read().await;
        let selected_notes = note_manager
            .select_notes(amount + self.config.max_fee)
            .ok_or(LifecycleError::NoNotesAvailable)?;

        // Build transaction
        let mut builder = self.builder.write().await;
        builder.clear();
        builder.set_merkle_root(merkle_root);

        // Configure builder
        let tx_config = TransactionConfig {
            use_groth16: self.config.use_groth16,
            max_fee: self.config.max_fee,
            ..Default::default()
        };
        *builder = TransactionBuilder::with_config(tx_config);
        builder.set_merkle_root(merkle_root);

        // Add inputs
        for owned_note in selected_notes {
            builder.add_input(TransactionInput {
                note: owned_note.note.clone(),
                merkle_path: owned_note.merkle_path.clone(),
                merkle_indices: owned_note.merkle_indices.clone(),
                spending_key: owned_note.spending_key.clone(),
            });
        }

        // Add output
        builder.add_output(TransactionOutput {
            value: amount,
            recipient,
        });

        // Add change output
        builder.add_change_output(change_address)?;
        drop(note_manager);

        // Build transaction (includes proof generation)
        let tx = builder.build()?;
        let tx_id = tx.hash();

        // Create pending transaction
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let pending_tx = PendingTransaction {
            tx_id,
            transaction: tx,
            status: TransactionStatus::Proved, // Build includes proof
            created_at: now,
            updated_at: now,
            attestations: Vec::new(),
        };

        // Store pending transaction
        self.pending.write().await.insert(tx_id, pending_tx);

        // Notify callback
        self.callback.on_created(tx_id).await;
        self.callback.on_signed(tx_id).await;
        self.callback.on_proved(tx_id).await;

        // Auto-propagate if configured
        if self.config.auto_propagate {
            self.propagate(&tx_id).await?;
        }

        Ok(tx_id)
    }

    /// Create a multi-output transaction
    pub async fn create_multi_payment(
        &self,
        recipients: Vec<(StealthAddress, u64)>,
        change_address: StealthAddress,
    ) -> LifecycleResult<[u8; 32]> {
        let total_amount: u64 = recipients.iter().map(|(_, v)| v).sum();

        // Check balance
        let balance = self.balance().await;
        if balance < total_amount {
            return Err(LifecycleError::InsufficientFunds {
                have: balance,
                need: total_amount,
            });
        }

        // Get merkle root
        let merkle_root = if let Some(ref provider) = self.state_provider {
            provider.get_merkle_root().await
        } else {
            [0u8; 32]
        };

        // Select notes
        let note_manager = self.note_manager.read().await;
        let selected_notes = note_manager
            .select_notes(total_amount + self.config.max_fee)
            .ok_or(LifecycleError::NoNotesAvailable)?;

        // Build transaction
        let mut builder = self.builder.write().await;
        builder.clear();
        builder.set_merkle_root(merkle_root);

        let tx_config = TransactionConfig {
            use_groth16: self.config.use_groth16,
            max_fee: self.config.max_fee,
            ..Default::default()
        };
        *builder = TransactionBuilder::with_config(tx_config);
        builder.set_merkle_root(merkle_root);

        // Add inputs
        for owned_note in selected_notes {
            builder.add_input(TransactionInput {
                note: owned_note.note.clone(),
                merkle_path: owned_note.merkle_path.clone(),
                merkle_indices: owned_note.merkle_indices.clone(),
                spending_key: owned_note.spending_key.clone(),
            });
        }

        // Add outputs
        for (recipient, amount) in recipients {
            builder.add_output(TransactionOutput {
                value: amount,
                recipient,
            });
        }

        // Add change output
        builder.add_change_output(change_address)?;
        drop(note_manager);

        // Build
        let tx = builder.build()?;
        let tx_id = tx.hash();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let pending_tx = PendingTransaction {
            tx_id,
            transaction: tx,
            status: TransactionStatus::Proved,
            created_at: now,
            updated_at: now,
            attestations: Vec::new(),
        };

        self.pending.write().await.insert(tx_id, pending_tx);

        self.callback.on_created(tx_id).await;
        self.callback.on_signed(tx_id).await;
        self.callback.on_proved(tx_id).await;

        if self.config.auto_propagate {
            self.propagate(&tx_id).await?;
        }

        Ok(tx_id)
    }

    /// Propagate a pending transaction to the network
    pub async fn propagate(&self, tx_id: &[u8; 32]) -> LifecycleResult<()> {
        let propagator = self.propagator.as_ref()
            .ok_or_else(|| LifecycleError::PropagationFailed("No propagator configured".into()))?;

        let mut pending = self.pending.write().await;
        let pending_tx = pending.get_mut(tx_id)
            .ok_or_else(|| LifecycleError::PropagationFailed("Transaction not found".into()))?;

        // Submit to mempool
        propagator.submit_to_mempool(&pending_tx.transaction).await
            .map_err(|e| LifecycleError::PropagationFailed(e))?;

        pending_tx.status = TransactionStatus::Submitted;
        pending_tx.updated_at = now();
        self.callback.on_submitted(*tx_id).await;

        // Propagate to P2P network
        propagator.propagate(&pending_tx.transaction).await
            .map_err(|e| LifecycleError::PropagationFailed(e))?;

        pending_tx.status = TransactionStatus::Propagated;
        pending_tx.updated_at = now();
        self.callback.on_propagated(*tx_id).await;

        pending_tx.status = TransactionStatus::Pending;

        Ok(())
    }

    /// Handle an incoming attestation
    pub async fn handle_attestation(
        &self,
        tx_id: &[u8; 32],
        attestation: TransactionAttestation,
    ) -> LifecycleResult<bool> {
        let mut pending = self.pending.write().await;
        let pending_tx = pending.get_mut(tx_id)
            .ok_or_else(|| LifecycleError::StateError("Transaction not found".into()))?;

        // Verify attestation signature (simplified - would verify against known validators)
        if attestation.signature.is_empty() {
            return Err(LifecycleError::StateError("Invalid attestation".into()));
        }

        // Add attestation
        pending_tx.attestations.push(attestation);
        pending_tx.updated_at = now();

        let count = pending_tx.attestations.len();
        self.callback.on_attestation(*tx_id, count).await;

        // Check if threshold reached
        if count >= self.config.confirmation_threshold {
            pending_tx.status = TransactionStatus::Confirmed {
                attestation_count: count,
            };
            self.callback.on_confirmed(*tx_id, count).await;

            // Mark notes as spent
            let nullifiers: Vec<[u8; 32]> = pending_tx.transaction.nullifiers.clone();
            drop(pending);

            self.note_manager.write().await.mark_spent(&nullifiers);

            return Ok(true);
        }

        Ok(false)
    }

    /// Handle transaction rejection
    pub async fn handle_rejection(&self, tx_id: &[u8; 32], reason: String) -> LifecycleResult<()> {
        let mut pending = self.pending.write().await;
        if let Some(pending_tx) = pending.get_mut(tx_id) {
            pending_tx.status = TransactionStatus::Rejected { reason: reason.clone() };
            pending_tx.updated_at = now();
        }

        self.callback.on_rejected(*tx_id, &reason).await;
        Ok(())
    }

    /// Get status of a pending transaction
    pub async fn get_status(&self, tx_id: &[u8; 32]) -> Option<TransactionStatus> {
        self.pending.read().await.get(tx_id).map(|p| p.status.clone())
    }

    /// Get a pending transaction
    pub async fn get_pending(&self, tx_id: &[u8; 32]) -> Option<PendingTransaction> {
        self.pending.read().await.get(tx_id).cloned()
    }

    /// Get all pending transactions
    pub async fn get_all_pending(&self) -> Vec<PendingTransaction> {
        self.pending.read().await.values().cloned().collect()
    }

    /// Clean up confirmed transactions
    pub async fn cleanup_confirmed(&self) -> Vec<[u8; 32]> {
        let mut pending = self.pending.write().await;
        let confirmed: Vec<[u8; 32]> = pending
            .iter()
            .filter(|(_, p)| matches!(p.status, TransactionStatus::Confirmed { .. }))
            .map(|(id, _)| *id)
            .collect();

        for id in &confirmed {
            pending.remove(id);
        }

        confirmed
    }

    /// Verify a transaction
    pub async fn verify(&self, tx: &Transaction, merkle_root: &[u8; 32]) -> LifecycleResult<bool> {
        let mut verifier_guard = self.verifier.write().await;
        if verifier_guard.is_none() {
            *verifier_guard = Some(TransactionVerifier::new()?);
        }
        let verifier = verifier_guard.as_ref().unwrap();

        verifier.verify(tx, merkle_root).map_err(|e| e.into())
    }

    /// Scan incoming transactions for notes belonging to this wallet
    pub async fn scan_transaction(
        &self,
        tx: &Transaction,
        merkle_paths: &[Vec<[u8; 32]>],
        merkle_indices: &[Vec<bool>],
        block_height: u64,
    ) -> Vec<OwnedNote> {
        let (view_key, spend_key) = match (&self.view_key, &self.spend_key) {
            (Some(v), Some(s)) => (v, s),
            _ => return Vec::new(),
        };

        let mut note_manager = self.note_manager.write().await;
        note_manager.scan_for_notes(
            view_key,
            spend_key,
            &tx.output_addresses,
            &tx.encrypted_amounts,
            merkle_paths,
            merkle_indices,
            block_height,
        )
    }

    /// Add a manually discovered note
    pub async fn add_note(&self, note: OwnedNote) {
        self.note_manager.write().await.add_note(note);
    }

    /// Get transaction history (from pending transactions)
    pub async fn get_transaction_history(&self) -> Vec<TransactionSummary> {
        self.pending.read().await
            .values()
            .map(|p| TransactionSummary {
                tx_id: p.tx_id,
                status: p.status.clone(),
                fee: p.transaction.fee,
                input_count: p.transaction.nullifiers.len(),
                output_count: p.transaction.output_commitments.len(),
                created_at: p.created_at,
                updated_at: p.updated_at,
            })
            .collect()
    }

    /// Estimate fee for a transaction
    pub async fn estimate_fee(&self, recipient_count: usize, input_count: usize) -> u64 {
        let base_size = 200;
        let input_size = input_count * 64;
        let output_size = (recipient_count + 1) * 300; // +1 for change
        let proof_size = if self.config.use_groth16 { 200 } else { 500 };

        let estimated_size = base_size + input_size + output_size + proof_size;
        (estimated_size as u64).min(self.config.max_fee)
    }
}

/// Summary of a transaction
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionSummary {
    /// Transaction ID
    pub tx_id: [u8; 32],
    /// Current status
    pub status: TransactionStatus,
    /// Fee paid
    pub fee: u64,
    /// Number of inputs
    pub input_count: usize,
    /// Number of outputs
    pub output_count: usize,
    /// Created timestamp
    pub created_at: u64,
    /// Last update timestamp
    pub updated_at: u64,
}

/// Helper to get current timestamp
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Simple in-memory propagator for testing
pub struct InMemoryPropagator {
    mempool: Arc<RwLock<Vec<Transaction>>>,
    network: Arc<RwLock<Vec<Transaction>>>,
}

impl InMemoryPropagator {
    pub fn new() -> Self {
        Self {
            mempool: Arc::new(RwLock::new(Vec::new())),
            network: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn mempool_size(&self) -> usize {
        self.mempool.read().await.len()
    }

    pub async fn network_size(&self) -> usize {
        self.network.read().await.len()
    }
}

impl Default for InMemoryPropagator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl TransactionPropagator for InMemoryPropagator {
    async fn submit_to_mempool(&self, tx: &Transaction) -> Result<(), String> {
        self.mempool.write().await.push(tx.clone());
        Ok(())
    }

    async fn propagate(&self, tx: &Transaction) -> Result<(), String> {
        self.network.write().await.push(tx.clone());
        Ok(())
    }
}

/// Simple in-memory state provider for testing
pub struct InMemoryStateProvider {
    merkle_root: Arc<RwLock<[u8; 32]>>,
    epoch: Arc<RwLock<u64>>,
    nullifiers: Arc<RwLock<std::collections::HashSet<[u8; 32]>>>,
}

impl InMemoryStateProvider {
    pub fn new() -> Self {
        Self {
            merkle_root: Arc::new(RwLock::new([0u8; 32])),
            epoch: Arc::new(RwLock::new(0)),
            nullifiers: Arc::new(RwLock::new(std::collections::HashSet::new())),
        }
    }

    pub async fn set_merkle_root(&self, root: [u8; 32]) {
        *self.merkle_root.write().await = root;
    }

    pub async fn advance_epoch(&self) {
        *self.epoch.write().await += 1;
    }

    pub async fn add_nullifier(&self, nullifier: [u8; 32]) {
        self.nullifiers.write().await.insert(nullifier);
    }
}

impl Default for InMemoryStateProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl StateProvider for InMemoryStateProvider {
    async fn get_merkle_root(&self) -> [u8; 32] {
        *self.merkle_root.read().await
    }

    async fn get_merkle_proof(&self, _commitment: &[u8; 32]) -> Option<(Vec<[u8; 32]>, Vec<bool>)> {
        // Mock merkle proof
        let path: Vec<[u8; 32]> = (0..32).map(|i| [i as u8; 32]).collect();
        let indices: Vec<bool> = (0..32).map(|i| i % 2 == 0).collect();
        Some((path, indices))
    }

    async fn nullifier_exists(&self, nullifier: &[u8; 32]) -> bool {
        self.nullifiers.read().await.contains(nullifier)
    }

    async fn get_epoch(&self) -> u64 {
        *self.epoch.read().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_lifecycle_creation() {
        let config = LifecycleConfig::default();
        let lifecycle = TransactionLifecycle::new(config);

        assert_eq!(lifecycle.balance().await, 0);
    }

    #[tokio::test]
    async fn test_in_memory_propagator() {
        let propagator = InMemoryPropagator::new();

        assert_eq!(propagator.mempool_size().await, 0);
        assert_eq!(propagator.network_size().await, 0);
    }

    #[tokio::test]
    async fn test_in_memory_state_provider() {
        let provider = InMemoryStateProvider::new();

        let root = provider.get_merkle_root().await;
        assert_eq!(root, [0u8; 32]);

        let epoch = provider.get_epoch().await;
        assert_eq!(epoch, 0);

        provider.advance_epoch().await;
        assert_eq!(provider.get_epoch().await, 1);
    }

    #[tokio::test]
    async fn test_fee_estimation() {
        let lifecycle = TransactionLifecycle::new(LifecycleConfig::default());

        let fee1 = lifecycle.estimate_fee(1, 1).await;
        let fee2 = lifecycle.estimate_fee(2, 2).await;

        assert!(fee1 > 0);
        assert!(fee2 > fee1);
    }

    #[tokio::test]
    async fn test_insufficient_funds() {
        let lifecycle = TransactionLifecycle::new(LifecycleConfig::default());

        let view_key = ViewKey::generate().unwrap();
        let spend_key = SpendKey::generate().unwrap();
        let recipient = StealthAddress::new(&view_key, &spend_key);

        let result = lifecycle.create_payment(recipient.clone(), 1000, recipient).await;

        assert!(matches!(result, Err(LifecycleError::InsufficientFunds { .. })));
    }

    #[test]
    fn test_transaction_status_serialization() {
        let status = TransactionStatus::Confirmed { attestation_count: 3 };
        let json = serde_json::to_string(&status).unwrap();
        let restored: TransactionStatus = serde_json::from_str(&json).unwrap();

        assert_eq!(status, restored);
    }
}
