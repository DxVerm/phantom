//! Transaction processor for state transitions
//!
//! Handles transaction validation, execution, and state updates.
//! Supports encrypted transactions with nullifier tracking.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};
use tokio::sync::RwLock;
use tracing::{debug, info, warn, error};

use phantom_esl::ESLState;
use phantom_storage::{Storage, StoredTransaction, TransactionType};

use crate::error::{NodeError, NodeResult};

/// Transaction processor configuration
#[derive(Debug, Clone)]
pub struct TxProcessorConfig {
    /// Maximum transactions per block
    pub max_txs_per_block: usize,
    /// Maximum gas per block
    pub max_gas_per_block: u64,
    /// Base gas cost per transaction
    pub base_gas_cost: u64,
    /// Gas cost per byte
    pub gas_per_byte: u64,
    /// Minimum gas price
    pub min_gas_price: u64,
    /// Transaction timeout
    pub tx_timeout: Duration,
    /// Enable parallel execution
    pub parallel_execution: bool,
    /// Maximum parallel threads
    pub max_parallel_threads: usize,
}

impl Default for TxProcessorConfig {
    fn default() -> Self {
        Self {
            max_txs_per_block: 1000,
            max_gas_per_block: 30_000_000,
            base_gas_cost: 21_000,
            gas_per_byte: 16,
            min_gas_price: 1,
            tx_timeout: Duration::from_secs(30),
            parallel_execution: true,
            max_parallel_threads: 4,
        }
    }
}

/// Transaction execution result
#[derive(Debug, Clone)]
pub struct TxExecution {
    /// Transaction hash
    pub tx_hash: [u8; 32],
    /// Whether execution succeeded
    pub success: bool,
    /// Gas used
    pub gas_used: u64,
    /// Execution logs
    pub logs: Vec<TxLog>,
    /// State changes (nullifiers consumed)
    pub nullifiers_consumed: Vec<[u8; 32]>,
    /// New commitments created
    pub commitments_created: Vec<[u8; 32]>,
    /// Error message if failed
    pub error: Option<String>,
}

/// Transaction receipt with execution details
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxReceipt {
    /// Transaction hash
    pub tx_hash: [u8; 32],
    /// Block height
    pub block_height: u64,
    /// Transaction index in block
    pub tx_index: u32,
    /// Execution success
    pub success: bool,
    /// Gas used
    pub gas_used: u64,
    /// Cumulative gas used in block
    pub cumulative_gas: u64,
    /// Logs emitted
    pub logs: Vec<TxLog>,
    /// State root after transaction
    pub post_state_root: [u8; 32],
    /// Bloom filter for log topics
    #[serde_as(as = "Bytes")]
    pub logs_bloom: [u8; 256],
}

/// Transaction log entry for receipts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxLog {
    /// Contract address
    pub contract: [u8; 32],
    /// Event topics
    pub topics: Vec<[u8; 32]>,
    /// Event data
    pub data: Vec<u8>,
}

impl TxReceipt {
    /// Create receipt from execution result
    pub fn from_execution(
        exec: &TxExecution,
        block_height: u64,
        tx_index: u32,
        cumulative_gas: u64,
        post_state_root: [u8; 32],
    ) -> Self {
        Self {
            tx_hash: exec.tx_hash,
            block_height,
            tx_index,
            success: exec.success,
            gas_used: exec.gas_used,
            cumulative_gas,
            logs: exec.logs.clone(),
            post_state_root,
            logs_bloom: Self::compute_bloom(&exec.logs),
        }
    }

    /// Compute bloom filter for logs
    fn compute_bloom(logs: &[TxLog]) -> [u8; 256] {
        let mut bloom = [0u8; 256];
        for log in logs {
            // Add contract address to bloom
            Self::add_to_bloom(&mut bloom, &log.contract);
            // Add topics to bloom
            for topic in &log.topics {
                Self::add_to_bloom(&mut bloom, topic);
            }
        }
        bloom
    }

    /// Add data to bloom filter
    fn add_to_bloom(bloom: &mut [u8; 256], data: &[u8; 32]) {
        let hash = blake3::hash(data);
        let hash_bytes = hash.as_bytes();

        // Use 3 positions in the bloom filter
        for i in 0..3 {
            let idx = ((hash_bytes[2 * i] as usize) << 8 | hash_bytes[2 * i + 1] as usize) % 2048;
            let byte_idx = idx / 8;
            let bit_idx = idx % 8;
            bloom[byte_idx] |= 1 << bit_idx;
        }
    }
}

/// Nullifier set for double-spend prevention
pub struct NullifierSet {
    /// Known nullifiers (spent notes)
    nullifiers: HashSet<[u8; 32]>,
    /// Pending nullifiers (in current block)
    pending: HashSet<[u8; 32]>,
}

impl NullifierSet {
    /// Create new nullifier set
    pub fn new() -> Self {
        Self {
            nullifiers: HashSet::new(),
            pending: HashSet::new(),
        }
    }

    /// Load nullifiers from storage
    pub fn load_from_storage(storage: &Storage) -> NodeResult<Self> {
        let mut set = Self::new();

        // Load all known nullifiers from storage
        if let Ok(Some(nullifier_data)) = storage.state.get_nullifier_set() {
            for nullifier in nullifier_data {
                set.nullifiers.insert(nullifier);
            }
        }

        Ok(set)
    }

    /// Check if nullifier exists (spent)
    pub fn contains(&self, nullifier: &[u8; 32]) -> bool {
        self.nullifiers.contains(nullifier) || self.pending.contains(nullifier)
    }

    /// Add nullifier to pending set
    pub fn add_pending(&mut self, nullifier: [u8; 32]) -> bool {
        if self.contains(&nullifier) {
            return false;
        }
        self.pending.insert(nullifier)
    }

    /// Commit pending nullifiers
    pub fn commit(&mut self) {
        for nullifier in self.pending.drain() {
            self.nullifiers.insert(nullifier);
        }
    }

    /// Rollback pending nullifiers
    pub fn rollback(&mut self) {
        self.pending.clear();
    }

    /// Get all nullifiers
    pub fn all(&self) -> Vec<[u8; 32]> {
        self.nullifiers.iter().copied().collect()
    }

    /// Get count
    pub fn len(&self) -> usize {
        self.nullifiers.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.nullifiers.is_empty()
    }
}

impl Default for NullifierSet {
    fn default() -> Self {
        Self::new()
    }
}

/// Transaction processor handles execution and state transitions
pub struct TransactionProcessor {
    config: TxProcessorConfig,
    nullifiers: RwLock<NullifierSet>,
    /// Execution statistics
    stats: RwLock<ProcessorStats>,
}

/// Processing statistics
#[derive(Debug, Default, Clone)]
pub struct ProcessorStats {
    /// Total transactions processed
    pub total_processed: u64,
    /// Successful transactions
    pub successful: u64,
    /// Failed transactions
    pub failed: u64,
    /// Total gas used
    pub total_gas: u64,
    /// Average gas per transaction
    pub avg_gas: u64,
    /// Processing time total (ms)
    pub total_time_ms: u64,
}

impl TransactionProcessor {
    /// Create new transaction processor
    pub fn new(config: TxProcessorConfig) -> Self {
        Self {
            config,
            nullifiers: RwLock::new(NullifierSet::new()),
            stats: RwLock::new(ProcessorStats::default()),
        }
    }

    /// Initialize processor with storage
    pub async fn init_from_storage(&self, storage: &Storage) -> NodeResult<()> {
        let nullifier_set = NullifierSet::load_from_storage(storage)?;
        let mut nullifiers = self.nullifiers.write().await;
        *nullifiers = nullifier_set;
        info!("Loaded {} nullifiers from storage", nullifiers.len());
        Ok(())
    }

    /// Validate transaction before execution
    pub async fn validate_tx(&self, tx: &StoredTransaction) -> NodeResult<()> {
        // Check transaction structure
        if tx.hash == [0u8; 32] {
            return Err(NodeError::InvalidTransaction("Empty transaction hash".into()));
        }

        // Check fee
        if tx.fee < self.config.min_gas_price * self.config.base_gas_cost {
            return Err(NodeError::InvalidTransaction(
                format!("Fee {} below minimum {}", tx.fee, self.config.min_gas_price * self.config.base_gas_cost)
            ));
        }

        // Check proof is present
        if tx.proof.is_empty() {
            return Err(NodeError::InvalidTransaction("Missing ZK proof".into()));
        }

        // Check signature is present
        if tx.signature.is_empty() {
            return Err(NodeError::InvalidTransaction("Missing signature".into()));
        }

        Ok(())
    }

    /// Calculate gas cost for transaction
    pub fn calculate_gas(&self, tx: &StoredTransaction) -> u64 {
        let base = self.config.base_gas_cost;
        let data_cost = (tx.proof.len() + tx.signature.len() + tx.encrypted_amount.len()) as u64
            * self.config.gas_per_byte;

        // Type-specific costs
        let type_cost = match tx.tx_type {
            TransactionType::Transfer => 0,
            TransactionType::Deploy => 50_000,
            TransactionType::Call => 10_000,
            TransactionType::Stake => 20_000,
            TransactionType::Unstake => 20_000,
            TransactionType::RegisterValidator => 100_000,
        };

        base + data_cost + type_cost
    }

    /// Execute a single transaction
    pub async fn execute_tx(
        &self,
        tx: &StoredTransaction,
        state: &mut ESLState,
    ) -> NodeResult<TxExecution> {
        let start = Instant::now();
        let gas_limit = self.calculate_gas(tx);

        // Validate transaction
        self.validate_tx(tx).await?;

        // Check for double-spend via nullifiers
        // In a real implementation, we'd extract nullifiers from the ZK proof
        let nullifier = Self::extract_nullifier(tx);

        {
            let mut nullifiers = self.nullifiers.write().await;
            if nullifiers.contains(&nullifier) {
                return Ok(TxExecution {
                    tx_hash: tx.hash,
                    success: false,
                    gas_used: gas_limit,
                    logs: vec![],
                    nullifiers_consumed: vec![],
                    commitments_created: vec![],
                    error: Some("Double spend detected: nullifier already consumed".into()),
                });
            }
            nullifiers.add_pending(nullifier);
        }

        // Verify ZK proof
        let proof_valid = self.verify_proof(tx).await?;
        if !proof_valid {
            self.nullifiers.write().await.rollback();
            return Ok(TxExecution {
                tx_hash: tx.hash,
                success: false,
                gas_used: gas_limit,
                logs: vec![],
                nullifiers_consumed: vec![],
                commitments_created: vec![],
                error: Some("ZK proof verification failed".into()),
            });
        }

        // Execute based on transaction type
        let result = match tx.tx_type {
            TransactionType::Transfer => {
                self.execute_transfer(tx, state).await
            }
            TransactionType::Deploy => {
                self.execute_deploy(tx, state).await
            }
            TransactionType::Call => {
                self.execute_call(tx, state).await
            }
            TransactionType::Stake => {
                self.execute_stake(tx, state).await
            }
            TransactionType::Unstake => {
                self.execute_unstake(tx, state).await
            }
            TransactionType::RegisterValidator => {
                self.execute_register_validator(tx, state).await
            }
        };

        // Commit or rollback nullifiers
        {
            let mut nullifiers = self.nullifiers.write().await;
            if result.success {
                nullifiers.commit();
            } else {
                nullifiers.rollback();
            }
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_processed += 1;
            if result.success {
                stats.successful += 1;
            } else {
                stats.failed += 1;
            }
            stats.total_gas += result.gas_used;
            stats.total_time_ms += start.elapsed().as_millis() as u64;
            if stats.total_processed > 0 {
                stats.avg_gas = stats.total_gas / stats.total_processed;
            }
        }

        Ok(result)
    }

    /// Execute a batch of transactions
    pub async fn execute_batch(
        &self,
        transactions: &[StoredTransaction],
        state: &mut ESLState,
        block_height: u64,
    ) -> NodeResult<Vec<TxReceipt>> {
        let mut receipts = Vec::with_capacity(transactions.len());
        let mut cumulative_gas = 0u64;
        let mut tx_index = 0u32;

        for tx in transactions {
            // Check block gas limit
            let estimated_gas = self.calculate_gas(tx);
            if cumulative_gas + estimated_gas > self.config.max_gas_per_block {
                warn!(
                    "Block gas limit reached at tx {} (cumulative: {}, limit: {})",
                    tx_index, cumulative_gas, self.config.max_gas_per_block
                );
                break;
            }

            // Execute transaction
            let result = self.execute_tx(tx, state).await?;
            cumulative_gas += result.gas_used;

            // Get post-state root
            let post_state_root = *state.commitment_root();

            // Create receipt
            let receipt = TxReceipt::from_execution(
                &result,
                block_height,
                tx_index,
                cumulative_gas,
                post_state_root,
            );

            receipts.push(receipt);
            tx_index += 1;

            debug!(
                "Executed tx {} at index {} (success: {}, gas: {})",
                hex::encode(&tx.hash[..4]),
                tx_index - 1,
                result.success,
                result.gas_used
            );
        }

        info!(
            "Executed {} transactions, total gas: {}",
            receipts.len(),
            cumulative_gas
        );

        Ok(receipts)
    }

    /// Execute transfer transaction
    async fn execute_transfer(
        &self,
        tx: &StoredTransaction,
        state: &mut ESLState,
    ) -> TxExecution {
        // For encrypted transfers, we update commitments in the ESL
        // The actual balance updates are verified by ZK proof

        let gas_used = self.calculate_gas(tx);
        let commitment = Self::compute_output_commitment(tx);

        // In production, this would properly update the commitment tree
        // For now, we simulate success

        TxExecution {
            tx_hash: tx.hash,
            success: true,
            gas_used,
            logs: vec![
                TxLog {
                    contract: [0u8; 32], // Native transfer
                    topics: vec![
                        Self::transfer_topic(),
                        Self::extract_nullifier(tx), // From (nullifier)
                        commitment, // To (commitment)
                    ],
                    data: vec![], // Amount is encrypted
                }
            ],
            nullifiers_consumed: vec![Self::extract_nullifier(tx)],
            commitments_created: vec![commitment],
            error: None,
        }
    }

    /// Execute contract deployment
    async fn execute_deploy(
        &self,
        tx: &StoredTransaction,
        state: &mut ESLState,
    ) -> TxExecution {
        let gas_used = self.calculate_gas(tx);

        // Compute contract address
        let contract_address = Self::compute_contract_address(tx);

        TxExecution {
            tx_hash: tx.hash,
            success: true,
            gas_used,
            logs: vec![
                TxLog {
                    contract: contract_address,
                    topics: vec![Self::deploy_topic()],
                    data: tx.proof.clone(), // Contract code hash
                }
            ],
            nullifiers_consumed: vec![Self::extract_nullifier(tx)],
            commitments_created: vec![contract_address],
            error: None,
        }
    }

    /// Execute contract call
    async fn execute_call(
        &self,
        tx: &StoredTransaction,
        state: &mut ESLState,
    ) -> TxExecution {
        let gas_used = self.calculate_gas(tx);

        // Extract contract address from recipient
        let mut contract = [0u8; 32];
        if tx.encrypted_receiver.len() >= 32 {
            contract.copy_from_slice(&tx.encrypted_receiver[..32]);
        }

        TxExecution {
            tx_hash: tx.hash,
            success: true,
            gas_used,
            logs: vec![
                TxLog {
                    contract,
                    topics: vec![Self::call_topic()],
                    data: vec![],
                }
            ],
            nullifiers_consumed: vec![Self::extract_nullifier(tx)],
            commitments_created: vec![],
            error: None,
        }
    }

    /// Execute stake transaction
    async fn execute_stake(
        &self,
        tx: &StoredTransaction,
        state: &mut ESLState,
    ) -> TxExecution {
        let gas_used = self.calculate_gas(tx);

        TxExecution {
            tx_hash: tx.hash,
            success: true,
            gas_used,
            logs: vec![
                TxLog {
                    contract: Self::staking_contract(),
                    topics: vec![
                        Self::stake_topic(),
                        Self::extract_nullifier(tx),
                    ],
                    data: vec![],
                }
            ],
            nullifiers_consumed: vec![Self::extract_nullifier(tx)],
            commitments_created: vec![],
            error: None,
        }
    }

    /// Execute unstake transaction
    async fn execute_unstake(
        &self,
        tx: &StoredTransaction,
        state: &mut ESLState,
    ) -> TxExecution {
        let gas_used = self.calculate_gas(tx);
        let commitment = Self::compute_output_commitment(tx);

        TxExecution {
            tx_hash: tx.hash,
            success: true,
            gas_used,
            logs: vec![
                TxLog {
                    contract: Self::staking_contract(),
                    topics: vec![
                        Self::unstake_topic(),
                        commitment,
                    ],
                    data: vec![],
                }
            ],
            nullifiers_consumed: vec![],
            commitments_created: vec![commitment],
            error: None,
        }
    }

    /// Execute validator registration
    async fn execute_register_validator(
        &self,
        tx: &StoredTransaction,
        state: &mut ESLState,
    ) -> TxExecution {
        let gas_used = self.calculate_gas(tx);

        // Extract validator ID from sender
        let mut validator_id = [0u8; 32];
        if tx.encrypted_sender.len() >= 32 {
            validator_id.copy_from_slice(&tx.encrypted_sender[..32]);
        }

        TxExecution {
            tx_hash: tx.hash,
            success: true,
            gas_used,
            logs: vec![
                TxLog {
                    contract: Self::validator_contract(),
                    topics: vec![
                        Self::register_validator_topic(),
                        validator_id,
                    ],
                    data: tx.proof.clone(), // Contains validator info
                }
            ],
            nullifiers_consumed: vec![Self::extract_nullifier(tx)],
            commitments_created: vec![],
            error: None,
        }
    }

    /// Verify ZK proof
    async fn verify_proof(&self, tx: &StoredTransaction) -> NodeResult<bool> {
        // In production, this would verify the Nova/Groth16 proof
        // For now, check that proof data is present and properly structured
        if tx.proof.is_empty() {
            return Ok(false);
        }

        // Minimum proof size check (Groth16 is ~192 bytes, Nova is larger)
        if tx.proof.len() < 128 {
            return Ok(false);
        }

        // Verify proof structure
        // In production: phantom_nova::groth16_verify or nova_verify
        Ok(true)
    }

    /// Extract nullifier from transaction
    fn extract_nullifier(tx: &StoredTransaction) -> [u8; 32] {
        // Compute nullifier from transaction hash and sender
        let mut hasher = blake3::Hasher::new();
        hasher.update(&tx.hash);
        hasher.update(&tx.encrypted_sender);
        hasher.update(b"nullifier");
        *hasher.finalize().as_bytes()
    }

    /// Compute output commitment
    fn compute_output_commitment(tx: &StoredTransaction) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&tx.hash);
        hasher.update(&tx.encrypted_receiver);
        hasher.update(&tx.encrypted_amount);
        hasher.update(b"commitment");
        *hasher.finalize().as_bytes()
    }

    /// Compute contract address from deployment
    fn compute_contract_address(tx: &StoredTransaction) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&tx.encrypted_sender);
        hasher.update(&tx.nonce.to_le_bytes());
        hasher.update(b"contract");
        *hasher.finalize().as_bytes()
    }

    /// Transfer event topic
    fn transfer_topic() -> [u8; 32] {
        blake3::hash(b"Transfer(bytes32,bytes32,bytes)").into()
    }

    /// Deploy event topic
    fn deploy_topic() -> [u8; 32] {
        blake3::hash(b"Deploy(bytes32)").into()
    }

    /// Call event topic
    fn call_topic() -> [u8; 32] {
        blake3::hash(b"Call(bytes32,bytes)").into()
    }

    /// Stake event topic
    fn stake_topic() -> [u8; 32] {
        blake3::hash(b"Stake(bytes32,uint256)").into()
    }

    /// Unstake event topic
    fn unstake_topic() -> [u8; 32] {
        blake3::hash(b"Unstake(bytes32,uint256)").into()
    }

    /// Register validator event topic
    fn register_validator_topic() -> [u8; 32] {
        blake3::hash(b"RegisterValidator(bytes32,bytes)").into()
    }

    /// Staking contract address
    fn staking_contract() -> [u8; 32] {
        let mut addr = [0u8; 32];
        addr[31] = 0x01; // Precompile address 0x01
        addr
    }

    /// Validator contract address
    fn validator_contract() -> [u8; 32] {
        let mut addr = [0u8; 32];
        addr[31] = 0x02; // Precompile address 0x02
        addr
    }

    /// Get processing statistics
    pub async fn stats(&self) -> ProcessorStats {
        self.stats.read().await.clone()
    }

    /// Get nullifier count
    pub async fn nullifier_count(&self) -> usize {
        self.nullifiers.read().await.len()
    }

    /// Check if nullifier exists
    pub async fn nullifier_exists(&self, nullifier: &[u8; 32]) -> bool {
        self.nullifiers.read().await.contains(nullifier)
    }

    /// Reset statistics
    pub async fn reset_stats(&self) {
        *self.stats.write().await = ProcessorStats::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_tx(nonce: u64, tx_type: TransactionType) -> StoredTransaction {
        let mut hash = [0u8; 32];
        hash[0..8].copy_from_slice(&nonce.to_le_bytes());

        StoredTransaction {
            hash,
            sender: vec![1u8; 32],
            recipient: vec![2u8; 32],
            amount_encrypted: vec![3u8; 64],
            fee: 100_000,
            nonce,
            timestamp: 1000000 + nonce,
            proof: vec![4u8; 256], // Large enough proof
            signature: vec![5u8; 64],
            tx_type,
        }
    }

    #[tokio::test]
    async fn test_tx_processor_creation() {
        let config = TxProcessorConfig::default();
        let processor = TransactionProcessor::new(config);

        assert_eq!(processor.nullifier_count().await, 0);
    }

    #[tokio::test]
    async fn test_tx_validation() {
        let config = TxProcessorConfig::default();
        let processor = TransactionProcessor::new(config);

        let tx = create_test_tx(1, TransactionType::Transfer);
        let result = processor.validate_tx(&tx).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_tx_validation_empty_hash() {
        let config = TxProcessorConfig::default();
        let processor = TransactionProcessor::new(config);

        let mut tx = create_test_tx(1, TransactionType::Transfer);
        tx.hash = [0u8; 32];

        let result = processor.validate_tx(&tx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tx_validation_low_fee() {
        let config = TxProcessorConfig::default();
        let processor = TransactionProcessor::new(config);

        let mut tx = create_test_tx(1, TransactionType::Transfer);
        tx.fee = 1; // Too low

        let result = processor.validate_tx(&tx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_gas_calculation() {
        let config = TxProcessorConfig::default();
        let processor = TransactionProcessor::new(config.clone());

        let transfer = create_test_tx(1, TransactionType::Transfer);
        let deploy = create_test_tx(2, TransactionType::Deploy);

        let transfer_gas = processor.calculate_gas(&transfer);
        let deploy_gas = processor.calculate_gas(&deploy);

        // Deploy should cost more
        assert!(deploy_gas > transfer_gas);

        // Should include base cost
        assert!(transfer_gas >= config.base_gas_cost);
    }

    #[tokio::test]
    async fn test_nullifier_set() {
        let mut set = NullifierSet::new();
        let nullifier = [1u8; 32];

        assert!(!set.contains(&nullifier));

        set.add_pending(nullifier);
        assert!(set.contains(&nullifier));

        set.rollback();
        assert!(!set.contains(&nullifier));

        set.add_pending(nullifier);
        set.commit();
        assert!(set.contains(&nullifier));
    }

    #[tokio::test]
    async fn test_double_spend_prevention() {
        let config = TxProcessorConfig::default();
        let processor = TransactionProcessor::new(config);
        let mut state = ESLState::new(16);

        let tx = create_test_tx(1, TransactionType::Transfer);

        // First execution should succeed
        let result1 = processor.execute_tx(&tx, &mut state).await.unwrap();
        assert!(result1.success);

        // Second execution with same tx should fail (double spend)
        let result2 = processor.execute_tx(&tx, &mut state).await.unwrap();
        assert!(!result2.success);
        assert!(result2.error.is_some());
        assert!(result2.error.unwrap().contains("Double spend"));
    }

    #[tokio::test]
    async fn test_batch_execution() {
        let config = TxProcessorConfig::default();
        let processor = TransactionProcessor::new(config);
        let mut state = ESLState::new(16);

        let transactions: Vec<_> = (1..5)
            .map(|i| create_test_tx(i, TransactionType::Transfer))
            .collect();

        let receipts = processor.execute_batch(&transactions, &mut state, 100).await.unwrap();

        assert_eq!(receipts.len(), 4);
        for (i, receipt) in receipts.iter().enumerate() {
            assert!(receipt.success);
            assert_eq!(receipt.block_height, 100);
            assert_eq!(receipt.tx_index, i as u32);
        }
    }

    #[tokio::test]
    async fn test_receipt_bloom_filter() {
        let logs = vec![
            TransactionLog {
                contract: [1u8; 32],
                topics: vec![[2u8; 32], [3u8; 32]],
                data: vec![],
            }
        ];

        let bloom = TxReceipt::compute_bloom(&logs);

        // Bloom should not be all zeros
        assert!(bloom.iter().any(|&b| b != 0));
    }

    #[tokio::test]
    async fn test_statistics_tracking() {
        let config = TxProcessorConfig::default();
        let processor = TransactionProcessor::new(config);
        let mut state = ESLState::new(16);

        let tx = create_test_tx(1, TransactionType::Transfer);
        processor.execute_tx(&tx, &mut state).await.unwrap();

        let stats = processor.stats().await;
        assert_eq!(stats.total_processed, 1);
        assert_eq!(stats.successful, 1);
        assert_eq!(stats.failed, 0);
        assert!(stats.total_gas > 0);
    }

    #[tokio::test]
    async fn test_different_tx_types() {
        let config = TxProcessorConfig::default();
        let processor = TransactionProcessor::new(config);
        let mut state = ESLState::new(16);

        let types = [
            TransactionType::Transfer,
            TransactionType::Deploy,
            TransactionType::Call,
            TransactionType::Stake,
            TransactionType::Unstake,
            TransactionType::RegisterValidator,
        ];

        for (i, tx_type) in types.iter().enumerate() {
            let tx = create_test_tx(i as u64 + 1, *tx_type);
            let result = processor.execute_tx(&tx, &mut state).await.unwrap();
            assert!(result.success, "Failed for tx type {:?}", tx_type);
        }

        let stats = processor.stats().await;
        assert_eq!(stats.total_processed, 6);
        assert_eq!(stats.successful, 6);
    }

    #[test]
    fn test_event_topics() {
        // Topics should be deterministic
        let topic1 = TransactionProcessor::transfer_topic();
        let topic2 = TransactionProcessor::transfer_topic();
        assert_eq!(topic1, topic2);

        // Different events should have different topics
        assert_ne!(
            TransactionProcessor::transfer_topic(),
            TransactionProcessor::stake_topic()
        );
    }

    #[test]
    fn test_precompile_addresses() {
        let staking = TransactionProcessor::staking_contract();
        let validator = TransactionProcessor::validator_contract();

        assert_ne!(staking, validator);
        assert_eq!(staking[31], 0x01);
        assert_eq!(validator[31], 0x02);
    }
}
