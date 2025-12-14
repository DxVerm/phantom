//! Block Verification Pipeline
//!
//! Comprehensive verification of blocks including:
//! - VRF proof verification for producer eligibility
//! - Attestation signature verification (Dilithium)
//! - Timestamp validation
//! - State transition verification
//! - Producer stake validation

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;
use tracing::{debug, warn, info};

use phantom_vrf::{VRFPublicKey, VRFOutput, VRFProof};
use phantom_pq::{DilithiumPublicKey, DilithiumSignature, SecurityLevel};

use crate::block::{Block, BlockHeader, Attestation};
use crate::error::{NodeError, NodeResult};
use crate::validator::{ValidatorInfo, ValidatorStatus};

/// Maximum allowed clock drift in seconds
const MAX_CLOCK_DRIFT_SECS: u64 = 30;

/// Maximum age of a block before it's considered too old
const MAX_BLOCK_AGE_SECS: u64 = 3600; // 1 hour

/// Minimum VRF threshold divisor (stake / total_stake * MAX)
const VRF_THRESHOLD_DIVISOR: u64 = 1_000_000;

/// Verification configuration
#[derive(Debug, Clone)]
pub struct VerificationConfig {
    /// Minimum attestations required for a valid block
    pub min_attestations: usize,
    /// Attestation threshold percentage (0-100)
    pub attestation_threshold_pct: u8,
    /// Whether to verify VRF proofs
    pub verify_vrf: bool,
    /// Whether to verify attestation signatures
    pub verify_signatures: bool,
    /// Whether to verify timestamps
    pub verify_timestamps: bool,
    /// Whether to verify state transitions
    pub verify_state: bool,
    /// Security level for Dilithium signatures
    pub security_level: SecurityLevel,
    /// Maximum clock drift allowed (seconds)
    pub max_clock_drift: u64,
    /// Maximum block age (seconds)
    pub max_block_age: u64,
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            min_attestations: 3,
            attestation_threshold_pct: 67,
            verify_vrf: true,
            verify_signatures: true,
            verify_timestamps: true,
            verify_state: true,
            security_level: SecurityLevel::Level5,
            max_clock_drift: MAX_CLOCK_DRIFT_SECS,
            max_block_age: MAX_BLOCK_AGE_SECS,
        }
    }
}

impl VerificationConfig {
    /// Create config for testing (relaxed checks)
    pub fn testing() -> Self {
        Self {
            min_attestations: 1,
            attestation_threshold_pct: 50,
            verify_vrf: false,
            verify_signatures: false,
            verify_timestamps: false,
            verify_state: false,
            security_level: SecurityLevel::Level5,
            max_clock_drift: 3600,
            max_block_age: 86400,
        }
    }

    /// Create config for local development
    pub fn local() -> Self {
        Self {
            min_attestations: 2,
            attestation_threshold_pct: 51,
            verify_vrf: true,
            verify_signatures: true,
            verify_timestamps: true,
            verify_state: true,
            security_level: SecurityLevel::Level3,
            max_clock_drift: 60,
            max_block_age: 7200,
        }
    }

    /// Create config for production
    pub fn production() -> Self {
        Self {
            min_attestations: 5,
            attestation_threshold_pct: 67,
            verify_vrf: true,
            verify_signatures: true,
            verify_timestamps: true,
            verify_state: true,
            security_level: SecurityLevel::Level5,
            max_clock_drift: MAX_CLOCK_DRIFT_SECS,
            max_block_age: MAX_BLOCK_AGE_SECS,
        }
    }
}

/// Result of block verification
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether verification passed
    pub valid: bool,
    /// VRF verification result
    pub vrf_valid: Option<bool>,
    /// Number of valid attestations
    pub valid_attestations: usize,
    /// Total attestations checked
    pub total_attestations: usize,
    /// Timestamp check result
    pub timestamp_valid: bool,
    /// State transition valid
    pub state_valid: bool,
    /// Producer eligibility valid
    pub producer_eligible: bool,
    /// Detailed error if failed
    pub error: Option<String>,
    /// Verification time in microseconds
    pub verification_time_us: u64,
}

impl VerificationResult {
    /// Create successful result
    pub fn success(
        vrf_valid: Option<bool>,
        valid_attestations: usize,
        total_attestations: usize,
        verification_time_us: u64,
    ) -> Self {
        Self {
            valid: true,
            vrf_valid,
            valid_attestations,
            total_attestations,
            timestamp_valid: true,
            state_valid: true,
            producer_eligible: true,
            error: None,
            verification_time_us,
        }
    }

    /// Create failed result
    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            valid: false,
            vrf_valid: None,
            valid_attestations: 0,
            total_attestations: 0,
            timestamp_valid: false,
            state_valid: false,
            producer_eligible: false,
            error: Some(error.into()),
            verification_time_us: 0,
        }
    }
}

/// Validator key cache for signature verification
#[derive(Debug, Clone)]
pub struct ValidatorKeyCache {
    /// Dilithium public keys by validator ID
    dilithium_keys: HashMap<[u8; 32], DilithiumPublicKey>,
    /// VRF public keys by validator ID
    vrf_keys: HashMap<[u8; 32], VRFPublicKey>,
    /// Validator stakes by ID
    stakes: HashMap<[u8; 32], u64>,
    /// Total stake
    total_stake: u64,
    /// Cache epoch (invalidate on epoch change)
    epoch: u64,
}

impl ValidatorKeyCache {
    /// Create empty cache
    pub fn new() -> Self {
        Self {
            dilithium_keys: HashMap::new(),
            vrf_keys: HashMap::new(),
            stakes: HashMap::new(),
            total_stake: 0,
            epoch: 0,
        }
    }

    /// Update cache from validator set
    pub fn update_from_validators(
        &mut self,
        validators: &[ValidatorInfo],
        epoch: u64,
        security_level: SecurityLevel,
    ) -> NodeResult<()> {
        // Clear cache if epoch changed
        if epoch != self.epoch {
            self.dilithium_keys.clear();
            self.vrf_keys.clear();
            self.stakes.clear();
            self.total_stake = 0;
            self.epoch = epoch;
        }

        for validator in validators {
            if validator.status != ValidatorStatus::Active {
                continue;
            }

            // Parse Dilithium public key
            if !validator.public_key.is_empty() {
                if let Ok(pk) = DilithiumPublicKey::from_bytes(
                    &validator.public_key,
                    security_level,
                ) {
                    self.dilithium_keys.insert(validator.id, pk);
                }
            }

            // Parse VRF public key
            if let Ok(vrf_pk) = VRFPublicKey::from_bytes(validator.vrf_key) {
                self.vrf_keys.insert(validator.id, vrf_pk);
            }

            // Store stake
            let total = validator.self_stake + validator.delegated_stake;
            self.stakes.insert(validator.id, total);
            self.total_stake += total;
        }

        Ok(())
    }

    /// Get Dilithium public key for validator
    pub fn get_dilithium_key(&self, validator_id: &[u8; 32]) -> Option<&DilithiumPublicKey> {
        self.dilithium_keys.get(validator_id)
    }

    /// Get VRF public key for validator
    pub fn get_vrf_key(&self, validator_id: &[u8; 32]) -> Option<&VRFPublicKey> {
        self.vrf_keys.get(validator_id)
    }

    /// Get validator stake
    pub fn get_stake(&self, validator_id: &[u8; 32]) -> u64 {
        self.stakes.get(validator_id).copied().unwrap_or(0)
    }

    /// Get total stake
    pub fn total_stake(&self) -> u64 {
        self.total_stake
    }

    /// Check if validator is in cache
    pub fn contains(&self, validator_id: &[u8; 32]) -> bool {
        self.dilithium_keys.contains_key(validator_id)
    }
}

impl Default for ValidatorKeyCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Block verification pipeline
pub struct BlockVerifier {
    config: VerificationConfig,
    key_cache: Arc<RwLock<ValidatorKeyCache>>,
    min_stake: u64,
    /// Statistics
    blocks_verified: u64,
    blocks_rejected: u64,
    total_verification_time_us: u64,
}

impl BlockVerifier {
    /// Create new block verifier
    pub fn new(config: VerificationConfig, min_stake: u64) -> Self {
        Self {
            config,
            key_cache: Arc::new(RwLock::new(ValidatorKeyCache::new())),
            min_stake,
            blocks_verified: 0,
            blocks_rejected: 0,
            total_verification_time_us: 0,
        }
    }

    /// Create with default config
    pub fn default_with_stake(min_stake: u64) -> Self {
        Self::new(VerificationConfig::default(), min_stake)
    }

    /// Update key cache from validators
    pub async fn update_key_cache(
        &self,
        validators: &[ValidatorInfo],
        epoch: u64,
    ) -> NodeResult<()> {
        let mut cache = self.key_cache.write().await;
        cache.update_from_validators(validators, epoch, self.config.security_level)
    }

    /// Verify a block fully
    pub async fn verify_block(
        &mut self,
        block: &Block,
        prev_state_root: &[u8; 32],
        expected_state_root: Option<&[u8; 32]>,
    ) -> NodeResult<VerificationResult> {
        let start = std::time::Instant::now();

        debug!(
            "Verifying block {} (producer: {})",
            block.height(),
            hex::encode(&block.header.producer[..8])
        );

        // Basic structure verification
        if !block.verify() {
            self.blocks_rejected += 1;
            return Ok(VerificationResult::failure("Block integrity check failed"));
        }

        // Timestamp verification
        if self.config.verify_timestamps {
            if let Err(e) = self.verify_timestamp(&block.header) {
                self.blocks_rejected += 1;
                return Ok(VerificationResult::failure(format!("Timestamp: {}", e)));
            }
        }

        // VRF verification
        let vrf_valid = if self.config.verify_vrf {
            match self.verify_vrf_proof(&block.header).await {
                Ok(valid) => {
                    if !valid {
                        self.blocks_rejected += 1;
                        return Ok(VerificationResult::failure("VRF proof invalid"));
                    }
                    Some(true)
                }
                Err(e) => {
                    self.blocks_rejected += 1;
                    return Ok(VerificationResult::failure(format!("VRF: {}", e)));
                }
            }
        } else {
            None
        };

        // Producer eligibility
        if let Err(e) = self.verify_producer_eligibility(&block.header).await {
            self.blocks_rejected += 1;
            return Ok(VerificationResult::failure(format!("Producer: {}", e)));
        }

        // Attestation verification
        let (valid_attestations, total_attestations) = if self.config.verify_signatures {
            self.verify_attestations(&block.header).await?
        } else {
            (block.header.attestations.len(), block.header.attestations.len())
        };

        // Check attestation threshold
        if valid_attestations < self.config.min_attestations {
            self.blocks_rejected += 1;
            return Ok(VerificationResult::failure(format!(
                "Insufficient attestations: {} < {}",
                valid_attestations, self.config.min_attestations
            )));
        }

        // State transition verification
        if self.config.verify_state {
            if let Some(expected) = expected_state_root {
                if &block.header.state_root != expected {
                    self.blocks_rejected += 1;
                    return Ok(VerificationResult::failure("State root mismatch"));
                }
            }
        }

        let elapsed = start.elapsed().as_micros() as u64;
        self.blocks_verified += 1;
        self.total_verification_time_us += elapsed;

        info!(
            "Block {} verified in {}µs ({}/{} attestations)",
            block.height(), elapsed, valid_attestations, total_attestations
        );

        Ok(VerificationResult::success(
            vrf_valid,
            valid_attestations,
            total_attestations,
            elapsed,
        ))
    }

    /// Verify block header only (for sync)
    pub async fn verify_header(&self, header: &BlockHeader) -> NodeResult<bool> {
        // Basic checks
        if self.config.verify_timestamps {
            self.verify_timestamp(header)?;
        }

        // Check attestation count
        if header.attestations.len() < self.config.min_attestations {
            return Ok(false);
        }

        // VRF check
        if self.config.verify_vrf {
            if !self.verify_vrf_proof(header).await? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Verify timestamp is within acceptable bounds
    fn verify_timestamp(&self, header: &BlockHeader) -> NodeResult<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| NodeError::Verification(format!("System time error: {}", e)))?
            .as_secs();

        // Check not too far in the future
        if header.timestamp > now + self.config.max_clock_drift {
            return Err(NodeError::Verification(format!(
                "Block timestamp {} is {} seconds in the future",
                header.timestamp,
                header.timestamp - now
            )));
        }

        // Check not too old
        if header.timestamp + self.config.max_block_age < now {
            return Err(NodeError::Verification(format!(
                "Block timestamp {} is {} seconds old (max: {})",
                header.timestamp,
                now - header.timestamp,
                self.config.max_block_age
            )));
        }

        Ok(())
    }

    /// Verify VRF proof for producer selection
    async fn verify_vrf_proof(&self, header: &BlockHeader) -> NodeResult<bool> {
        // Get producer's VRF public key
        let cache = self.key_cache.read().await;
        let vrf_key = cache.get_vrf_key(&header.producer).ok_or_else(|| {
            NodeError::Verification(format!(
                "VRF key not found for producer {}",
                hex::encode(&header.producer[..8])
            ))
        })?;

        // Deserialize VRF proof
        if header.vrf_proof.len() != 96 {
            return Err(NodeError::Verification(format!(
                "Invalid VRF proof length: {} (expected 96)",
                header.vrf_proof.len()
            )));
        }

        let proof_bytes: [u8; 96] = header.vrf_proof[..96]
            .try_into()
            .map_err(|_| NodeError::Verification("Invalid VRF proof format".into()))?;
        let proof = VRFProof::from_bytes(&proof_bytes);

        // Construct VRF input: epoch || round || prev_hash
        let mut alpha = Vec::with_capacity(80);
        alpha.extend_from_slice(&header.epoch.to_le_bytes());
        alpha.extend_from_slice(&header.round.to_le_bytes());
        alpha.extend_from_slice(&header.prev_hash);

        // Compute expected output for threshold check
        let mut output_bytes = [0u8; 32];
        // The VRF output should be derivable from the proof's gamma point
        // For verification, we compute what the output should be
        output_bytes.copy_from_slice(&blake3::hash(&header.vrf_proof[..32]).as_bytes()[..32]);
        let output = VRFOutput::from_bytes(output_bytes);

        // Verify the proof
        match vrf_key.verify(&alpha, &output, &proof) {
            Ok(valid) => {
                if !valid {
                    warn!(
                        "VRF verification failed for block {} producer {}",
                        header.height,
                        hex::encode(&header.producer[..8])
                    );
                }
                Ok(valid)
            }
            Err(e) => {
                warn!("VRF verification error: {}", e);
                Ok(false)
            }
        }
    }

    /// Verify producer is eligible (has sufficient stake)
    async fn verify_producer_eligibility(&self, header: &BlockHeader) -> NodeResult<()> {
        let cache = self.key_cache.read().await;

        let stake = cache.get_stake(&header.producer);
        if stake < self.min_stake {
            return Err(NodeError::Verification(format!(
                "Producer stake {} below minimum {}",
                stake, self.min_stake
            )));
        }

        // Check producer is in active validator set
        if !cache.contains(&header.producer) {
            return Err(NodeError::Verification(format!(
                "Producer {} not in active validator set",
                hex::encode(&header.producer[..8])
            )));
        }

        Ok(())
    }

    /// Verify attestation signatures
    async fn verify_attestations(&self, header: &BlockHeader) -> NodeResult<(usize, usize)> {
        let cache = self.key_cache.read().await;
        let block_hash = header.hash();

        let mut valid_count = 0;
        let total = header.attestations.len();

        for attestation in &header.attestations {
            if let Some(valid) = self.verify_single_attestation(
                attestation,
                &block_hash,
                &cache,
            ) {
                if valid {
                    valid_count += 1;
                }
            }
        }

        Ok((valid_count, total))
    }

    /// Verify a single attestation signature
    fn verify_single_attestation(
        &self,
        attestation: &Attestation,
        block_hash: &[u8; 32],
        cache: &ValidatorKeyCache,
    ) -> Option<bool> {
        // Check attestation is for this block
        if &attestation.block_hash != block_hash {
            debug!(
                "Attestation block hash mismatch: expected {}, got {}",
                hex::encode(&block_hash[..8]),
                hex::encode(&attestation.block_hash[..8])
            );
            return Some(false);
        }

        // Get witness public key
        let public_key = cache.get_dilithium_key(&attestation.witness_id)?;

        // Create signature from bytes
        let signature = match DilithiumSignature::from_bytes(
            &attestation.signature,
            self.config.security_level,
        ) {
            Ok(sig) => sig,
            Err(e) => {
                debug!(
                    "Failed to parse attestation signature from {}: {}",
                    hex::encode(&attestation.witness_id[..8]),
                    e
                );
                return Some(false);
            }
        };

        // Verify signature over block hash
        match signature.verify(block_hash, public_key) {
            Ok(valid) => {
                if !valid {
                    debug!(
                        "Attestation signature verification failed for witness {}",
                        hex::encode(&attestation.witness_id[..8])
                    );
                }
                Some(valid)
            }
            Err(e) => {
                debug!("Signature verification error: {}", e);
                Some(false)
            }
        }
    }

    /// Quick validation for gossip (minimal checks)
    pub fn quick_validate(&self, block: &Block) -> bool {
        // Check basic integrity
        if !block.verify() {
            return false;
        }

        // Check attestation count
        if block.header.attestations.len() < self.config.min_attestations {
            return false;
        }

        // Check VRF proof present
        if self.config.verify_vrf && block.header.vrf_proof.is_empty() {
            return false;
        }

        true
    }

    /// Get verification statistics
    pub fn stats(&self) -> VerificationStats {
        VerificationStats {
            blocks_verified: self.blocks_verified,
            blocks_rejected: self.blocks_rejected,
            avg_verification_time_us: if self.blocks_verified > 0 {
                self.total_verification_time_us / self.blocks_verified
            } else {
                0
            },
        }
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.blocks_verified = 0;
        self.blocks_rejected = 0;
        self.total_verification_time_us = 0;
    }

    /// Get config
    pub fn config(&self) -> &VerificationConfig {
        &self.config
    }

    /// Update config
    pub fn set_config(&mut self, config: VerificationConfig) {
        self.config = config;
    }
}

/// Verification statistics
#[derive(Debug, Clone, Default)]
pub struct VerificationStats {
    /// Total blocks verified
    pub blocks_verified: u64,
    /// Total blocks rejected
    pub blocks_rejected: u64,
    /// Average verification time in microseconds
    pub avg_verification_time_us: u64,
}

impl VerificationStats {
    /// Get acceptance rate
    pub fn acceptance_rate(&self) -> f64 {
        let total = self.blocks_verified + self.blocks_rejected;
        if total == 0 {
            1.0
        } else {
            self.blocks_verified as f64 / total as f64
        }
    }
}

/// Batch verification for multiple blocks
pub struct BatchVerifier {
    verifier: BlockVerifier,
    /// Maximum batch size
    max_batch_size: usize,
}

impl BatchVerifier {
    /// Create new batch verifier
    pub fn new(verifier: BlockVerifier, max_batch_size: usize) -> Self {
        Self {
            verifier,
            max_batch_size,
        }
    }

    /// Verify a batch of blocks
    pub async fn verify_batch(
        &mut self,
        blocks: &[Block],
    ) -> NodeResult<Vec<VerificationResult>> {
        let mut results = Vec::with_capacity(blocks.len());

        for chunk in blocks.chunks(self.max_batch_size) {
            for block in chunk {
                let result = self.verifier
                    .verify_block(block, &[0u8; 32], None)
                    .await?;
                results.push(result);
            }
        }

        Ok(results)
    }

    /// Verify chain of blocks (sequential validation)
    pub async fn verify_chain(
        &mut self,
        blocks: &[Block],
        starting_state_root: &[u8; 32],
    ) -> NodeResult<Vec<VerificationResult>> {
        let mut results = Vec::with_capacity(blocks.len());
        let mut prev_state_root = *starting_state_root;

        for (i, block) in blocks.iter().enumerate() {
            // Verify block
            let result = self.verifier
                .verify_block(block, &prev_state_root, None)
                .await?;

            if !result.valid {
                // Stop chain verification on first failure
                results.push(result);
                break;
            }

            // Update state root for next block
            prev_state_root = block.header.state_root;
            results.push(result);
        }

        Ok(results)
    }

    /// Get underlying verifier
    pub fn inner(&self) -> &BlockVerifier {
        &self.verifier
    }

    /// Get mutable underlying verifier
    pub fn inner_mut(&mut self) -> &mut BlockVerifier {
        &mut self.verifier
    }
}

/// Verification error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    /// Block structure invalid
    InvalidStructure(String),
    /// VRF proof invalid
    InvalidVRFProof,
    /// Attestation signature invalid
    InvalidAttestationSignature { witness: [u8; 32] },
    /// Insufficient attestations
    InsufficientAttestations { got: usize, need: usize },
    /// Timestamp out of range
    TimestampOutOfRange { timestamp: u64 },
    /// Producer not eligible
    ProducerNotEligible { producer: [u8; 32], stake: u64 },
    /// State root mismatch
    StateRootMismatch { expected: [u8; 32], got: [u8; 32] },
    /// Key not found
    KeyNotFound { validator: [u8; 32] },
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidStructure(msg) => write!(f, "Invalid block structure: {}", msg),
            Self::InvalidVRFProof => write!(f, "Invalid VRF proof"),
            Self::InvalidAttestationSignature { witness } => {
                write!(f, "Invalid attestation from {}", hex::encode(&witness[..8]))
            }
            Self::InsufficientAttestations { got, need } => {
                write!(f, "Insufficient attestations: {} < {}", got, need)
            }
            Self::TimestampOutOfRange { timestamp } => {
                write!(f, "Timestamp {} out of acceptable range", timestamp)
            }
            Self::ProducerNotEligible { producer, stake } => {
                write!(
                    f,
                    "Producer {} not eligible (stake: {})",
                    hex::encode(&producer[..8]),
                    stake
                )
            }
            Self::StateRootMismatch { expected, got } => {
                write!(
                    f,
                    "State root mismatch: expected {}, got {}",
                    hex::encode(&expected[..8]),
                    hex::encode(&got[..8])
                )
            }
            Self::KeyNotFound { validator } => {
                write!(f, "Key not found for validator {}", hex::encode(&validator[..8]))
            }
        }
    }
}

impl std::error::Error for VerificationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{BlockBody, BlockHeader};

    fn create_test_header(height: u64) -> BlockHeader {
        BlockHeader {
            height,
            prev_hash: [0u8; 32],
            state_root: [1u8; 32],
            tx_root: [0u8; 32],
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            epoch: 0,
            round: 0,
            producer: [2u8; 32],
            vrf_proof: vec![0u8; 96],
            attestations: vec![],
            extra_data: vec![],
        }
    }

    fn create_test_block(height: u64) -> Block {
        Block::new(create_test_header(height), BlockBody::empty())
    }

    #[test]
    fn test_verification_config_defaults() {
        let config = VerificationConfig::default();
        assert_eq!(config.min_attestations, 3);
        assert_eq!(config.attestation_threshold_pct, 67);
        assert!(config.verify_vrf);
        assert!(config.verify_signatures);
    }

    #[test]
    fn test_verification_config_testing() {
        let config = VerificationConfig::testing();
        assert_eq!(config.min_attestations, 1);
        assert!(!config.verify_vrf);
        assert!(!config.verify_signatures);
    }

    #[test]
    fn test_verification_result_success() {
        let result = VerificationResult::success(Some(true), 5, 5, 100);
        assert!(result.valid);
        assert_eq!(result.vrf_valid, Some(true));
        assert_eq!(result.valid_attestations, 5);
    }

    #[test]
    fn test_verification_result_failure() {
        let result = VerificationResult::failure("Test failure");
        assert!(!result.valid);
        assert_eq!(result.error, Some("Test failure".to_string()));
    }

    #[test]
    fn test_validator_key_cache() {
        let cache = ValidatorKeyCache::new();
        assert_eq!(cache.total_stake(), 0);
        assert!(!cache.contains(&[0u8; 32]));
    }

    #[tokio::test]
    async fn test_verifier_quick_validate() {
        let verifier = BlockVerifier::new(VerificationConfig::testing(), 100);

        let mut block = create_test_block(1);

        // Empty attestations - should fail with default config
        let production_verifier = BlockVerifier::new(VerificationConfig::default(), 100);
        assert!(!production_verifier.quick_validate(&block));

        // Add attestations
        block.header.attestations = vec![
            Attestation::new([1u8; 32], block.hash(), vec![0u8; 100]),
            Attestation::new([2u8; 32], block.hash(), vec![0u8; 100]),
            Attestation::new([3u8; 32], block.hash(), vec![0u8; 100]),
        ];

        assert!(production_verifier.quick_validate(&block));
    }

    #[test]
    fn test_verification_stats() {
        let stats = VerificationStats {
            blocks_verified: 90,
            blocks_rejected: 10,
            avg_verification_time_us: 100,
        };

        assert_eq!(stats.acceptance_rate(), 0.9);
    }

    #[test]
    fn test_verification_stats_empty() {
        let stats = VerificationStats::default();
        assert_eq!(stats.acceptance_rate(), 1.0);
    }

    #[tokio::test]
    async fn test_verify_block_basic() {
        let mut verifier = BlockVerifier::new(VerificationConfig::testing(), 100);

        let mut block = create_test_block(1);
        block.header.attestations = vec![
            Attestation::new([1u8; 32], block.hash(), vec![]),
        ];

        let result = verifier
            .verify_block(&block, &[0u8; 32], None)
            .await
            .unwrap();

        assert!(result.valid);
    }

    #[test]
    fn test_timestamp_verification() {
        let verifier = BlockVerifier::new(VerificationConfig::default(), 100);

        // Current time - should pass
        let mut header = create_test_header(1);
        assert!(verifier.verify_timestamp(&header).is_ok());

        // Future time - should fail
        header.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() + 3600;
        assert!(verifier.verify_timestamp(&header).is_err());

        // Old time - should fail
        header.timestamp = 0;
        assert!(verifier.verify_timestamp(&header).is_err());
    }

    #[test]
    fn test_verification_error_display() {
        let err = VerificationError::InvalidVRFProof;
        assert_eq!(err.to_string(), "Invalid VRF proof");

        let err = VerificationError::InsufficientAttestations { got: 2, need: 5 };
        assert_eq!(err.to_string(), "Insufficient attestations: 2 < 5");
    }

    #[tokio::test]
    async fn test_batch_verifier() {
        let verifier = BlockVerifier::new(VerificationConfig::testing(), 100);
        let mut batch_verifier = BatchVerifier::new(verifier, 10);

        let blocks: Vec<Block> = (1..=5)
            .map(|i| {
                let mut block = create_test_block(i);
                block.header.attestations = vec![
                    Attestation::new([1u8; 32], block.hash(), vec![]),
                ];
                block
            })
            .collect();

        let results = batch_verifier.verify_batch(&blocks).await.unwrap();
        assert_eq!(results.len(), 5);
        assert!(results.iter().all(|r| r.valid));
    }

    #[tokio::test]
    async fn test_verify_chain() {
        let verifier = BlockVerifier::new(VerificationConfig::testing(), 100);
        let mut batch_verifier = BatchVerifier::new(verifier, 10);

        let mut prev_hash = [0u8; 32];
        let blocks: Vec<Block> = (1..=3)
            .map(|i| {
                let mut header = create_test_header(i);
                header.prev_hash = prev_hash;
                let block = Block::new(header, BlockBody::empty());
                prev_hash = block.hash();

                let mut block_with_attestation = block.clone();
                block_with_attestation.header.attestations = vec![
                    Attestation::new([1u8; 32], block.hash(), vec![]),
                ];
                block_with_attestation
            })
            .collect();

        let results = batch_verifier.verify_chain(&blocks, &[0u8; 32]).await.unwrap();
        assert_eq!(results.len(), 3);
    }

    #[tokio::test]
    async fn test_verifier_stats() {
        let mut verifier = BlockVerifier::new(VerificationConfig::testing(), 100);

        // Verify some blocks
        for i in 1..=5 {
            let mut block = create_test_block(i);
            block.header.attestations = vec![
                Attestation::new([1u8; 32], block.hash(), vec![]),
            ];
            let _ = verifier.verify_block(&block, &[0u8; 32], None).await;
        }

        let stats = verifier.stats();
        assert_eq!(stats.blocks_verified, 5);
        assert!(stats.avg_verification_time_us > 0);

        verifier.reset_stats();
        let stats = verifier.stats();
        assert_eq!(stats.blocks_verified, 0);
    }
}
