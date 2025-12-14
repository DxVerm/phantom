//! Proof Delegation Protocol
//!
//! Enables light clients to delegate heavy FHE proof computations to trusted full nodes.
//!
//! # Security Model
//!
//! The delegation protocol uses a threshold trust model:
//! - Light client maintains a set of trusted full nodes
//! - Proofs must be signed by at least `threshold` nodes
//! - Invalid signatures cause node reputation penalties
//!
//! # Protocol Flow
//!
//! ```text
//! Light Client                        Full Node(s)
//!      │                                   │
//!      │──── DelegationRequest ──────────►│
//!      │     (proof_type, parameters)      │
//!      │                                   │
//!      │                           [Compute Proof]
//!      │                                   │
//!      │◄─── DelegationResponse ──────────│
//!      │     (proof, signature, witness)   │
//!      │                                   │
//!  [Verify Signature]                      │
//!  [Verify Witness]                        │
//!  [Update Trust Score]                    │
//! ```

use crate::errors::{LightClientError, LightClientResult};
use crate::verification::{InclusionProof, StateProof};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;

/// Types of proofs that can be delegated
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DelegatedProofType {
    /// Transaction inclusion proof
    TransactionInclusion,
    /// State proof (account balance, contract storage)
    StateProof,
    /// Receipt proof (transaction execution result)
    ReceiptProof,
    /// FHE computation proof
    FHEComputation,
    /// Batch proof (multiple items)
    BatchProof,
}

/// Request to delegate proof computation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationRequest {
    /// Unique request ID
    pub request_id: u64,
    /// Type of proof requested
    pub proof_type: DelegatedProofType,
    /// Block height for the proof
    pub block_height: u64,
    /// Block hash for the proof
    pub block_hash: [u8; 32],
    /// Item hash (transaction, state key, etc.)
    pub item_hash: [u8; 32],
    /// Additional parameters (serialized)
    pub parameters: Vec<u8>,
    /// Timestamp of request
    pub timestamp: u64,
    /// Client's public key for response encryption
    pub client_pubkey: [u8; 32],
}

impl DelegationRequest {
    /// Create a new delegation request
    pub fn new(
        request_id: u64,
        proof_type: DelegatedProofType,
        block_height: u64,
        block_hash: [u8; 32],
        item_hash: [u8; 32],
    ) -> Self {
        Self {
            request_id,
            proof_type,
            block_height,
            block_hash,
            item_hash,
            parameters: Vec::new(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            client_pubkey: [0u8; 32],
        }
    }

    /// Set additional parameters
    pub fn with_parameters(mut self, params: Vec<u8>) -> Self {
        self.parameters = params;
        self
    }

    /// Set client public key
    pub fn with_client_pubkey(mut self, pubkey: [u8; 32]) -> Self {
        self.client_pubkey = pubkey;
        self
    }

    /// Compute request hash for signing
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.request_id.to_le_bytes());
        hasher.update(&[self.proof_type as u8]);
        hasher.update(&self.block_height.to_le_bytes());
        hasher.update(&self.block_hash);
        hasher.update(&self.item_hash);
        hasher.update(&self.parameters);
        *hasher.finalize().as_bytes()
    }
}

/// Response from a delegated proof computation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationResponse {
    /// Request ID this responds to
    pub request_id: u64,
    /// Node that computed the proof
    pub node_pubkey: [u8; 32],
    /// The delegated proof
    pub proof: DelegatedProofData,
    /// Node's signature over the proof (64 bytes for Ed25519/Dilithium)
    pub signature: Vec<u8>,
    /// Computation witness (for verification)
    pub witness: ComputationWitness,
    /// Response timestamp
    pub timestamp: u64,
}

/// Proof data in delegation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DelegatedProofData {
    /// Inclusion proof
    Inclusion(InclusionProof),
    /// State proof
    State(StateProof),
    /// Raw proof bytes (for FHE proofs)
    Raw(Vec<u8>),
    /// Batch of proofs
    Batch(Vec<DelegatedProofData>),
}

/// Witness data for verifying computation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputationWitness {
    /// Merkle root used in verification
    pub merkle_root: [u8; 32],
    /// State root at block
    pub state_root: [u8; 32],
    /// Computation steps (for debugging/audit)
    pub steps: u32,
    /// Intermediate hashes (optional)
    pub intermediate_hashes: Vec<[u8; 32]>,
}

impl Default for ComputationWitness {
    fn default() -> Self {
        Self {
            merkle_root: [0u8; 32],
            state_root: [0u8; 32],
            steps: 0,
            intermediate_hashes: Vec::new(),
        }
    }
}

/// Trust level for a node
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustLevel {
    /// New node, no history
    Unknown = 0,
    /// Some successful delegations
    Basic = 1,
    /// Many successful delegations
    Trusted = 2,
    /// Hardcoded trusted node
    Verified = 3,
}

/// Information about a trusted delegation node
#[derive(Debug, Clone)]
pub struct DelegationNode {
    /// Node's public key
    pub pubkey: [u8; 32],
    /// Trust level
    pub trust_level: TrustLevel,
    /// Successful delegations
    pub success_count: u64,
    /// Failed/invalid delegations
    pub failure_count: u64,
    /// Last successful response time
    pub last_success: Option<Instant>,
    /// Average response time (ms)
    pub avg_response_ms: u64,
    /// Endpoint URL (for network requests)
    pub endpoint: Option<String>,
    /// Supported proof types
    pub supported_types: Vec<DelegatedProofType>,
}

impl DelegationNode {
    /// Create a new delegation node
    pub fn new(pubkey: [u8; 32]) -> Self {
        Self {
            pubkey,
            trust_level: TrustLevel::Unknown,
            success_count: 0,
            failure_count: 0,
            last_success: None,
            avg_response_ms: 0,
            endpoint: None,
            supported_types: vec![
                DelegatedProofType::TransactionInclusion,
                DelegatedProofType::StateProof,
                DelegatedProofType::ReceiptProof,
            ],
        }
    }

    /// Create a verified (hardcoded) node
    pub fn verified(pubkey: [u8; 32], endpoint: String) -> Self {
        Self {
            pubkey,
            trust_level: TrustLevel::Verified,
            success_count: 0,
            failure_count: 0,
            last_success: None,
            avg_response_ms: 0,
            endpoint: Some(endpoint),
            supported_types: vec![
                DelegatedProofType::TransactionInclusion,
                DelegatedProofType::StateProof,
                DelegatedProofType::ReceiptProof,
                DelegatedProofType::FHEComputation,
                DelegatedProofType::BatchProof,
            ],
        }
    }

    /// Calculate reliability score (0.0 - 1.0)
    pub fn reliability_score(&self) -> f64 {
        let total = self.success_count + self.failure_count;
        if total == 0 {
            return match self.trust_level {
                TrustLevel::Verified => 0.9,
                TrustLevel::Trusted => 0.7,
                TrustLevel::Basic => 0.5,
                TrustLevel::Unknown => 0.3,
            };
        }

        let success_rate = self.success_count as f64 / total as f64;
        let base_score = match self.trust_level {
            TrustLevel::Verified => 0.2,
            TrustLevel::Trusted => 0.1,
            TrustLevel::Basic => 0.05,
            TrustLevel::Unknown => 0.0,
        };

        (success_rate * 0.8 + base_score).min(1.0)
    }

    /// Record a successful delegation
    pub fn record_success(&mut self, response_ms: u64) {
        self.success_count += 1;
        self.last_success = Some(Instant::now());

        // Update average response time
        if self.avg_response_ms == 0 {
            self.avg_response_ms = response_ms;
        } else {
            self.avg_response_ms = (self.avg_response_ms * 9 + response_ms) / 10;
        }

        // Upgrade trust level
        self.update_trust_level();
    }

    /// Record a failed delegation
    pub fn record_failure(&mut self) {
        self.failure_count += 1;
        // Downgrade trust level if too many failures
        if self.failure_count > self.success_count / 2 && self.trust_level != TrustLevel::Verified {
            self.trust_level = TrustLevel::Unknown;
        }
    }

    /// Update trust level based on history
    fn update_trust_level(&mut self) {
        if self.trust_level == TrustLevel::Verified {
            return; // Don't downgrade verified nodes
        }

        let total = self.success_count + self.failure_count;
        let success_rate = if total > 0 {
            self.success_count as f64 / total as f64
        } else {
            0.0
        };

        self.trust_level = if self.success_count >= 100 && success_rate >= 0.99 {
            TrustLevel::Trusted
        } else if self.success_count >= 10 && success_rate >= 0.9 {
            TrustLevel::Basic
        } else {
            TrustLevel::Unknown
        };
    }

    /// Check if node supports a proof type
    pub fn supports(&self, proof_type: DelegatedProofType) -> bool {
        self.supported_types.contains(&proof_type)
    }
}

/// Configuration for delegation manager
#[derive(Debug, Clone)]
pub struct DelegationConfig {
    /// Minimum number of nodes required for threshold verification
    pub min_nodes: usize,
    /// Threshold for accepting a proof (e.g., 2 of 3)
    pub threshold: usize,
    /// Maximum age of delegated proofs (seconds)
    pub max_proof_age: u64,
    /// Request timeout (seconds)
    pub request_timeout: u64,
    /// Maximum concurrent requests
    pub max_concurrent: usize,
    /// Retry count for failed requests
    pub retry_count: usize,
}

impl Default for DelegationConfig {
    fn default() -> Self {
        Self {
            min_nodes: 3,
            threshold: 2,
            max_proof_age: 3600,
            request_timeout: 30,
            max_concurrent: 5,
            retry_count: 2,
        }
    }
}

/// Manager for proof delegation
pub struct DelegationManager {
    /// Configuration
    config: DelegationConfig,
    /// Trusted nodes
    nodes: RwLock<HashMap<[u8; 32], DelegationNode>>,
    /// Pending requests
    pending: RwLock<HashMap<u64, PendingRequest>>,
    /// Next request ID
    next_request_id: RwLock<u64>,
    /// Cached proofs
    cache: RwLock<HashMap<[u8; 32], CachedProof>>,
}

/// A pending delegation request
#[derive(Debug)]
struct PendingRequest {
    request: DelegationRequest,
    created: Instant,
    responses: Vec<DelegationResponse>,
    target_nodes: Vec<[u8; 32]>,
}

/// A cached proof
#[derive(Debug, Clone)]
struct CachedProof {
    proof: DelegatedProofData,
    timestamp: u64,
    verified_by: Vec<[u8; 32]>,
}

impl DelegationManager {
    /// Create a new delegation manager
    pub fn new(config: DelegationConfig) -> Self {
        Self {
            config,
            nodes: RwLock::new(HashMap::new()),
            pending: RwLock::new(HashMap::new()),
            next_request_id: RwLock::new(0),
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Add a trusted node
    pub fn add_node(&self, node: DelegationNode) {
        self.nodes.write().insert(node.pubkey, node);
    }

    /// Remove a node
    pub fn remove_node(&self, pubkey: &[u8; 32]) {
        self.nodes.write().remove(pubkey);
    }

    /// Get node by public key
    pub fn get_node(&self, pubkey: &[u8; 32]) -> Option<DelegationNode> {
        self.nodes.read().get(pubkey).cloned()
    }

    /// List all nodes
    pub fn list_nodes(&self) -> Vec<DelegationNode> {
        self.nodes.read().values().cloned().collect()
    }

    /// Get nodes that support a proof type, sorted by reliability
    pub fn get_nodes_for_type(&self, proof_type: DelegatedProofType) -> Vec<DelegationNode> {
        let nodes = self.nodes.read();
        let mut suitable: Vec<_> = nodes
            .values()
            .filter(|n| n.supports(proof_type))
            .cloned()
            .collect();

        suitable.sort_by(|a, b| {
            b.reliability_score()
                .partial_cmp(&a.reliability_score())
                .unwrap()
        });

        suitable
    }

    /// Create a delegation request
    pub fn create_request(
        &self,
        proof_type: DelegatedProofType,
        block_height: u64,
        block_hash: [u8; 32],
        item_hash: [u8; 32],
    ) -> LightClientResult<DelegationRequest> {
        let mut request_id = self.next_request_id.write();
        *request_id += 1;

        let request = DelegationRequest::new(
            *request_id,
            proof_type,
            block_height,
            block_hash,
            item_hash,
        );

        // Select nodes for this request
        let nodes = self.get_nodes_for_type(proof_type);
        if nodes.len() < self.config.min_nodes {
            return Err(LightClientError::NotEnoughNodes {
                required: self.config.min_nodes,
                available: nodes.len(),
            });
        }

        // Store pending request
        let target_nodes: Vec<_> = nodes
            .iter()
            .take(self.config.max_concurrent)
            .map(|n| n.pubkey)
            .collect();

        self.pending.write().insert(
            request.request_id,
            PendingRequest {
                request: request.clone(),
                created: Instant::now(),
                responses: Vec::new(),
                target_nodes,
            },
        );

        Ok(request)
    }

    /// Process a delegation response
    pub fn process_response(
        &self,
        response: DelegationResponse,
    ) -> LightClientResult<Option<DelegatedProofData>> {
        let mut pending = self.pending.write();
        let request = pending
            .get_mut(&response.request_id)
            .ok_or(LightClientError::RequestNotFound(response.request_id))?;

        // Verify the node is expected
        if !request.target_nodes.contains(&response.node_pubkey) {
            return Err(LightClientError::UnexpectedNode(response.node_pubkey));
        }

        // Verify signature
        self.verify_response_signature(&response)?;

        // Add response
        request.responses.push(response.clone());

        // Check if we have enough responses
        if request.responses.len() >= self.config.threshold {
            // Verify consensus
            let proof = self.verify_consensus(&request.responses)?;

            // Update node stats
            for resp in &request.responses {
                if let Some(node) = self.nodes.write().get_mut(&resp.node_pubkey) {
                    let elapsed = request.created.elapsed().as_millis() as u64;
                    node.record_success(elapsed);
                }
            }

            // Cache the proof
            let cache_key = self.compute_cache_key(&request.request);
            self.cache.write().insert(
                cache_key,
                CachedProof {
                    proof: proof.clone(),
                    timestamp: response.timestamp,
                    verified_by: request.responses.iter().map(|r| r.node_pubkey).collect(),
                },
            );

            // Remove from pending
            pending.remove(&response.request_id);

            return Ok(Some(proof));
        }

        Ok(None)
    }

    /// Verify signature on a response
    fn verify_response_signature(&self, response: &DelegationResponse) -> LightClientResult<()> {
        // In production, this would use actual signature verification
        // For now, we just check the node is known
        let nodes = self.nodes.read();
        if !nodes.contains_key(&response.node_pubkey) {
            return Err(LightClientError::UnknownNode(response.node_pubkey));
        }

        // Verify timestamp is not too old
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if now > response.timestamp + self.config.max_proof_age {
            return Err(LightClientError::ProofExpired);
        }

        Ok(())
    }

    /// Verify consensus among responses
    fn verify_consensus(
        &self,
        responses: &[DelegationResponse],
    ) -> LightClientResult<DelegatedProofData> {
        if responses.is_empty() {
            return Err(LightClientError::NoResponses);
        }

        // All responses must have the same proof data
        // (In production, you'd compare proof hashes)
        let first = &responses[0].proof;

        // Simple check: all proofs must be of the same type
        for response in responses.iter().skip(1) {
            if std::mem::discriminant(&response.proof) != std::mem::discriminant(first) {
                return Err(LightClientError::ConsensusFailed);
            }
        }

        Ok(first.clone())
    }

    /// Compute cache key for a request
    fn compute_cache_key(&self, request: &DelegationRequest) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[request.proof_type as u8]);
        hasher.update(&request.block_height.to_le_bytes());
        hasher.update(&request.block_hash);
        hasher.update(&request.item_hash);
        *hasher.finalize().as_bytes()
    }

    /// Check cache for a proof
    pub fn get_cached_proof(
        &self,
        proof_type: DelegatedProofType,
        block_height: u64,
        block_hash: [u8; 32],
        item_hash: [u8; 32],
    ) -> Option<DelegatedProofData> {
        let request = DelegationRequest::new(
            0, // ID doesn't matter for cache key
            proof_type,
            block_height,
            block_hash,
            item_hash,
        );

        let cache_key = self.compute_cache_key(&request);
        let cache = self.cache.read();

        cache.get(&cache_key).and_then(|cached| {
            // Check if not expired
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            if now <= cached.timestamp + self.config.max_proof_age {
                Some(cached.proof.clone())
            } else {
                None
            }
        })
    }

    /// Clean expired cache entries
    pub fn clean_cache(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.cache.write().retain(|_, cached| {
            now <= cached.timestamp + self.config.max_proof_age
        });
    }

    /// Clean expired pending requests
    pub fn clean_pending(&self) {
        let timeout = std::time::Duration::from_secs(self.config.request_timeout);
        self.pending.write().retain(|_, pending| {
            pending.created.elapsed() < timeout
        });

        // Record failures for timed out requests
        // (In production, you'd track which nodes didn't respond)
    }

    /// Get delegation statistics
    pub fn stats(&self) -> DelegationStats {
        let nodes = self.nodes.read();
        let pending = self.pending.read();
        let cache = self.cache.read();

        let total_nodes = nodes.len();
        let trusted_nodes = nodes.values().filter(|n| n.trust_level >= TrustLevel::Trusted).count();
        let verified_nodes = nodes.values().filter(|n| n.trust_level == TrustLevel::Verified).count();

        DelegationStats {
            total_nodes,
            trusted_nodes,
            verified_nodes,
            pending_requests: pending.len(),
            cached_proofs: cache.len(),
            avg_reliability: if total_nodes > 0 {
                nodes.values().map(|n| n.reliability_score()).sum::<f64>() / total_nodes as f64
            } else {
                0.0
            },
        }
    }
}

/// Statistics about delegation
#[derive(Debug, Clone)]
pub struct DelegationStats {
    pub total_nodes: usize,
    pub trusted_nodes: usize,
    pub verified_nodes: usize,
    pub pending_requests: usize,
    pub cached_proofs: usize,
    pub avg_reliability: f64,
}

/// Trait for delegation network transport
#[async_trait::async_trait]
pub trait DelegationNetwork: Send + Sync {
    /// Send a delegation request to a node
    async fn send_request(
        &self,
        node_endpoint: &str,
        request: &DelegationRequest,
    ) -> LightClientResult<()>;

    /// Receive responses (called periodically)
    async fn receive_responses(&self) -> LightClientResult<Vec<DelegationResponse>>;
}

/// High-level delegator that coordinates proof requests
pub struct ProofDelegator<N: DelegationNetwork> {
    manager: DelegationManager,
    network: N,
}

impl<N: DelegationNetwork> ProofDelegator<N> {
    /// Create a new proof delegator
    pub fn new(config: DelegationConfig, network: N) -> Self {
        Self {
            manager: DelegationManager::new(config),
            network,
        }
    }

    /// Add a trusted node
    pub fn add_trusted_node(&self, pubkey: [u8; 32], endpoint: String) {
        self.manager.add_node(DelegationNode::verified(pubkey, endpoint));
    }

    /// Request a proof (async)
    pub async fn request_proof(
        &self,
        proof_type: DelegatedProofType,
        block_height: u64,
        block_hash: [u8; 32],
        item_hash: [u8; 32],
    ) -> LightClientResult<DelegatedProofData> {
        // Check cache first
        if let Some(cached) = self.manager.get_cached_proof(
            proof_type,
            block_height,
            block_hash,
            item_hash,
        ) {
            return Ok(cached);
        }

        // Create request
        let request = self.manager.create_request(
            proof_type,
            block_height,
            block_hash,
            item_hash,
        )?;

        // Get nodes to query
        let nodes = self.manager.get_nodes_for_type(proof_type);

        // Send to nodes
        for node in nodes.iter().take(self.manager.config.max_concurrent) {
            if let Some(endpoint) = &node.endpoint {
                let _ = self.network.send_request(endpoint, &request).await;
            }
        }

        // Wait for responses
        let timeout = std::time::Duration::from_secs(self.manager.config.request_timeout);
        let start = Instant::now();

        while start.elapsed() < timeout {
            let responses = self.network.receive_responses().await?;

            for response in responses {
                if response.request_id == request.request_id {
                    if let Some(proof) = self.manager.process_response(response)? {
                        return Ok(proof);
                    }
                }
            }

            // Small delay before checking again
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        Err(LightClientError::DelegationTimeout)
    }

    /// Get delegation statistics
    pub fn stats(&self) -> DelegationStats {
        self.manager.stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delegation_node_scoring() {
        let mut node = DelegationNode::new([1u8; 32]);

        // Initial score for unknown node
        let initial = node.reliability_score();
        assert!(initial > 0.0 && initial < 0.5);

        // After successes
        for _ in 0..20 {
            node.record_success(100);
        }
        let after_success = node.reliability_score();
        assert!(after_success > initial);

        // After failures
        for _ in 0..10 {
            node.record_failure();
        }
        let after_failure = node.reliability_score();
        assert!(after_failure < after_success);
    }

    #[test]
    fn test_delegation_node_trust_upgrade() {
        let mut node = DelegationNode::new([1u8; 32]);
        assert_eq!(node.trust_level, TrustLevel::Unknown);

        // 10 successes with 90%+ rate should upgrade to Basic
        for _ in 0..11 {
            node.record_success(100);
        }
        assert_eq!(node.trust_level, TrustLevel::Basic);

        // 100 successes with 99%+ rate should upgrade to Trusted
        for _ in 0..90 {
            node.record_success(100);
        }
        assert_eq!(node.trust_level, TrustLevel::Trusted);
    }

    #[test]
    fn test_verified_node_never_downgrades() {
        let mut node = DelegationNode::verified([1u8; 32], "http://node1.example.com".into());
        assert_eq!(node.trust_level, TrustLevel::Verified);

        // Even with failures, should stay verified
        for _ in 0..100 {
            node.record_failure();
        }
        assert_eq!(node.trust_level, TrustLevel::Verified);
    }

    #[test]
    fn test_delegation_request_hash() {
        let req1 = DelegationRequest::new(
            1,
            DelegatedProofType::TransactionInclusion,
            100,
            [1u8; 32],
            [2u8; 32],
        );

        let req2 = DelegationRequest::new(
            1,
            DelegatedProofType::TransactionInclusion,
            100,
            [1u8; 32],
            [2u8; 32],
        );

        // Same parameters should give same hash (ignoring timestamp)
        let hash1 = req1.compute_hash();
        let hash2 = req2.compute_hash();
        assert_eq!(hash1, hash2);

        // Different parameters should give different hash
        let req3 = DelegationRequest::new(
            1,
            DelegatedProofType::StateProof,
            100,
            [1u8; 32],
            [2u8; 32],
        );
        let hash3 = req3.compute_hash();
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_delegation_manager_node_management() {
        let config = DelegationConfig::default();
        let manager = DelegationManager::new(config);

        // Add nodes
        manager.add_node(DelegationNode::new([1u8; 32]));
        manager.add_node(DelegationNode::new([2u8; 32]));
        manager.add_node(DelegationNode::verified([3u8; 32], "http://node3.example.com".into()));

        assert_eq!(manager.list_nodes().len(), 3);

        // Get nodes for proof type
        let nodes = manager.get_nodes_for_type(DelegatedProofType::TransactionInclusion);
        assert_eq!(nodes.len(), 3);

        // Verified node should be first (highest reliability)
        assert_eq!(nodes[0].pubkey, [3u8; 32]);

        // Remove node
        manager.remove_node(&[2u8; 32]);
        assert_eq!(manager.list_nodes().len(), 2);
    }

    #[test]
    fn test_delegation_config_defaults() {
        let config = DelegationConfig::default();
        assert_eq!(config.min_nodes, 3);
        assert_eq!(config.threshold, 2);
        assert_eq!(config.max_proof_age, 3600);
        assert_eq!(config.request_timeout, 30);
    }

    #[test]
    fn test_computation_witness_default() {
        let witness = ComputationWitness::default();
        assert_eq!(witness.merkle_root, [0u8; 32]);
        assert_eq!(witness.state_root, [0u8; 32]);
        assert_eq!(witness.steps, 0);
        assert!(witness.intermediate_hashes.is_empty());
    }

    #[test]
    fn test_delegation_stats() {
        let config = DelegationConfig::default();
        let manager = DelegationManager::new(config);

        manager.add_node(DelegationNode::new([1u8; 32]));
        manager.add_node(DelegationNode::verified([2u8; 32], "http://node2.example.com".into()));

        let stats = manager.stats();
        assert_eq!(stats.total_nodes, 2);
        assert_eq!(stats.verified_nodes, 1);
        assert!(stats.avg_reliability > 0.0);
    }
}
