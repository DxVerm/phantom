//! Attestation types for CWA consensus

use serde::{Deserialize, Serialize};
use crate::{ThresholdSignature, CWAError, CWAResult};

/// An attestation from a single witness
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attestation {
    /// Witness validator ID
    pub witness_id: [u8; 32],
    /// Hash of the state update being attested
    pub update_hash: [u8; 32],
    /// Witness signature (Dilithium)
    pub signature: Vec<u8>,
    /// Timestamp of attestation
    pub timestamp: u64,
    /// VRF proof that this witness was selected
    pub vrf_proof: Vec<u8>,
    /// Round number
    pub round: u64,
}

impl Attestation {
    /// Create a new attestation
    pub fn new(
        witness_id: [u8; 32],
        update_hash: [u8; 32],
        signature: Vec<u8>,
        vrf_proof: Vec<u8>,
        round: u64,
    ) -> Self {
        Self {
            witness_id,
            update_hash,
            signature,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            vrf_proof,
            round,
        }
    }

    /// Verify the attestation signature
    pub fn verify(&self, public_key: &[u8]) -> bool {
        // In production, use Dilithium verify
        // For now, check basic structure
        !self.signature.is_empty() && !public_key.is_empty()
    }

    /// Get attestation ID (hash of key fields)
    pub fn id(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.witness_id);
        hasher.update(&self.update_hash);
        hasher.update(&self.round.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Check if this attestation is for a specific update
    pub fn attests_to(&self, update_hash: &[u8; 32]) -> bool {
        &self.update_hash == update_hash
    }
}

/// Aggregated attestation from multiple witnesses
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatedAttestation {
    /// Hash of the state update
    pub update_hash: [u8; 32],
    /// Threshold signature from all witnesses
    pub threshold_signature: ThresholdSignature,
    /// Individual attestations (for auditability)
    pub attestations: Vec<AttestationSummary>,
    /// Round number
    pub round: u64,
    /// Timestamp of aggregation
    pub aggregated_at: u64,
    /// Merkle root of all attestations
    pub attestation_root: [u8; 32],
}

/// Summary of an individual attestation (for storage efficiency)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationSummary {
    /// Witness ID
    pub witness_id: [u8; 32],
    /// Signature hash (not full signature)
    pub signature_hash: [u8; 32],
    /// Timestamp
    pub timestamp: u64,
}

impl AggregatedAttestation {
    /// Create from individual attestations
    pub fn aggregate(
        update_hash: [u8; 32],
        attestations: &[Attestation],
        threshold_signature: ThresholdSignature,
        round: u64,
    ) -> CWAResult<Self> {
        if attestations.is_empty() {
            return Err(CWAError::InvalidAttestation("No attestations provided".into()));
        }

        // Verify all attestations are for the same update
        for att in attestations {
            if att.update_hash != update_hash {
                return Err(CWAError::InvalidAttestation(
                    "Attestation update hash mismatch".into()
                ));
            }
        }

        // Create summaries
        let summaries: Vec<AttestationSummary> = attestations
            .iter()
            .map(|a| AttestationSummary {
                witness_id: a.witness_id,
                signature_hash: blake3::hash(&a.signature).into(),
                timestamp: a.timestamp,
            })
            .collect();

        // Compute Merkle root of attestations
        let attestation_root = Self::compute_merkle_root(&summaries);

        Ok(Self {
            update_hash,
            threshold_signature,
            attestations: summaries,
            round,
            aggregated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            attestation_root,
        })
    }

    /// Compute Merkle root of attestation summaries
    fn compute_merkle_root(summaries: &[AttestationSummary]) -> [u8; 32] {
        if summaries.is_empty() {
            return [0u8; 32];
        }

        let mut hashes: Vec<[u8; 32]> = summaries
            .iter()
            .map(|s| {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&s.witness_id);
                hasher.update(&s.signature_hash);
                hasher.update(&s.timestamp.to_le_bytes());
                *hasher.finalize().as_bytes()
            })
            .collect();

        // Build Merkle tree
        while hashes.len() > 1 {
            let mut new_level = Vec::new();
            for chunk in hashes.chunks(2) {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&chunk[0]);
                if chunk.len() > 1 {
                    hasher.update(&chunk[1]);
                } else {
                    hasher.update(&chunk[0]); // Duplicate for odd count
                }
                new_level.push(*hasher.finalize().as_bytes());
            }
            hashes = new_level;
        }

        hashes[0]
    }

    /// Verify the aggregated attestation
    pub fn verify(&self, min_attestations: usize) -> bool {
        // Check minimum attestations
        if self.attestations.len() < min_attestations {
            return false;
        }

        // Verify threshold signature has enough signers
        if self.threshold_signature.signer_count() < min_attestations {
            return false;
        }

        // Verify Merkle root
        let computed_root = Self::compute_merkle_root(&self.attestations);
        if computed_root != self.attestation_root {
            return false;
        }

        true
    }

    /// Get attestation count
    pub fn attestation_count(&self) -> usize {
        self.attestations.len()
    }

    /// Check if a specific validator attested
    pub fn attested_by(&self, validator_id: &[u8; 32]) -> bool {
        self.attestations.iter().any(|a| &a.witness_id == validator_id)
    }

    /// Get all attesting validator IDs
    pub fn attesting_validators(&self) -> Vec<[u8; 32]> {
        self.attestations.iter().map(|a| a.witness_id).collect()
    }
}

/// Attestation collection state
#[derive(Clone, Debug)]
pub struct AttestationCollector {
    /// Update being attested
    pub update_hash: [u8; 32],
    /// Round number
    pub round: u64,
    /// Collected attestations
    attestations: Vec<Attestation>,
    /// Required threshold
    threshold: usize,
    /// Deadline for collection
    deadline: u64,
}

impl AttestationCollector {
    /// Create a new collector
    pub fn new(update_hash: [u8; 32], round: u64, threshold: usize, timeout_ms: u64) -> Self {
        let deadline = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64 + timeout_ms;

        Self {
            update_hash,
            round,
            attestations: Vec::new(),
            threshold,
            deadline,
        }
    }

    /// Add an attestation
    pub fn add(&mut self, attestation: Attestation) -> CWAResult<()> {
        // Verify attestation is for this update
        if attestation.update_hash != self.update_hash {
            return Err(CWAError::InvalidAttestation("Update hash mismatch".into()));
        }

        // Check for duplicate
        if self.attestations.iter().any(|a| a.witness_id == attestation.witness_id) {
            return Err(CWAError::DoubleAttestation);
        }

        self.attestations.push(attestation);
        Ok(())
    }

    /// Check if threshold is met
    pub fn threshold_met(&self) -> bool {
        self.attestations.len() >= self.threshold
    }

    /// Check if deadline passed
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        now > self.deadline
    }

    /// Get collected attestations
    pub fn attestations(&self) -> &[Attestation] {
        &self.attestations
    }

    /// Get attestation count
    pub fn count(&self) -> usize {
        self.attestations.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attestation_creation() {
        let att = Attestation::new(
            [1u8; 32],
            [2u8; 32],
            vec![0u8; 64],
            vec![0u8; 80],
            1,
        );

        assert!(att.attests_to(&[2u8; 32]));
        assert!(!att.attests_to(&[3u8; 32]));
    }

    #[test]
    fn test_collector() {
        let mut collector = AttestationCollector::new(
            [1u8; 32],
            1,
            3,
            5000,
        );

        for i in 0..3 {
            let mut witness_id = [0u8; 32];
            witness_id[0] = i;

            let att = Attestation::new(
                witness_id,
                [1u8; 32],
                vec![0u8; 64],
                vec![0u8; 80],
                1,
            );

            collector.add(att).unwrap();
        }

        assert!(collector.threshold_met());
        assert_eq!(collector.count(), 3);
    }

    #[test]
    fn test_double_attestation() {
        let mut collector = AttestationCollector::new([1u8; 32], 1, 3, 5000);

        let att = Attestation::new([1u8; 32], [1u8; 32], vec![], vec![0u8; 80], 1);
        collector.add(att.clone()).unwrap();

        // Try to add same witness again
        let result = collector.add(att);
        assert!(matches!(result, Err(CWAError::DoubleAttestation)));
    }
}
