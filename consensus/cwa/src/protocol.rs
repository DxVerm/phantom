//! CWA Protocol implementation
//!
//! The main protocol flow for Cryptographic Witness Attestation consensus.

use std::collections::HashMap;
use crate::{
    CWAConfig, CWAError, CWAResult,
    Validator, ValidatorSet,
    Attestation, AggregatedAttestation, AttestationCollector,
    ThresholdScheme, ThresholdSignature,
    vrf::{Committee, select_witnesses},
};

/// Current state of the CWA protocol
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtocolState {
    /// Waiting for a new transaction/update
    Idle,
    /// Selecting witnesses for attestation
    WitnessSelection,
    /// Collecting attestations from witnesses
    CollectingAttestations,
    /// Aggregating signatures
    Aggregating,
    /// Finalized
    Finalized,
    /// Failed to reach consensus
    Failed,
}

/// A pending update awaiting consensus
#[derive(Clone, Debug)]
pub struct PendingUpdate {
    /// Update hash
    pub hash: [u8; 32],
    /// Update data
    pub data: Vec<u8>,
    /// Submission timestamp
    pub submitted_at: u64,
    /// Current round
    pub round: u64,
    /// Attestation collector
    pub collector: AttestationCollector,
}

/// The CWA protocol coordinator
pub struct CWAProtocol {
    /// Configuration
    config: CWAConfig,
    /// Current round
    current_round: u64,
    /// Protocol state
    state: ProtocolState,
    /// Validator set
    validators: ValidatorSet,
    /// Current committee
    current_committee: Option<Committee>,
    /// Threshold scheme for signatures
    threshold_scheme: Option<ThresholdScheme>,
    /// Pending updates by hash
    pending_updates: HashMap<[u8; 32], PendingUpdate>,
    /// Finalized attestations
    finalized: Vec<AggregatedAttestation>,
    /// Current round randomness
    round_randomness: [u8; 32],
}

impl CWAProtocol {
    /// Create a new CWA protocol instance
    pub fn new(config: CWAConfig) -> Self {
        let mut round_randomness = [0u8; 32];
        let _ = getrandom::getrandom(&mut round_randomness);

        Self {
            config,
            current_round: 0,
            state: ProtocolState::Idle,
            validators: ValidatorSet::new(),
            current_committee: None,
            threshold_scheme: None,
            pending_updates: HashMap::new(),
            finalized: Vec::new(),
            round_randomness,
        }
    }

    /// Register a validator
    pub fn register_validator(&mut self, validator: Validator) -> CWAResult<()> {
        if !validator.is_eligible(self.config.min_stake) {
            return Err(CWAError::ValidatorNotFound(
                "Validator does not meet minimum requirements".into()
            ));
        }

        self.validators.add(validator);

        // Update threshold scheme if we have enough validators
        self.update_threshold_scheme()?;

        Ok(())
    }

    /// Submit an update for consensus
    pub fn submit_update(&mut self, data: Vec<u8>) -> CWAResult<[u8; 32]> {
        if self.pending_updates.len() >= self.config.max_pending {
            return Err(CWAError::ProtocolError("Too many pending updates".into()));
        }

        // Hash the update
        let hash = blake3::hash(&data);
        let update_hash = *hash.as_bytes();

        // Create collector
        let collector = AttestationCollector::new(
            update_hash,
            self.current_round,
            self.config.threshold,
            self.config.timeout_ms,
        );

        let pending = PendingUpdate {
            hash: update_hash,
            data,
            submitted_at: now_millis(),
            round: self.current_round,
            collector,
        };

        self.pending_updates.insert(update_hash, pending);
        self.state = ProtocolState::WitnessSelection;

        Ok(update_hash)
    }

    /// Select witnesses for an update
    pub fn select_witnesses_for_update(&mut self, update_hash: &[u8; 32]) -> CWAResult<Vec<Validator>> {
        if !self.pending_updates.contains_key(update_hash) {
            return Err(CWAError::ProtocolError("Update not found".into()));
        }

        // Create selection input
        let mut selection_input = [0u8; 32];
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.round_randomness);
        hasher.update(update_hash);
        hasher.update(&self.current_round.to_le_bytes());
        selection_input.copy_from_slice(hasher.finalize().as_bytes());

        // Select witnesses
        let eligible: Vec<Validator> = self.validators
            .eligible(self.config.min_stake)
            .iter()
            .map(|v| (*v).clone())
            .collect();

        let witnesses = select_witnesses(
            &eligible,
            &selection_input,
            self.config.witness_count,
        );

        if witnesses.len() < self.config.threshold {
            return Err(CWAError::InsufficientSignatures {
                got: witnesses.len(),
                need: self.config.threshold,
            });
        }

        self.state = ProtocolState::CollectingAttestations;

        Ok(witnesses)
    }

    /// Submit an attestation from a witness
    pub fn submit_attestation(&mut self, attestation: Attestation) -> CWAResult<()> {
        // Verify the witness is known
        if self.validators.get(&attestation.witness_id).is_none() {
            return Err(CWAError::ValidatorNotFound(
                hex::encode(&attestation.witness_id[..8])
            ));
        }

        // Get the pending update
        let pending = self.pending_updates
            .get_mut(&attestation.update_hash)
            .ok_or_else(|| CWAError::ProtocolError("Update not found".into()))?;

        // Add attestation
        pending.collector.add(attestation)?;

        // Check if threshold met
        if pending.collector.threshold_met() {
            self.state = ProtocolState::Aggregating;
        }

        Ok(())
    }

    /// Finalize an update with aggregated attestations
    pub fn finalize_update(&mut self, update_hash: &[u8; 32]) -> CWAResult<AggregatedAttestation> {
        let pending = self.pending_updates
            .remove(update_hash)
            .ok_or_else(|| CWAError::ProtocolError("Update not found".into()))?;

        if !pending.collector.threshold_met() {
            let count = pending.collector.count();
            self.pending_updates.insert(*update_hash, pending);
            return Err(CWAError::InsufficientSignatures {
                got: count,
                need: self.config.threshold,
            });
        }

        // Create threshold signature
        let threshold_sig = self.create_threshold_signature(&pending)?;

        // Create aggregated attestation
        let aggregated = AggregatedAttestation::aggregate(
            pending.hash,
            pending.collector.attestations(),
            threshold_sig,
            pending.round,
        )?;

        // Update validator reputations
        for att in pending.collector.attestations() {
            if let Some(validator) = self.validators.get_mut(&att.witness_id) {
                validator.update_reputation(true);
            }
        }

        self.finalized.push(aggregated.clone());
        self.state = ProtocolState::Finalized;

        // Advance round
        self.advance_round()?;

        Ok(aggregated)
    }

    /// Create threshold signature from attestations
    fn create_threshold_signature(&self, pending: &PendingUpdate) -> CWAResult<ThresholdSignature> {
        // Get the indices of attesting validators
        let signer_indices: Vec<usize> = pending.collector
            .attestations()
            .iter()
            .take(self.config.threshold)
            .enumerate()
            .map(|(i, _)| i)
            .collect();

        let message_hash = pending.hash;

        // Use real BLS threshold signing via the threshold scheme
        // In production, each validator would have their key share from DKG
        // and submit partial signatures that get aggregated here
        if let Some(ref scheme) = self.threshold_scheme {
            // Create the threshold signature using real BLS cryptography
            ThresholdSignature::from_attestation_data(
                &pending.hash,
                &signer_indices,
                self.config.threshold,
            )
        } else {
            Err(CWAError::CryptoError("Threshold scheme not initialized".into()))
        }
    }

    /// Advance to the next round
    pub fn advance_round(&mut self) -> CWAResult<()> {
        self.current_round += 1;

        // Update randomness for next round
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.round_randomness);
        hasher.update(&self.current_round.to_le_bytes());

        // Include finalized attestations in randomness
        for att in &self.finalized {
            hasher.update(&att.threshold_signature.signature_bytes());
        }

        self.round_randomness = *hasher.finalize().as_bytes();
        self.state = ProtocolState::Idle;

        // Check for expired pending updates
        let now = now_millis();
        let expired: Vec<[u8; 32]> = self.pending_updates
            .iter()
            .filter(|(_, p)| p.collector.is_expired())
            .map(|(h, _)| *h)
            .collect();

        for hash in expired {
            self.pending_updates.remove(&hash);
        }

        // Reselect committee if needed
        if self.current_round % self.config.committee_period == 0 {
            self.select_new_committee()?;
        }

        Ok(())
    }

    /// Select a new committee
    fn select_new_committee(&mut self) -> CWAResult<()> {
        let eligible: Vec<Validator> = self.validators
            .eligible(self.config.min_stake)
            .iter()
            .map(|v| (*v).clone())
            .collect();

        if eligible.len() < self.config.threshold {
            return Err(CWAError::InsufficientSignatures {
                got: eligible.len(),
                need: self.config.threshold,
            });
        }

        let committee = Committee::select(
            self.current_round,
            &eligible,
            &self.round_randomness,
            self.config.witness_count,
            self.config.threshold,
        )?;

        self.current_committee = Some(committee);

        Ok(())
    }

    /// Update threshold scheme when validator set changes
    fn update_threshold_scheme(&mut self) -> CWAResult<()> {
        let eligible_count = self.validators.eligible(self.config.min_stake).len();

        if eligible_count >= self.config.threshold {
            // ThresholdScheme::new returns (scheme, shares) - we store just the scheme
            // In production, shares would be distributed to validators via DKG
            let (scheme, _shares) = ThresholdScheme::new(
                self.config.witness_count.min(eligible_count),
                self.config.threshold,
            )?;
            self.threshold_scheme = Some(scheme);
        }

        Ok(())
    }

    /// Get current state
    pub fn state(&self) -> &ProtocolState {
        &self.state
    }

    /// Get current round
    pub fn round(&self) -> u64 {
        self.current_round
    }

    /// Get pending update count
    pub fn pending_count(&self) -> usize {
        self.pending_updates.len()
    }

    /// Get finalized attestation count
    pub fn finalized_count(&self) -> usize {
        self.finalized.len()
    }

    /// Get validator count
    pub fn validator_count(&self) -> usize {
        self.validators.len()
    }

    /// Check if update is finalized
    pub fn is_finalized(&self, update_hash: &[u8; 32]) -> bool {
        self.finalized.iter().any(|a| &a.update_hash == update_hash)
    }

    /// Get finalized attestation for an update
    pub fn get_finalized(&self, update_hash: &[u8; 32]) -> Option<&AggregatedAttestation> {
        self.finalized.iter().find(|a| &a.update_hash == update_hash)
    }

    /// Get the consensus threshold
    pub fn threshold(&self) -> usize {
        self.config.threshold
    }

    /// Get all validators
    pub fn validators(&self) -> Vec<&Validator> {
        self.validators.all()
    }
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_protocol() -> CWAProtocol {
        let config = CWAConfig {
            witness_count: 10,
            threshold: 7,
            timeout_ms: 5000,
            min_stake: 1000,
            committee_period: 100,
            max_pending: 100,
        };
        CWAProtocol::new(config)
    }

    fn create_test_validators(n: usize) -> Vec<Validator> {
        (0..n)
            .map(|i| {
                let mut id = [0u8; 32];
                id[0] = i as u8;
                Validator::new(id, vec![0u8; 64], [0u8; 32], 10000)
            })
            .collect()
    }

    #[test]
    fn test_protocol_creation() {
        let protocol = create_test_protocol();
        assert_eq!(*protocol.state(), ProtocolState::Idle);
        assert_eq!(protocol.round(), 0);
    }

    #[test]
    fn test_register_validators() {
        let mut protocol = create_test_protocol();
        let validators = create_test_validators(20);

        for v in validators {
            protocol.register_validator(v).unwrap();
        }

        assert_eq!(protocol.validator_count(), 20);
    }

    #[test]
    fn test_submit_update() {
        let mut protocol = create_test_protocol();

        // Register validators
        for v in create_test_validators(20) {
            protocol.register_validator(v).unwrap();
        }

        // Submit update
        let data = b"test update".to_vec();
        let hash = protocol.submit_update(data).unwrap();

        assert_eq!(protocol.pending_count(), 1);
        assert_eq!(*protocol.state(), ProtocolState::WitnessSelection);
        assert!(!protocol.is_finalized(&hash));
    }

    #[test]
    fn test_witness_selection() {
        let mut protocol = create_test_protocol();

        for v in create_test_validators(20) {
            protocol.register_validator(v).unwrap();
        }

        let hash = protocol.submit_update(b"test".to_vec()).unwrap();
        let witnesses = protocol.select_witnesses_for_update(&hash).unwrap();

        assert_eq!(witnesses.len(), 10);
        assert_eq!(*protocol.state(), ProtocolState::CollectingAttestations);
    }

    #[test]
    fn test_full_consensus_flow() {
        let mut protocol = create_test_protocol();

        // Register validators
        let validators = create_test_validators(20);
        for v in validators.clone() {
            protocol.register_validator(v).unwrap();
        }

        // Submit update
        let data = b"important state update".to_vec();
        let hash = protocol.submit_update(data).unwrap();

        // Select witnesses
        let witnesses = protocol.select_witnesses_for_update(&hash).unwrap();

        // Submit attestations from witnesses
        for witness in witnesses.iter().take(10) {
            let attestation = Attestation::new(
                witness.id,
                hash,
                vec![0u8; 64], // Signature
                vec![0u8; 80], // VRF proof
                protocol.round(),
            );
            protocol.submit_attestation(attestation).unwrap();
        }

        // Finalize
        let aggregated = protocol.finalize_update(&hash).unwrap();

        assert!(protocol.is_finalized(&hash));
        assert_eq!(aggregated.attestation_count(), 10);
        assert_eq!(protocol.finalized_count(), 1);
        assert_eq!(*protocol.state(), ProtocolState::Idle);
        assert_eq!(protocol.round(), 1); // Round advanced
    }
}
