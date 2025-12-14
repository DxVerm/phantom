//! Witness Attestation System
//!
//! In CWA consensus, a randomly selected subset of validators (witnesses)
//! attest to the validity of state updates. This provides security without
//! requiring global consensus.

use crate::errors::ESLError;
use crate::state::StateUpdate;
use serde::{Deserialize, Serialize};

/// A single witness in the network
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Witness {
    /// Unique witness ID
    pub id: [u8; 32],
    /// Public key for signature verification
    pub public_key: Vec<u8>,
    /// Stake amount (for weighted selection)
    pub stake: u64,
    /// Reputation score (0-1000)
    pub reputation: u16,
    /// Active status
    pub active: bool,
}

impl Witness {
    /// Create a new witness
    pub fn new(id: [u8; 32], public_key: Vec<u8>, stake: u64) -> Self {
        Self {
            id,
            public_key,
            stake,
            reputation: 500, // Start neutral
            active: true,
        }
    }

    /// Increase reputation (for good behavior)
    pub fn increase_reputation(&mut self, amount: u16) {
        self.reputation = (self.reputation + amount).min(1000);
    }

    /// Decrease reputation (for bad behavior)
    pub fn decrease_reputation(&mut self, amount: u16) {
        self.reputation = self.reputation.saturating_sub(amount);
        if self.reputation < 100 {
            self.active = false; // Automatically deactivate low-rep witnesses
        }
    }

    /// Calculate selection weight (stake * reputation factor)
    pub fn selection_weight(&self) -> u64 {
        if !self.active {
            return 0;
        }
        // Weight = stake * (reputation / 500)
        // At reputation 500: weight = stake
        // At reputation 1000: weight = 2 * stake
        // At reputation 250: weight = 0.5 * stake
        (self.stake as u128 * self.reputation as u128 / 500) as u64
    }
}

/// A set of witnesses selected for attestation
#[derive(Clone, Debug)]
pub struct WitnessSet {
    /// Selected witnesses
    witnesses: Vec<Witness>,
    /// Threshold required for valid attestation
    threshold: usize,
    /// Selection randomness (from VRF)
    selection_seed: [u8; 32],
}

impl WitnessSet {
    /// Create a new witness set
    pub fn new(witnesses: Vec<Witness>, threshold: usize, selection_seed: [u8; 32]) -> Self {
        Self {
            witnesses,
            threshold,
            selection_seed,
        }
    }

    /// Select witnesses using VRF randomness
    pub fn select(
        all_witnesses: &[Witness],
        num_to_select: usize,
        threshold: usize,
        vrf_output: [u8; 32],
    ) -> Result<Self, ESLError> {
        if num_to_select > all_witnesses.len() {
            return Err(ESLError::InsufficientWitnesses {
                got: all_witnesses.len(),
                need: num_to_select,
            });
        }

        if threshold > num_to_select {
            return Err(ESLError::InvalidWitnessAttestation(
                "Threshold cannot exceed set size".into()
            ));
        }

        // Filter active witnesses
        let active: Vec<_> = all_witnesses
            .iter()
            .filter(|w| w.active)
            .cloned()
            .collect();

        if active.len() < num_to_select {
            return Err(ESLError::InsufficientWitnesses {
                got: active.len(),
                need: num_to_select,
            });
        }

        // Weighted random selection
        let total_weight: u64 = active.iter().map(|w| w.selection_weight()).sum();
        let mut selected = Vec::with_capacity(num_to_select);
        let mut remaining = active.clone();

        let mut rng_state = vrf_output;

        while selected.len() < num_to_select && !remaining.is_empty() {
            // Generate random value
            let mut hasher = blake3::Hasher::new();
            hasher.update(&rng_state);
            hasher.update(&[selected.len() as u8]);
            rng_state = *hasher.finalize().as_bytes();

            let random_value = u64::from_le_bytes(rng_state[0..8].try_into().unwrap());
            let target = random_value % total_weight.max(1);

            // Select witness based on weight
            let mut cumulative = 0u64;
            let mut selected_idx = 0;

            for (i, witness) in remaining.iter().enumerate() {
                cumulative += witness.selection_weight();
                if cumulative > target {
                    selected_idx = i;
                    break;
                }
            }

            selected.push(remaining.remove(selected_idx));
        }

        Ok(Self {
            witnesses: selected,
            threshold,
            selection_seed: vrf_output,
        })
    }

    /// Get the witnesses
    pub fn witnesses(&self) -> &[Witness] {
        &self.witnesses
    }

    /// Get the threshold
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Get the number of witnesses
    pub fn len(&self) -> usize {
        self.witnesses.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.witnesses.is_empty()
    }
}

/// An attestation from a single witness
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WitnessAttestation {
    /// Witness ID
    pub witness_id: [u8; 32],
    /// State update hash being attested
    pub update_hash: [u8; 32],
    /// Signature over the attestation
    pub signature: Vec<u8>,
    /// Timestamp
    pub timestamp: u64,
}

impl WitnessAttestation {
    /// Create a new attestation
    pub fn new(witness_id: [u8; 32], update_hash: [u8; 32], signature: Vec<u8>) -> Self {
        Self {
            witness_id,
            update_hash,
            signature,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Create an attestation for a state update
    pub fn attest(witness: &Witness, update: &StateUpdate, sign_fn: impl Fn(&[u8]) -> Vec<u8>) -> Self {
        let update_hash = update.hash();
        let message = Self::attestation_message(&witness.id, &update_hash);
        let signature = sign_fn(&message);

        Self::new(witness.id, update_hash, signature)
    }

    /// Verify the attestation
    pub fn verify(&self, witness: &Witness, verify_fn: impl Fn(&[u8], &[u8], &[u8]) -> bool) -> bool {
        if witness.id != self.witness_id {
            return false;
        }

        let message = Self::attestation_message(&self.witness_id, &self.update_hash);
        verify_fn(&witness.public_key, &message, &self.signature)
    }

    /// Compute the message to sign
    fn attestation_message(witness_id: &[u8; 32], update_hash: &[u8; 32]) -> Vec<u8> {
        let mut message = Vec::with_capacity(72);
        message.extend_from_slice(b"phantom_attestation");
        message.extend_from_slice(witness_id);
        message.extend_from_slice(update_hash);
        message
    }
}

/// Aggregated attestations for a state update
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatedAttestation {
    /// State update hash
    pub update_hash: [u8; 32],
    /// Individual attestations
    pub attestations: Vec<WitnessAttestation>,
    /// Aggregated signature (if supported)
    pub aggregated_signature: Option<Vec<u8>>,
}

impl AggregatedAttestation {
    /// Create a new aggregated attestation
    pub fn new(update_hash: [u8; 32]) -> Self {
        Self {
            update_hash,
            attestations: Vec::new(),
            aggregated_signature: None,
        }
    }

    /// Add an attestation
    pub fn add_attestation(&mut self, attestation: WitnessAttestation) -> Result<(), ESLError> {
        if attestation.update_hash != self.update_hash {
            return Err(ESLError::InvalidWitnessAttestation(
                "Update hash mismatch".into()
            ));
        }

        // Check for duplicate
        if self.attestations.iter().any(|a| a.witness_id == attestation.witness_id) {
            return Err(ESLError::InvalidWitnessAttestation(
                "Duplicate attestation".into()
            ));
        }

        self.attestations.push(attestation);
        Ok(())
    }

    /// Check if threshold is met
    pub fn meets_threshold(&self, threshold: usize) -> bool {
        self.attestations.len() >= threshold
    }

    /// Get the number of attestations
    pub fn count(&self) -> usize {
        self.attestations.len()
    }

    /// Aggregate signatures (for threshold signatures)
    pub fn aggregate_signatures(&mut self, aggregate_fn: impl Fn(&[Vec<u8>]) -> Vec<u8>) {
        let signatures: Vec<_> = self.attestations
            .iter()
            .map(|a| a.signature.clone())
            .collect();

        self.aggregated_signature = Some(aggregate_fn(&signatures));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_witnesses(count: usize) -> Vec<Witness> {
        (0..count)
            .map(|i| {
                let mut id = [0u8; 32];
                id[0] = i as u8;
                Witness::new(id, vec![i as u8; 32], 1000 + i as u64 * 100)
            })
            .collect()
    }

    #[test]
    fn test_witness_creation() {
        let witness = Witness::new([1u8; 32], vec![2u8; 32], 1000);
        assert_eq!(witness.reputation, 500);
        assert!(witness.active);
        assert_eq!(witness.selection_weight(), 1000);
    }

    #[test]
    fn test_witness_reputation() {
        let mut witness = Witness::new([1u8; 32], vec![2u8; 32], 1000);

        witness.increase_reputation(200);
        assert_eq!(witness.reputation, 700);

        witness.decrease_reputation(100);
        assert_eq!(witness.reputation, 600);
    }

    #[test]
    fn test_witness_selection() {
        let witnesses = create_test_witnesses(10);
        let vrf_output = [42u8; 32];

        let set = WitnessSet::select(&witnesses, 5, 3, vrf_output).unwrap();

        assert_eq!(set.len(), 5);
        assert_eq!(set.threshold(), 3);
    }

    #[test]
    fn test_attestation_aggregation() {
        let update_hash = [1u8; 32];
        let mut agg = AggregatedAttestation::new(update_hash);

        for i in 0..3 {
            let mut witness_id = [0u8; 32];
            witness_id[0] = i;
            let attestation = WitnessAttestation::new(
                witness_id,
                update_hash,
                vec![i; 64],
            );
            agg.add_attestation(attestation).unwrap();
        }

        assert_eq!(agg.count(), 3);
        assert!(agg.meets_threshold(3));
        assert!(!agg.meets_threshold(4));
    }

    #[test]
    fn test_duplicate_attestation_rejected() {
        let update_hash = [1u8; 32];
        let mut agg = AggregatedAttestation::new(update_hash);

        let attestation = WitnessAttestation::new([1u8; 32], update_hash, vec![1u8; 64]);

        agg.add_attestation(attestation.clone()).unwrap();
        assert!(agg.add_attestation(attestation).is_err()); // Duplicate!
    }
}
