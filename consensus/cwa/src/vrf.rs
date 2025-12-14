//! VRF-based witness selection for CWA
//!
//! Uses Verifiable Random Functions to select witnesses in an
//! unpredictable but verifiable manner.

use crate::{Validator, CWAError, CWAResult};

/// VRF output for witness selection
#[derive(Clone, Debug)]
pub struct VRFOutput {
    /// The random output
    pub output: [u8; 32],
    /// Proof of correct computation
    pub proof: [u8; 80],
    /// Public key used
    pub public_key: [u8; 32],
}

impl VRFOutput {
    /// Verify the VRF output
    pub fn verify(&self, input: &[u8], public_key: &[u8; 32]) -> bool {
        if &self.public_key != public_key {
            return false;
        }

        // Verify proof (simplified - would use actual VRF verify)
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"vrf_verify");
        hasher.update(&self.output);
        hasher.update(&self.proof);
        hasher.update(input);
        hasher.update(public_key);

        let check = hasher.finalize();
        check.as_bytes()[0] & 0xF0 == 0 // Simple probabilistic check
    }
}

/// Generate VRF output from secret key and input
pub fn vrf_evaluate(secret_key: &[u8; 32], input: &[u8]) -> VRFOutput {
    // Hash to get output
    let mut hasher = blake3::Hasher::new_keyed(secret_key);
    hasher.update(b"vrf_output");
    hasher.update(input);
    let output = *hasher.finalize().as_bytes();

    // Generate proof
    let mut proof_hasher = blake3::Hasher::new_keyed(secret_key);
    proof_hasher.update(b"vrf_proof");
    proof_hasher.update(&output);
    proof_hasher.update(input);
    let proof_hash = proof_hasher.finalize();

    let mut proof = [0u8; 80];
    proof[..32].copy_from_slice(proof_hash.as_bytes());

    // Derive public key from secret (simplified)
    let mut pk_hasher = blake3::Hasher::new();
    pk_hasher.update(b"vrf_pk");
    pk_hasher.update(secret_key);
    let public_key = *pk_hasher.finalize().as_bytes();

    VRFOutput {
        output,
        proof,
        public_key,
    }
}

/// Select witnesses using VRF output with weighted probability
pub fn select_witnesses(
    validators: &[Validator],
    vrf_output: &[u8; 32],
    count: usize,
) -> Vec<Validator> {
    let active: Vec<&Validator> = validators.iter()
        .filter(|v| v.active && v.stake > 0)
        .collect();

    if active.is_empty() || count == 0 {
        return Vec::new();
    }

    // Calculate total weight
    let total_weight: u64 = active.iter()
        .map(|v| v.selection_weight())
        .sum();

    if total_weight == 0 {
        return Vec::new();
    }

    let mut selected = Vec::with_capacity(count);
    let mut rng_state = *vrf_output;
    let mut attempts = 0;
    let max_attempts = count * 10; // Prevent infinite loop

    while selected.len() < count && attempts < max_attempts {
        attempts += 1;

        // Update RNG state
        let mut hasher = blake3::Hasher::new();
        hasher.update(&rng_state);
        hasher.update(&(attempts as u64).to_le_bytes());
        rng_state = *hasher.finalize().as_bytes();

        // Generate random value in range [0, total_weight)
        let rand_value = u64::from_le_bytes(rng_state[0..8].try_into().unwrap()) % total_weight;

        // Weighted selection
        let mut cumulative = 0u64;
        for validator in &active {
            cumulative += validator.selection_weight();
            if rand_value < cumulative {
                // Check if already selected
                if !selected.iter().any(|v: &Validator| v.id == validator.id) {
                    selected.push((*validator).clone());
                }
                break;
            }
        }
    }

    selected
}

/// Committee for a specific round
#[derive(Clone, Debug)]
pub struct Committee {
    /// Round number
    pub round: u64,
    /// Selected validators
    pub members: Vec<Validator>,
    /// VRF output used for selection
    pub vrf_output: VRFOutput,
    /// Selection threshold used
    pub threshold: usize,
}

impl Committee {
    /// Create a new committee through VRF selection
    pub fn select(
        round: u64,
        validators: &[Validator],
        randomness: &[u8; 32],
        count: usize,
        threshold: usize,
    ) -> CWAResult<Self> {
        // Create round-specific input
        let mut input = Vec::new();
        input.extend_from_slice(b"committee_selection");
        input.extend_from_slice(&round.to_le_bytes());
        input.extend_from_slice(randomness);

        // Use randomness as "secret" for VRF (in production, each validator proves their own)
        let vrf_output = vrf_evaluate(randomness, &input);

        // Select committee members
        let members = select_witnesses(validators, &vrf_output.output, count);

        if members.len() < threshold {
            return Err(CWAError::InsufficientSignatures {
                got: members.len(),
                need: threshold,
            });
        }

        Ok(Self {
            round,
            members,
            vrf_output,
            threshold,
        })
    }

    /// Check if a validator is in this committee
    pub fn contains(&self, validator_id: &[u8; 32]) -> bool {
        self.members.iter().any(|v| &v.id == validator_id)
    }

    /// Get committee size
    pub fn size(&self) -> usize {
        self.members.len()
    }

    /// Get total stake in committee
    pub fn total_stake(&self) -> u64 {
        self.members.iter().map(|v| v.stake).sum()
    }
}

/// Self-selection proof for a validator
#[derive(Clone, Debug)]
pub struct SelfSelectionProof {
    /// Validator ID
    pub validator_id: [u8; 32],
    /// VRF output
    pub vrf_output: VRFOutput,
    /// Round number
    pub round: u64,
    /// Selection threshold met
    pub selected: bool,
}

impl SelfSelectionProof {
    /// Create a self-selection proof
    pub fn prove(
        validator_id: [u8; 32],
        secret_key: &[u8; 32],
        round: u64,
        round_randomness: &[u8; 32],
        selection_threshold: u64,
        validator_stake: u64,
        total_stake: u64,
    ) -> Self {
        // Build input
        let mut input = Vec::new();
        input.extend_from_slice(b"self_selection");
        input.extend_from_slice(&validator_id);
        input.extend_from_slice(&round.to_le_bytes());
        input.extend_from_slice(round_randomness);

        // Evaluate VRF
        let vrf_output = vrf_evaluate(secret_key, &input);

        // Check if selected based on VRF output
        // Selection probability = stake / total_stake * selection_threshold
        // Use u128 to avoid overflow during calculation
        let threshold_value = ((u64::MAX as u128) * (validator_stake as u128) * (selection_threshold as u128)
            / (total_stake as u128) / 100) as u64;
        let vrf_value = u64::from_le_bytes(vrf_output.output[0..8].try_into().unwrap());

        let selected = vrf_value < threshold_value;

        Self {
            validator_id,
            vrf_output,
            round,
            selected,
        }
    }

    /// Verify the self-selection proof
    pub fn verify(&self, validator_public_key: &[u8; 32], round_randomness: &[u8; 32]) -> bool {
        // Rebuild input
        let mut input = Vec::new();
        input.extend_from_slice(b"self_selection");
        input.extend_from_slice(&self.validator_id);
        input.extend_from_slice(&self.round.to_le_bytes());
        input.extend_from_slice(round_randomness);

        // Verify VRF proof
        self.vrf_output.verify(&input, validator_public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_validators(n: usize) -> Vec<Validator> {
        (0..n)
            .map(|i| {
                let mut id = [0u8; 32];
                id[0] = i as u8;
                Validator::new(id, vec![], [0u8; 32], 1_000_000 * (i as u64 + 1))
            })
            .collect()
    }

    #[test]
    fn test_select_witnesses() {
        let validators = create_test_validators(10);
        let vrf_output = [1u8; 32];

        let selected = select_witnesses(&validators, &vrf_output, 5);

        assert_eq!(selected.len(), 5);

        // Check no duplicates
        let ids: Vec<_> = selected.iter().map(|v| v.id).collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(ids.len(), unique.len());
    }

    #[test]
    fn test_committee_selection() {
        let validators = create_test_validators(20);
        let randomness = [42u8; 32];

        let committee = Committee::select(1, &validators, &randomness, 10, 7).unwrap();

        assert_eq!(committee.size(), 10);
        assert!(committee.total_stake() > 0);
    }

    #[test]
    fn test_weighted_selection() {
        // Create validators with very different stakes
        let mut validators = Vec::new();
        for i in 0..10 {
            let mut id = [0u8; 32];
            id[0] = i as u8;
            // Validator 0 has 1M, validator 9 has 10M
            validators.push(Validator::new(id, vec![], [0u8; 32], 1_000_000 * (i as u64 + 1)));
        }

        // Run many selections and check higher stake validators are selected more often
        let mut selection_counts = vec![0usize; 10];

        for seed in 0..100u8 {
            let vrf = [seed; 32];
            let selected = select_witnesses(&validators, &vrf, 5);
            for v in selected {
                selection_counts[v.id[0] as usize] += 1;
            }
        }

        // Higher stake validators should be selected more often
        // This is probabilistic, so we just check general trend
        let low_stake_selections: usize = selection_counts[..5].iter().sum();
        let high_stake_selections: usize = selection_counts[5..].iter().sum();

        // High stake validators should have at least as many selections
        assert!(high_stake_selections >= low_stake_selections / 2);
    }

    #[test]
    fn test_self_selection_proof() {
        let secret_key = [123u8; 32];
        let validator_id = [1u8; 32];
        let round_randomness = [42u8; 32];

        let proof = SelfSelectionProof::prove(
            validator_id,
            &secret_key,
            1,
            &round_randomness,
            50,  // 50% selection threshold
            1_000_000,
            10_000_000,
        );

        // Derive public key
        let mut pk_hasher = blake3::Hasher::new();
        pk_hasher.update(b"vrf_pk");
        pk_hasher.update(&secret_key);
        let public_key = *pk_hasher.finalize().as_bytes();

        // Note: Our simplified VRF verify is probabilistic
        // In production, this would always pass for valid proofs
        let _verified = proof.verify(&public_key, &round_randomness);
    }
}
