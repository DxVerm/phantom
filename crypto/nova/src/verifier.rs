//! Nova proof verification

use crate::errors::NovaError;
use crate::types::{NovaProof, NovaVerificationKey, TransactionPublicInputs};

/// Nova verifier for validating transaction proofs
pub struct NovaVerifier {
    /// Verification key
    verification_key: NovaVerificationKey,
}

impl NovaVerifier {
    /// Create a new verifier with the given verification key
    pub fn new(verification_key: NovaVerificationKey) -> Self {
        Self { verification_key }
    }

    /// Verify a single proof
    pub fn verify(
        &self,
        proof: &NovaProof,
        public_inputs: &TransactionPublicInputs,
    ) -> Result<bool, NovaError> {
        // Check public inputs hash matches
        let computed_hash = public_inputs.hash();
        if computed_hash != proof.public_inputs_hash {
            return Err(NovaError::VerificationFailed(
                "Public inputs hash mismatch".into()
            ));
        }

        // Verify proof structure
        if proof.proof_bytes.is_empty() {
            return Err(NovaError::VerificationFailed(
                "Empty proof".into()
            ));
        }

        // In real implementation: verify the SNARK proof
        // This involves:
        // 1. Deserializing the proof
        // 2. Checking the verification equation
        // 3. Verifying the folding correctness

        // Placeholder verification (always succeeds for valid structure)
        Ok(true)
    }

    /// Verify a batch proof with multiple public inputs
    pub fn verify_batch(
        &self,
        proof: &NovaProof,
        public_inputs_list: &[TransactionPublicInputs],
    ) -> Result<bool, NovaError> {
        if public_inputs_list.is_empty() {
            return Err(NovaError::VerificationFailed(
                "Empty public inputs list".into()
            ));
        }

        // Check that number of steps matches
        if proof.num_steps != public_inputs_list.len() {
            return Err(NovaError::VerificationFailed(
                format!(
                    "Proof steps {} doesn't match inputs {}",
                    proof.num_steps,
                    public_inputs_list.len()
                )
            ));
        }

        // Compute combined public inputs hash
        let combined_hash = self.compute_combined_hash(public_inputs_list);
        if combined_hash != proof.public_inputs_hash {
            return Err(NovaError::VerificationFailed(
                "Combined public inputs hash mismatch".into()
            ));
        }

        // In real implementation: verify the batch proof
        Ok(true)
    }

    /// Get the verification key
    pub fn verification_key(&self) -> &NovaVerificationKey {
        &self.verification_key
    }

    /// Estimate verification time (in milliseconds)
    pub fn estimate_verification_time(&self, _proof: &NovaProof) -> u64 {
        // Nova verification is O(1) regardless of proof size
        // Typical verification: ~10ms
        10
    }

    /// Compute combined hash for batch verification
    /// This must match the folding scheme's public_inputs_hash computation
    fn compute_combined_hash(&self, public_inputs_list: &[TransactionPublicInputs]) -> [u8; 32] {
        if public_inputs_list.is_empty() {
            return [0u8; 32];
        }

        // First hash is just the first public input hash
        let mut combined = public_inputs_list[0].hash();

        // Each subsequent hash is: hash(combined || new_hash)
        // This matches the folding scheme's computation
        for inputs in public_inputs_list.iter().skip(1) {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&combined);
            hasher.update(&inputs.hash());
            combined = *hasher.finalize().as_bytes();
        }

        combined
    }
}

/// Batch verifier for parallel verification
pub struct BatchVerifier {
    verifier: NovaVerifier,
    num_threads: usize,
}

impl BatchVerifier {
    /// Create a new batch verifier
    pub fn new(verification_key: NovaVerificationKey, num_threads: usize) -> Self {
        Self {
            verifier: NovaVerifier::new(verification_key),
            num_threads: num_threads.max(1),
        }
    }

    /// Verify multiple proofs in parallel
    pub fn verify_parallel(
        &self,
        proofs_and_inputs: Vec<(NovaProof, TransactionPublicInputs)>,
    ) -> Result<Vec<bool>, NovaError> {
        // In real implementation: use rayon for parallel verification
        // For now, sequential verification
        proofs_and_inputs
            .iter()
            .map(|(proof, inputs)| self.verifier.verify(proof, inputs))
            .collect()
    }

    /// Get estimated throughput (verifications per second)
    pub fn estimated_throughput(&self) -> u64 {
        // Each verification takes ~10ms
        // With parallelism: 100 * num_threads verifications per second
        100 * self.num_threads as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::{setup, NovaProver};
    use crate::types::TransactionWitness;

    fn create_test_inputs() -> (TransactionPublicInputs, TransactionWitness) {
        let public_inputs = TransactionPublicInputs {
            nullifier: [1u8; 32],
            output_commitment: [2u8; 32],
            merkle_root: [3u8; 32],
            encrypted_amount_hash: [4u8; 32],
        };

        let witness = TransactionWitness {
            secret_key: [5u8; 32],
            input_value: 1000,
            output_value: 900,
            merkle_path: vec![[6u8; 32]; 32],
            merkle_indices: vec![false; 32],
            output_randomness: [7u8; 32],
        };

        (public_inputs, witness)
    }

    #[test]
    fn test_verifier_creation() {
        let (_pk, vk) = setup().unwrap();
        let verifier = NovaVerifier::new(vk);
        assert!(!verifier.verification_key().vk_bytes.is_empty());
    }

    #[test]
    fn test_proof_verification() {
        let (pk, vk) = setup().unwrap();
        let mut prover = NovaProver::new(pk, 10);
        let verifier = NovaVerifier::new(vk);

        let (public_inputs, witness) = create_test_inputs();
        let proof = prover.prove(public_inputs.clone(), witness).unwrap();

        let result = verifier.verify(&proof, &public_inputs);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_batch_verification() {
        let (pk, vk) = setup().unwrap();
        let mut prover = NovaProver::new(pk, 10);
        let verifier = NovaVerifier::new(vk);

        let transactions: Vec<_> = (0..3)
            .map(|_| create_test_inputs())
            .collect();

        let public_inputs_list: Vec<_> = transactions.iter()
            .map(|(pi, _)| pi.clone())
            .collect();

        let proof = prover.prove_batch(transactions).unwrap();
        let result = verifier.verify_batch(&proof, &public_inputs_list);

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_verification_time_estimate() {
        let (_pk, vk) = setup().unwrap();
        let verifier = NovaVerifier::new(vk);

        let proof = NovaProof::new(vec![0u8; 256], 1, [0u8; 32]);
        let time = verifier.estimate_verification_time(&proof);

        assert_eq!(time, 10); // O(1) verification
    }

    #[test]
    fn test_batch_verifier_throughput() {
        let (_pk, vk) = setup().unwrap();
        let batch_verifier = BatchVerifier::new(vk, 4);

        let throughput = batch_verifier.estimated_throughput();
        assert_eq!(throughput, 400); // 100 * 4 threads
    }
}
