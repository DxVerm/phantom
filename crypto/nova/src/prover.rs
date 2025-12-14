//! Nova proof generation

use crate::circuit::PhantomCircuit;
use crate::errors::NovaError;
use crate::folding::FoldingScheme;
use crate::types::{NovaProof, NovaProvingKey, TransactionPublicInputs, TransactionWitness};

/// Nova prover for generating transaction proofs
pub struct NovaProver {
    /// Proving key
    proving_key: NovaProvingKey,
    /// Folding scheme for batch proving
    folding_scheme: FoldingScheme,
    /// Enable parallel proving
    parallel: bool,
}

impl NovaProver {
    /// Create a new prover with the given proving key
    pub fn new(proving_key: NovaProvingKey, max_fold_count: usize) -> Self {
        Self {
            proving_key,
            folding_scheme: FoldingScheme::new(max_fold_count),
            parallel: true,
        }
    }

    /// Enable or disable parallel proving
    pub fn set_parallel(&mut self, parallel: bool) {
        self.parallel = parallel;
    }

    /// Generate a proof for a single transaction
    pub fn prove(
        &mut self,
        public_inputs: TransactionPublicInputs,
        witness: TransactionWitness,
    ) -> Result<NovaProof, NovaError> {
        // Build circuit
        let circuit = PhantomCircuit::new()
            .with_public_inputs(public_inputs.clone())
            .with_witness(witness);

        // Verify circuit satisfiability
        circuit.synthesize()?;

        // Fold into accumulator
        self.folding_scheme.fold(&circuit)?;

        // Compress to get proof
        let proof = self.folding_scheme.compress()?;

        // Reset for next proof
        self.folding_scheme.reset();

        Ok(proof)
    }

    /// Generate a batch proof for multiple transactions
    pub fn prove_batch(
        &mut self,
        transactions: Vec<(TransactionPublicInputs, TransactionWitness)>,
    ) -> Result<NovaProof, NovaError> {
        if transactions.is_empty() {
            return Err(NovaError::InvalidPublicInput("Empty transaction batch".into()));
        }

        // Build and fold all circuits
        for (public_inputs, witness) in transactions {
            let circuit = PhantomCircuit::new()
                .with_public_inputs(public_inputs)
                .with_witness(witness);

            self.folding_scheme.fold(&circuit)?;
        }

        // Compress accumulated proofs
        let proof = self.folding_scheme.compress()?;
        self.folding_scheme.reset();

        Ok(proof)
    }

    /// Get the proving key
    pub fn proving_key(&self) -> &NovaProvingKey {
        &self.proving_key
    }

    /// Estimate proving time for a batch of transactions (in milliseconds)
    pub fn estimate_proving_time(&self, batch_size: usize) -> u64 {
        // Based on Nova benchmarks:
        // - Single proof: ~170ms
        // - Each additional fold: ~50ms
        // - Compression: ~100ms
        let base_time = 170;
        let fold_time = (batch_size.saturating_sub(1) as u64) * 50;
        let compression_time = 100;

        if self.parallel {
            // Parallel proving reduces fold time
            base_time + (fold_time / 4) + compression_time
        } else {
            base_time + fold_time + compression_time
        }
    }
}

/// Setup function to generate proving and verification keys
pub fn setup() -> Result<(NovaProvingKey, crate::types::NovaVerificationKey), NovaError> {
    // In real implementation: run trusted setup or use universal SRS

    let circuit = PhantomCircuit::new();
    let circuit_hash = compute_circuit_hash(&circuit);

    let pk = NovaProvingKey {
        pk_bytes: vec![0u8; 1024], // Placeholder
        circuit_hash,
    };

    let vk = crate::types::NovaVerificationKey {
        vk_bytes: vec![0u8; 256], // Placeholder
        circuit_hash,
    };

    Ok((pk, vk))
}

/// Compute a hash of the circuit structure for compatibility checking
fn compute_circuit_hash(circuit: &PhantomCircuit) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&circuit.num_constraints().to_le_bytes());
    hasher.update(b"phantom_circuit_v1");
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_setup() {
        let result = setup();
        assert!(result.is_ok());
        let (pk, vk) = result.unwrap();
        assert_eq!(pk.circuit_hash, vk.circuit_hash);
    }

    #[test]
    fn test_single_proof() {
        let (pk, _vk) = setup().unwrap();
        let mut prover = NovaProver::new(pk, 10);

        let (public_inputs, witness) = create_test_inputs();
        let proof = prover.prove(public_inputs, witness);

        assert!(proof.is_ok());
    }

    #[test]
    fn test_batch_proof() {
        let (pk, _vk) = setup().unwrap();
        let mut prover = NovaProver::new(pk, 10);

        let transactions: Vec<_> = (0..5)
            .map(|_| create_test_inputs())
            .collect();

        let proof = prover.prove_batch(transactions);
        assert!(proof.is_ok());
        assert_eq!(proof.unwrap().num_steps, 5);
    }

    #[test]
    fn test_proving_time_estimate() {
        let (pk, _vk) = setup().unwrap();
        let prover = NovaProver::new(pk, 10);

        let single_time = prover.estimate_proving_time(1);
        let batch_time = prover.estimate_proving_time(10);

        assert!(single_time > 0);
        assert!(batch_time > single_time);
    }
}
