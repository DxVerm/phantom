//! Real Groth16 proving system using arkworks
//!
//! This module provides actual zero-knowledge proof generation and verification
//! using the Groth16 proving system from ark-groth16.

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::PrimeField;
use ark_groth16::{
    Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey,
    prepare_verifying_key,
};
use ark_relations::r1cs::ConstraintSystem;
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};

use crate::errors::NovaError;
use crate::r1cs_circuit::{PhantomR1CSCircuit, CircuitStats};
use crate::types::{TransactionPublicInputs, TransactionWitness};

/// Groth16 proving key for PHANTOM circuits
pub struct Groth16ProvingKey {
    /// The actual proving key
    pk: ProvingKey<Bls12_381>,
}

/// Groth16 verification key for PHANTOM circuits
pub struct Groth16VerifyingKey {
    /// The prepared verifying key for efficient verification
    pvk: PreparedVerifyingKey<Bls12_381>,
    /// Raw verifying key for serialization
    vk: VerifyingKey<Bls12_381>,
}

/// Groth16 proof for a PHANTOM transaction
#[derive(Clone)]
pub struct Groth16Proof {
    /// The actual proof
    proof: Proof<Bls12_381>,
    /// Public inputs used in the proof (stored for debugging/verification)
    #[allow(dead_code)]
    public_inputs: Vec<Fr>,
}

impl Groth16Proof {
    /// Serialize the proof to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, NovaError> {
        let mut bytes = Vec::new();
        self.proof.serialize_compressed(&mut bytes)
            .map_err(|e| NovaError::ProofGenerationFailed(format!("Serialization error: {}", e)))?;
        Ok(bytes)
    }

    /// Deserialize proof from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NovaError> {
        let proof = Proof::<Bls12_381>::deserialize_compressed(bytes)
            .map_err(|e| NovaError::VerificationFailed(format!("Deserialization error: {}", e)))?;
        Ok(Self {
            proof,
            public_inputs: Vec::new(), // Will be set during verification
        })
    }

    /// Get proof size in bytes
    pub fn size(&self) -> usize {
        // Groth16 proof on BLS12-381: ~192 bytes
        // 2 G1 points (48 bytes each) + 1 G2 point (96 bytes)
        192
    }
}

/// Setup the Groth16 proving system
///
/// This generates the proving and verification keys for the PHANTOM circuit.
/// In production, this would be done via a trusted setup ceremony.
pub fn groth16_setup() -> Result<(Groth16ProvingKey, Groth16VerifyingKey), NovaError> {
    // Create the circuit for setup (empty circuit defines the constraint structure)
    let circuit = PhantomR1CSCircuit::new();

    // Use a deterministic RNG for reproducible testing
    // In production, use true randomness from a trusted setup ceremony
    let mut rng = StdRng::seed_from_u64(12345);

    // Generate proving and verifying keys
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(circuit, &mut rng)
        .map_err(|e| NovaError::ProofGenerationFailed(format!("Setup failed: {}", e)))?;

    // Prepare the verifying key for efficient verification
    let pvk = prepare_verifying_key(&vk);

    Ok((
        Groth16ProvingKey { pk },
        Groth16VerifyingKey { pvk, vk },
    ))
}

/// Generate a Groth16 proof for a PHANTOM transaction
pub fn groth16_prove(
    pk: &Groth16ProvingKey,
    public_inputs: TransactionPublicInputs,
    witness: TransactionWitness,
) -> Result<Groth16Proof, NovaError> {
    // Create the circuit with inputs
    let circuit = PhantomR1CSCircuit::with_inputs(public_inputs.clone(), witness);

    // Use deterministic RNG for testing (in production, use fresh randomness)
    let mut rng = StdRng::seed_from_u64(54321);

    // Generate the proof
    let proof = Groth16::<Bls12_381>::prove(&pk.pk, circuit, &mut rng)
        .map_err(|e| NovaError::ProofGenerationFailed(format!("Proving failed: {}", e)))?;

    // Extract public inputs as field elements
    let public_inputs_fe = extract_public_inputs(&public_inputs);

    Ok(Groth16Proof {
        proof,
        public_inputs: public_inputs_fe,
    })
}

/// Verify a Groth16 proof
pub fn groth16_verify(
    vk: &Groth16VerifyingKey,
    proof: &Groth16Proof,
    public_inputs: &TransactionPublicInputs,
) -> Result<bool, NovaError> {
    // Extract public inputs as field elements
    let public_inputs_fe = extract_public_inputs(public_inputs);

    // Verify the proof
    let result = Groth16::<Bls12_381>::verify_with_processed_vk(&vk.pvk, &public_inputs_fe, &proof.proof)
        .map_err(|e| NovaError::VerificationFailed(format!("Verification error: {}", e)))?;

    Ok(result)
}

/// Extract public inputs as field elements
fn extract_public_inputs(pi: &TransactionPublicInputs) -> Vec<Fr> {
    // Convert each 32-byte public input to field elements
    // Using the same conversion as in r1cs_circuit
    let mut result = Vec::new();

    // Add nullifier field elements
    for chunk in pi.nullifier.chunks(31) {
        let mut arr = [0u8; 32];
        arr[..chunk.len()].copy_from_slice(chunk);
        result.push(Fr::from_le_bytes_mod_order(&arr));
    }

    // Add output commitment field elements
    for chunk in pi.output_commitment.chunks(31) {
        let mut arr = [0u8; 32];
        arr[..chunk.len()].copy_from_slice(chunk);
        result.push(Fr::from_le_bytes_mod_order(&arr));
    }

    // Add merkle root field elements
    for chunk in pi.merkle_root.chunks(31) {
        let mut arr = [0u8; 32];
        arr[..chunk.len()].copy_from_slice(chunk);
        result.push(Fr::from_le_bytes_mod_order(&arr));
    }

    result
}

/// Get circuit statistics for the PHANTOM circuit
pub fn get_circuit_stats() -> Result<CircuitStats, NovaError> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    let circuit = PhantomR1CSCircuit::new();

    use ark_relations::r1cs::ConstraintSynthesizer;
    circuit.generate_constraints(cs.clone())
        .map_err(|e| NovaError::InvalidPublicInput(format!("Circuit synthesis failed: {}", e)))?;

    Ok(CircuitStats::from_cs(&cs))
}

/// Serialize verifying key to bytes
impl Groth16VerifyingKey {
    pub fn to_bytes(&self) -> Result<Vec<u8>, NovaError> {
        let mut bytes = Vec::new();
        self.vk.serialize_compressed(&mut bytes)
            .map_err(|e| NovaError::ProofGenerationFailed(format!("VK serialization error: {}", e)))?;
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NovaError> {
        let vk = VerifyingKey::<Bls12_381>::deserialize_compressed(bytes)
            .map_err(|e| NovaError::VerificationFailed(format!("VK deserialization error: {}", e)))?;
        let pvk = prepare_verifying_key(&vk);
        Ok(Self { pvk, vk })
    }
}

/// Serialize proving key to bytes
impl Groth16ProvingKey {
    pub fn to_bytes(&self) -> Result<Vec<u8>, NovaError> {
        let mut bytes = Vec::new();
        self.pk.serialize_compressed(&mut bytes)
            .map_err(|e| NovaError::ProofGenerationFailed(format!("PK serialization error: {}", e)))?;
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NovaError> {
        let pk = ProvingKey::<Bls12_381>::deserialize_compressed(bytes)
            .map_err(|e| NovaError::ProofGenerationFailed(format!("PK deserialization error: {}", e)))?;
        Ok(Self { pk })
    }
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
    fn test_groth16_setup() {
        let result = groth16_setup();
        assert!(result.is_ok(), "Setup should succeed");

        let (pk, vk) = result.unwrap();

        // Test serialization
        let pk_bytes = pk.to_bytes().expect("PK serialization should work");
        let vk_bytes = vk.to_bytes().expect("VK serialization should work");

        assert!(!pk_bytes.is_empty());
        assert!(!vk_bytes.is_empty());
    }

    #[test]
    fn test_groth16_prove_and_verify() {
        let (pk, vk) = groth16_setup().expect("Setup should succeed");
        let (public_inputs, witness) = create_test_inputs();

        // Generate proof
        let proof = groth16_prove(&pk, public_inputs.clone(), witness)
            .expect("Proving should succeed");

        // Verify proof
        let result = groth16_verify(&vk, &proof, &public_inputs)
            .expect("Verification should not error");

        assert!(result, "Valid proof should verify");
    }

    #[test]
    fn test_proof_serialization() {
        let (pk, _vk) = groth16_setup().expect("Setup should succeed");
        let (public_inputs, witness) = create_test_inputs();

        let proof = groth16_prove(&pk, public_inputs, witness)
            .expect("Proving should succeed");

        let bytes = proof.to_bytes().expect("Serialization should work");
        assert!(!bytes.is_empty());

        // Groth16 proof is ~192 bytes on BLS12-381
        assert!(bytes.len() < 250);
    }

    #[test]
    fn test_circuit_stats() {
        let stats = get_circuit_stats().expect("Stats should work");
        println!("Circuit stats: {:?}", stats);

        // Empty circuit should have minimal constraints
        assert!(stats.num_public_inputs > 0);
    }

    #[test]
    fn test_invalid_proof_fails() {
        let (pk, vk) = groth16_setup().expect("Setup should succeed");
        let (public_inputs, witness) = create_test_inputs();

        let proof = groth16_prove(&pk, public_inputs.clone(), witness)
            .expect("Proving should succeed");

        // Try to verify with different public inputs
        let mut wrong_inputs = public_inputs.clone();
        wrong_inputs.nullifier = [99u8; 32];

        let result = groth16_verify(&vk, &proof, &wrong_inputs)
            .expect("Verification should not error");

        assert!(!result, "Proof with wrong inputs should not verify");
    }
}
