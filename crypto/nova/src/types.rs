//! Core types for Nova ZKP system

use serde::{Deserialize, Serialize};

/// A Nova proof that can be verified
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NovaProof {
    /// Compressed proof bytes
    pub proof_bytes: Vec<u8>,
    /// Number of folding steps
    pub num_steps: usize,
    /// Public inputs hash
    pub public_inputs_hash: [u8; 32],
}

/// Public inputs for a PHANTOM transaction proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionPublicInputs {
    /// Nullifier (prevents double-spend)
    pub nullifier: [u8; 32],
    /// Output commitment
    pub output_commitment: [u8; 32],
    /// Merkle root of valid commitments
    pub merkle_root: [u8; 32],
    /// Encrypted amount (FHE ciphertext reference)
    pub encrypted_amount_hash: [u8; 32],
}

/// Witness data for proving transaction validity
#[derive(Clone, Debug)]
pub struct TransactionWitness {
    /// Secret key for nullifier derivation
    pub secret_key: [u8; 32],
    /// Input note value
    pub input_value: u64,
    /// Output note value
    pub output_value: u64,
    /// Merkle path for input commitment
    pub merkle_path: Vec<[u8; 32]>,
    /// Merkle path indices
    pub merkle_indices: Vec<bool>,
    /// Randomness for output commitment
    pub output_randomness: [u8; 32],
}

/// Verification key for Nova proofs
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NovaVerificationKey {
    /// Serialized verification key
    pub vk_bytes: Vec<u8>,
    /// Circuit hash for compatibility checking
    pub circuit_hash: [u8; 32],
}

/// Proving key for Nova proofs
#[derive(Clone, Debug)]
pub struct NovaProvingKey {
    /// Serialized proving key
    pub pk_bytes: Vec<u8>,
    /// Circuit hash for compatibility checking
    pub circuit_hash: [u8; 32],
}

impl NovaProof {
    /// Create a new proof
    pub fn new(proof_bytes: Vec<u8>, num_steps: usize, public_inputs_hash: [u8; 32]) -> Self {
        Self {
            proof_bytes,
            num_steps,
            public_inputs_hash,
        }
    }

    /// Get proof size in bytes
    pub fn size(&self) -> usize {
        self.proof_bytes.len()
    }
}

impl TransactionPublicInputs {
    /// Hash the public inputs for binding
    pub fn hash(&self) -> [u8; 32] {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(&self.nullifier);
        hasher.update(&self.output_commitment);
        hasher.update(&self.merkle_root);
        hasher.update(&self.encrypted_amount_hash);
        *hasher.finalize().as_bytes()
    }
}
