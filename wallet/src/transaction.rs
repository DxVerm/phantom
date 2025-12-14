//! Private Transaction Building
//!
//! Complete transaction lifecycle with:
//! - Input note selection and nullifier generation
//! - Output creation with stealth addresses
//! - Nova/Groth16 ZK proof generation
//! - Transaction signing with spending keys
//! - Fee handling and change output

use phantom_nova::{
    groth16_prover::{groth16_setup, groth16_prove, groth16_verify, Groth16Proof, Groth16ProvingKey, Groth16VerifyingKey},
    types::{TransactionPublicInputs, TransactionWitness},
    NovaProof, NovaProver, prover::setup as nova_setup,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::note::Note;
use crate::stealth::{OneTimeAddress, SpendingKey, StealthAddress, ViewKey, SpendKey, StealthError};

/// Transaction errors
#[derive(Debug, Error)]
pub enum TransactionError {
    #[error("Insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u64, need: u64 },
    #[error("No inputs specified")]
    NoInputs,
    #[error("No outputs specified")]
    NoOutputs,
    #[error("Input sum {inputs} less than output sum {outputs} plus fee {fee}")]
    UnbalancedTransaction { inputs: u64, outputs: u64, fee: u64 },
    #[error("Proof generation failed: {0}")]
    ProofFailed(String),
    #[error("Stealth address error: {0}")]
    StealthError(#[from] StealthError),
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    #[error("Invalid note: {0}")]
    InvalidNote(String),
    #[error("Merkle proof missing for input")]
    MissingMerkleProof,
}

/// A complete private transaction
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    /// Transaction version
    pub version: u8,
    /// Input nullifiers (reveals which notes are spent)
    pub nullifiers: Vec<[u8; 32]>,
    /// Output commitments (encrypted output notes)
    pub output_commitments: Vec<[u8; 32]>,
    /// One-time addresses for outputs (for recipient to scan)
    pub output_addresses: Vec<OneTimeAddress>,
    /// Encrypted amounts for outputs (FHE ciphertexts)
    pub encrypted_amounts: Vec<Vec<u8>>,
    /// ZK proof of transaction validity
    pub proof: TransactionProof,
    /// Merkle root at time of creation
    pub merkle_root: [u8; 32],
    /// Transaction fee (public for fee market)
    pub fee: u64,
    /// Binding signature (proves control of inputs)
    pub binding_signature: Vec<u8>,
    /// Transaction hash (computed)
    #[serde(skip)]
    tx_hash: Option<[u8; 32]>,
}

/// Transaction proof (either Nova or Groth16)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TransactionProof {
    /// Nova folding proof (for batch proving)
    Nova(NovaProofData),
    /// Groth16 proof (for single transactions)
    Groth16(Groth16ProofData),
}

/// Serializable Nova proof data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NovaProofData {
    pub proof_bytes: Vec<u8>,
    pub num_steps: usize,
    pub public_inputs_hash: [u8; 32],
}

/// Serializable Groth16 proof data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Groth16ProofData {
    pub proof_bytes: Vec<u8>,
}

impl Transaction {
    /// Compute transaction hash
    pub fn hash(&self) -> [u8; 32] {
        if let Some(hash) = self.tx_hash {
            return hash;
        }

        let mut hasher = blake3::Hasher::new();
        hasher.update(&[self.version]);
        for nullifier in &self.nullifiers {
            hasher.update(nullifier);
        }
        for commitment in &self.output_commitments {
            hasher.update(commitment);
        }
        hasher.update(&self.merkle_root);
        hasher.update(&self.fee.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Get size in bytes (approximate)
    pub fn size(&self) -> usize {
        // Version: 1
        // Nullifiers: 32 * count
        // Commitments: 32 * count
        // Proof: variable (~192 for Groth16)
        // Other fields
        let base = 1 + 32 + 8 + 64; // version + root + fee + sig
        let nullifiers_size = self.nullifiers.len() * 32;
        let commitments_size = self.output_commitments.len() * 32;
        let proof_size = match &self.proof {
            TransactionProof::Nova(p) => p.proof_bytes.len(),
            TransactionProof::Groth16(p) => p.proof_bytes.len(),
        };
        let addresses_size: usize = self.output_addresses.iter()
            .map(|a| a.encapsulated_secret.len() + 32 + a.encrypted_randomness.len())
            .sum();
        let encrypted_size: usize = self.encrypted_amounts.iter().map(|e| e.len()).sum();

        base + nullifiers_size + commitments_size + proof_size + addresses_size + encrypted_size
    }

    /// Verify transaction structure (not proof)
    pub fn verify_structure(&self) -> Result<(), TransactionError> {
        if self.nullifiers.is_empty() {
            return Err(TransactionError::NoInputs);
        }
        if self.output_commitments.is_empty() {
            return Err(TransactionError::NoOutputs);
        }
        if self.output_commitments.len() != self.output_addresses.len() {
            return Err(TransactionError::InvalidNote(
                "Mismatched output count".into()
            ));
        }
        Ok(())
    }
}

/// Input for transaction builder
#[derive(Clone)]
pub struct TransactionInput {
    /// The note being spent
    pub note: Note,
    /// Merkle proof of inclusion
    pub merkle_path: Vec<[u8; 32]>,
    /// Merkle path indices (left/right at each level)
    pub merkle_indices: Vec<bool>,
    /// Spending key for this input
    pub spending_key: SpendingKey,
}

/// Output for transaction builder
#[derive(Clone)]
pub struct TransactionOutput {
    /// Value to send
    pub value: u64,
    /// Recipient's stealth address
    pub recipient: StealthAddress,
}

/// Configuration for transaction building
#[derive(Clone)]
pub struct TransactionConfig {
    /// Use Groth16 (true) or Nova (false) proofs
    pub use_groth16: bool,
    /// Target fee rate (per byte)
    pub fee_rate: u64,
    /// Minimum fee
    pub min_fee: u64,
    /// Maximum fee
    pub max_fee: u64,
}

impl Default for TransactionConfig {
    fn default() -> Self {
        Self {
            use_groth16: true, // Default to Groth16 for single txs
            fee_rate: 1,       // 1 unit per byte
            min_fee: 100,      // Minimum fee
            max_fee: 100_000,  // Maximum fee
        }
    }
}

/// Transaction builder for creating private transactions
pub struct TransactionBuilder {
    /// Inputs to spend
    inputs: Vec<TransactionInput>,
    /// Outputs to create
    outputs: Vec<TransactionOutput>,
    /// Current merkle root
    merkle_root: [u8; 32],
    /// Configuration
    config: TransactionConfig,
    /// Groth16 proving key (cached)
    groth16_pk: Option<Groth16ProvingKey>,
    /// Nova prover (cached)
    nova_prover: Option<NovaProver>,
}

impl TransactionBuilder {
    /// Create a new transaction builder
    pub fn new() -> Self {
        Self {
            inputs: Vec::new(),
            outputs: Vec::new(),
            merkle_root: [0u8; 32],
            config: TransactionConfig::default(),
            groth16_pk: None,
            nova_prover: None,
        }
    }

    /// Create with specific configuration
    pub fn with_config(config: TransactionConfig) -> Self {
        Self {
            inputs: Vec::new(),
            outputs: Vec::new(),
            merkle_root: [0u8; 32],
            config,
            groth16_pk: None,
            nova_prover: None,
        }
    }

    /// Set the merkle root
    pub fn set_merkle_root(&mut self, root: [u8; 32]) -> &mut Self {
        self.merkle_root = root;
        self
    }

    /// Add an input note
    pub fn add_input(&mut self, input: TransactionInput) -> &mut Self {
        self.inputs.push(input);
        self
    }

    /// Add an output
    pub fn add_output(&mut self, output: TransactionOutput) -> &mut Self {
        self.outputs.push(output);
        self
    }

    /// Add output by value and recipient address
    pub fn add_output_to(&mut self, value: u64, recipient: StealthAddress) -> &mut Self {
        self.outputs.push(TransactionOutput { value, recipient });
        self
    }

    /// Get total input value
    pub fn input_sum(&self) -> u64 {
        self.inputs.iter().map(|i| i.note.value).sum()
    }

    /// Get total output value
    pub fn output_sum(&self) -> u64 {
        self.outputs.iter().map(|o| o.value).sum()
    }

    /// Calculate fee based on estimated size
    pub fn calculate_fee(&self) -> u64 {
        // Estimate size: base + inputs + outputs
        let base_size = 200; // Approximate fixed overhead
        let input_size = self.inputs.len() * 64; // nullifier + merkle proof ref
        let output_size = self.outputs.len() * 300; // commitment + OTA + encrypted
        let proof_size = if self.config.use_groth16 { 200 } else { 500 };

        let estimated_size = base_size + input_size + output_size + proof_size;
        let fee = (estimated_size as u64) * self.config.fee_rate;

        fee.max(self.config.min_fee).min(self.config.max_fee)
    }

    /// Check if transaction is balanced
    pub fn is_balanced(&self) -> bool {
        let fee = self.calculate_fee();
        self.input_sum() >= self.output_sum() + fee
    }

    /// Add change output if needed
    pub fn add_change_output(&mut self, change_address: StealthAddress) -> Result<&mut Self, TransactionError> {
        let input_sum = self.input_sum();
        let output_sum = self.output_sum();

        // Calculate fee assuming we'll add a change output (to get accurate size)
        // Temporarily add a dummy output to calculate correct fee
        let current_output_count = self.outputs.len();
        self.outputs.push(TransactionOutput { value: 0, recipient: change_address.clone() });
        let fee = self.calculate_fee();
        self.outputs.pop(); // Remove dummy output

        if input_sum < output_sum + fee {
            return Err(TransactionError::InsufficientBalance {
                have: input_sum,
                need: output_sum + fee,
            });
        }

        let change = input_sum - output_sum - fee;
        if change > 0 {
            self.outputs.push(TransactionOutput {
                value: change,
                recipient: change_address,
            });
        }

        Ok(self)
    }

    /// Build the transaction
    pub fn build(&mut self) -> Result<Transaction, TransactionError> {
        // Validate inputs
        if self.inputs.is_empty() {
            return Err(TransactionError::NoInputs);
        }
        if self.outputs.is_empty() {
            return Err(TransactionError::NoOutputs);
        }

        let fee = self.calculate_fee();
        let input_sum = self.input_sum();
        let output_sum = self.output_sum();

        if input_sum < output_sum + fee {
            return Err(TransactionError::UnbalancedTransaction {
                inputs: input_sum,
                outputs: output_sum,
                fee,
            });
        }

        // Generate nullifiers for inputs
        let nullifiers: Vec<[u8; 32]> = self.inputs
            .iter()
            .map(|input| input.note.nullifier())
            .collect();

        // Generate outputs
        let mut output_commitments = Vec::new();
        let mut output_addresses = Vec::new();
        let mut encrypted_amounts = Vec::new();
        let mut output_randomnesses = Vec::new();

        for output in &self.outputs {
            // Derive one-time address for recipient
            let (ota, randomness) = OneTimeAddress::derive_for_recipient(&output.recipient)?;

            // Create note commitment
            let commitment = compute_commitment(output.value, &randomness);

            // Encrypt amount (simple XOR for now, will be FHE later)
            let encrypted = encrypt_amount(output.value, &randomness);

            output_commitments.push(commitment);
            output_addresses.push(ota);
            encrypted_amounts.push(encrypted);
            output_randomnesses.push(randomness);
        }

        // Generate ZK proof
        let proof = if self.config.use_groth16 {
            self.generate_groth16_proof(
                &nullifiers,
                &output_commitments,
                &output_randomnesses,
            )?
        } else {
            self.generate_nova_proof(
                &nullifiers,
                &output_commitments,
                &output_randomnesses,
            )?
        };

        // Generate binding signature
        let binding_signature = self.generate_binding_signature(&nullifiers, &output_commitments)?;

        Ok(Transaction {
            version: 1,
            nullifiers,
            output_commitments,
            output_addresses,
            encrypted_amounts,
            proof,
            merkle_root: self.merkle_root,
            fee,
            binding_signature,
            tx_hash: None,
        })
    }

    /// Generate Groth16 proof for the transaction
    fn generate_groth16_proof(
        &mut self,
        nullifiers: &[[u8; 32]],
        output_commitments: &[[u8; 32]],
        output_randomnesses: &[[u8; 32]],
    ) -> Result<TransactionProof, TransactionError> {
        // Initialize proving key if needed
        if self.groth16_pk.is_none() {
            let (pk, _vk) = groth16_setup()
                .map_err(|e| TransactionError::ProofFailed(e.to_string()))?;
            self.groth16_pk = Some(pk);
        }
        let pk = self.groth16_pk.as_ref().unwrap();

        // Build proof for each input-output pair
        // In practice, we'd combine into a single proof
        let input = &self.inputs[0];
        let output_commitment = output_commitments.get(0).copied().unwrap_or([0u8; 32]);
        let output_randomness = output_randomnesses.get(0).copied().unwrap_or([0u8; 32]);

        // Build public inputs
        let public_inputs = TransactionPublicInputs {
            nullifier: nullifiers[0],
            output_commitment,
            merkle_root: self.merkle_root,
            encrypted_amount_hash: blake3::hash(&encrypt_amount(
                self.outputs.get(0).map(|o| o.value).unwrap_or(0),
                &output_randomness,
            )).as_bytes().clone(),
        };

        // Build witness
        let witness = TransactionWitness {
            secret_key: input.spending_key.nullifier_key(),
            input_value: input.note.value,
            output_value: self.outputs.get(0).map(|o| o.value).unwrap_or(0),
            merkle_path: input.merkle_path.clone(),
            merkle_indices: input.merkle_indices.clone(),
            output_randomness,
        };

        // Generate proof
        let proof = groth16_prove(pk, public_inputs, witness)
            .map_err(|e| TransactionError::ProofFailed(e.to_string()))?;

        let proof_bytes = proof.to_bytes()
            .map_err(|e| TransactionError::ProofFailed(e.to_string()))?;

        Ok(TransactionProof::Groth16(Groth16ProofData { proof_bytes }))
    }

    /// Generate Nova folding proof for the transaction
    fn generate_nova_proof(
        &mut self,
        nullifiers: &[[u8; 32]],
        output_commitments: &[[u8; 32]],
        output_randomnesses: &[[u8; 32]],
    ) -> Result<TransactionProof, TransactionError> {
        // Initialize Nova prover if needed
        if self.nova_prover.is_none() {
            let (pk, _vk) = nova_setup()
                .map_err(|e| TransactionError::ProofFailed(e.to_string()))?;
            self.nova_prover = Some(NovaProver::new(pk, 10));
        }
        let prover = self.nova_prover.as_mut().unwrap();

        // Build transactions for batching
        let mut transactions = Vec::new();

        for (i, input) in self.inputs.iter().enumerate() {
            let output_commitment = output_commitments.get(i).copied().unwrap_or([0u8; 32]);
            let output_randomness = output_randomnesses.get(i).copied().unwrap_or([0u8; 32]);
            let output_value = self.outputs.get(i).map(|o| o.value).unwrap_or(0);

            let public_inputs = TransactionPublicInputs {
                nullifier: nullifiers.get(i).copied().unwrap_or([0u8; 32]),
                output_commitment,
                merkle_root: self.merkle_root,
                encrypted_amount_hash: *blake3::hash(&encrypt_amount(output_value, &output_randomness)).as_bytes(),
            };

            let witness = TransactionWitness {
                secret_key: input.spending_key.nullifier_key(),
                input_value: input.note.value,
                output_value,
                merkle_path: input.merkle_path.clone(),
                merkle_indices: input.merkle_indices.clone(),
                output_randomness,
            };

            transactions.push((public_inputs, witness));
        }

        // Generate batch proof
        let proof = if transactions.len() == 1 {
            let (pi, wit) = transactions.remove(0);
            prover.prove(pi, wit)
        } else {
            prover.prove_batch(transactions)
        }.map_err(|e| TransactionError::ProofFailed(e.to_string()))?;

        Ok(TransactionProof::Nova(NovaProofData {
            proof_bytes: proof.proof_bytes,
            num_steps: proof.num_steps,
            public_inputs_hash: proof.public_inputs_hash,
        }))
    }

    /// Generate binding signature
    fn generate_binding_signature(
        &self,
        nullifiers: &[[u8; 32]],
        output_commitments: &[[u8; 32]],
    ) -> Result<Vec<u8>, TransactionError> {
        // Create message to sign
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"phantom_binding_sig");
        for n in nullifiers {
            hasher.update(n);
        }
        for c in output_commitments {
            hasher.update(c);
        }
        hasher.update(&self.merkle_root);
        let message = hasher.finalize();

        // Sign with all spending keys
        let mut combined_sig = Vec::new();
        for input in &self.inputs {
            let sig = input.spending_key.sign(message.as_bytes())
                .map_err(|e| TransactionError::SigningFailed(e.to_string()))?;
            combined_sig.extend_from_slice(&sig);
        }

        // Combine signatures
        let binding_sig = blake3::derive_key("phantom_binding", &combined_sig);
        Ok(binding_sig.to_vec())
    }

    /// Clear the builder for reuse
    pub fn clear(&mut self) {
        self.inputs.clear();
        self.outputs.clear();
        self.merkle_root = [0u8; 32];
    }
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Transaction verifier
pub struct TransactionVerifier {
    /// Groth16 verification key
    groth16_vk: Option<Groth16VerifyingKey>,
    /// Nova verification key
    nova_vk: Option<phantom_nova::types::NovaVerificationKey>,
}

impl TransactionVerifier {
    /// Create a new verifier
    pub fn new() -> Result<Self, TransactionError> {
        let (_, groth16_vk) = groth16_setup()
            .map_err(|e| TransactionError::VerificationFailed(e.to_string()))?;
        let (_, nova_vk) = nova_setup()
            .map_err(|e| TransactionError::VerificationFailed(e.to_string()))?;

        Ok(Self {
            groth16_vk: Some(groth16_vk),
            nova_vk: Some(nova_vk),
        })
    }

    /// Verify a transaction
    pub fn verify(&self, tx: &Transaction, merkle_root: &[u8; 32]) -> Result<bool, TransactionError> {
        // Verify structure
        tx.verify_structure()?;

        // Verify merkle root matches
        if tx.merkle_root != *merkle_root {
            return Err(TransactionError::VerificationFailed(
                "Merkle root mismatch".into()
            ));
        }

        // Verify proof
        match &tx.proof {
            TransactionProof::Groth16(proof_data) => {
                self.verify_groth16(tx, proof_data)
            }
            TransactionProof::Nova(proof_data) => {
                self.verify_nova(tx, proof_data)
            }
        }
    }

    /// Verify Groth16 proof
    fn verify_groth16(&self, tx: &Transaction, proof_data: &Groth16ProofData) -> Result<bool, TransactionError> {
        let vk = self.groth16_vk.as_ref()
            .ok_or(TransactionError::VerificationFailed("No verification key".into()))?;

        let proof = Groth16Proof::from_bytes(&proof_data.proof_bytes)
            .map_err(|e| TransactionError::VerificationFailed(e.to_string()))?;

        // Reconstruct public inputs
        let public_inputs = TransactionPublicInputs {
            nullifier: tx.nullifiers.get(0).copied().unwrap_or([0u8; 32]),
            output_commitment: tx.output_commitments.get(0).copied().unwrap_or([0u8; 32]),
            merkle_root: tx.merkle_root,
            encrypted_amount_hash: *blake3::hash(
                tx.encrypted_amounts.get(0).map(|e| e.as_slice()).unwrap_or(&[])
            ).as_bytes(),
        };

        groth16_verify(vk, &proof, &public_inputs)
            .map_err(|e| TransactionError::VerificationFailed(e.to_string()))
    }

    /// Verify Nova proof
    fn verify_nova(&self, tx: &Transaction, proof_data: &NovaProofData) -> Result<bool, TransactionError> {
        let vk = self.nova_vk.as_ref()
            .ok_or(TransactionError::VerificationFailed("No verification key".into()))?;

        let proof = NovaProof {
            proof_bytes: proof_data.proof_bytes.clone(),
            num_steps: proof_data.num_steps,
            public_inputs_hash: proof_data.public_inputs_hash,
        };

        let verifier = phantom_nova::NovaVerifier::new(vk.clone());

        // Reconstruct public inputs for verification
        let public_inputs = TransactionPublicInputs {
            nullifier: tx.nullifiers.get(0).copied().unwrap_or([0u8; 32]),
            output_commitment: tx.output_commitments.get(0).copied().unwrap_or([0u8; 32]),
            merkle_root: tx.merkle_root,
            encrypted_amount_hash: *blake3::hash(
                tx.encrypted_amounts.get(0).map(|e| e.as_slice()).unwrap_or(&[])
            ).as_bytes(),
        };

        verifier.verify(&proof, &public_inputs)
            .map_err(|e| TransactionError::VerificationFailed(e.to_string()))
    }
}

impl Default for TransactionVerifier {
    fn default() -> Self {
        Self::new().expect("Failed to initialize verifier")
    }
}

/// Note manager for tracking owned notes
pub struct NoteManager {
    /// Owned notes (unspent)
    notes: Vec<OwnedNote>,
    /// Spent nullifiers
    spent_nullifiers: std::collections::HashSet<[u8; 32]>,
}

/// A note owned by the wallet
#[derive(Clone, Debug)]
pub struct OwnedNote {
    /// The note data
    pub note: Note,
    /// Merkle path for the note
    pub merkle_path: Vec<[u8; 32]>,
    /// Merkle path indices
    pub merkle_indices: Vec<bool>,
    /// Spending key for this note
    pub spending_key: SpendingKey,
    /// Block height where note was received
    pub block_height: u64,
}

impl NoteManager {
    /// Create a new note manager
    pub fn new() -> Self {
        Self {
            notes: Vec::new(),
            spent_nullifiers: std::collections::HashSet::new(),
        }
    }

    /// Add a received note
    pub fn add_note(&mut self, note: OwnedNote) {
        self.notes.push(note);
    }

    /// Get total balance
    pub fn balance(&self) -> u64 {
        self.notes.iter()
            .filter(|n| !n.note.spent && !self.spent_nullifiers.contains(&n.note.nullifier()))
            .map(|n| n.note.value)
            .sum()
    }

    /// Get spendable notes
    pub fn spendable_notes(&self) -> Vec<&OwnedNote> {
        self.notes.iter()
            .filter(|n| !n.note.spent && !self.spent_nullifiers.contains(&n.note.nullifier()))
            .collect()
    }

    /// Select notes for transaction
    pub fn select_notes(&self, target_value: u64) -> Option<Vec<&OwnedNote>> {
        let spendable: Vec<_> = self.spendable_notes();

        // Simple greedy selection (could use more sophisticated algorithms)
        let mut selected = Vec::new();
        let mut total = 0u64;

        for note in spendable {
            if total >= target_value {
                break;
            }
            selected.push(note);
            total += note.note.value;
        }

        if total >= target_value {
            Some(selected)
        } else {
            None
        }
    }

    /// Mark notes as spent
    pub fn mark_spent(&mut self, nullifiers: &[[u8; 32]]) {
        for nullifier in nullifiers {
            self.spent_nullifiers.insert(*nullifier);
        }
        for note in &mut self.notes {
            if self.spent_nullifiers.contains(&note.note.nullifier()) {
                note.note.spent = true;
            }
        }
    }

    /// Scan for incoming notes
    pub fn scan_for_notes(
        &mut self,
        view_key: &ViewKey,
        spend_key: &SpendKey,
        addresses: &[OneTimeAddress],
        encrypted_amounts: &[Vec<u8>],
        merkle_paths: &[Vec<[u8; 32]>],
        merkle_indices: &[Vec<bool>],
        block_height: u64,
    ) -> Vec<OwnedNote> {
        let mut found = Vec::new();

        for (i, addr) in addresses.iter().enumerate() {
            if let Ok(true) = addr.scan(view_key, spend_key) {
                if let Ok((spending_key, randomness)) = addr.recover(view_key, spend_key) {
                    // Decrypt amount
                    let encrypted = encrypted_amounts.get(i).cloned().unwrap_or_default();
                    let value = decrypt_amount(&encrypted, &randomness);

                    // Create note
                    let note = Note::new(value, randomness, spending_key.nullifier_key());

                    let owned = OwnedNote {
                        note,
                        merkle_path: merkle_paths.get(i).cloned().unwrap_or_default(),
                        merkle_indices: merkle_indices.get(i).cloned().unwrap_or_default(),
                        spending_key,
                        block_height,
                    };

                    found.push(owned.clone());
                    self.notes.push(owned);
                }
            }
        }

        found
    }
}

impl Default for NoteManager {
    fn default() -> Self {
        Self::new()
    }
}

// Helper functions

/// Compute note commitment
fn compute_commitment(value: u64, randomness: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"phantom_commitment");
    hasher.update(&value.to_le_bytes());
    hasher.update(randomness);
    *hasher.finalize().as_bytes()
}

/// Encrypt amount (placeholder - will be FHE)
fn encrypt_amount(value: u64, key: &[u8; 32]) -> Vec<u8> {
    let value_bytes = value.to_le_bytes();
    let encryption_key = blake3::derive_key("phantom_amount_encryption", key);

    value_bytes.iter()
        .zip(encryption_key.iter())
        .map(|(v, k)| v ^ k)
        .collect()
}

/// Decrypt amount
fn decrypt_amount(encrypted: &[u8], key: &[u8; 32]) -> u64 {
    let encryption_key = blake3::derive_key("phantom_amount_encryption", key);

    let decrypted: Vec<u8> = encrypted.iter()
        .zip(encryption_key.iter())
        .map(|(e, k)| e ^ k)
        .collect();

    if decrypted.len() >= 8 {
        u64::from_le_bytes(decrypted[..8].try_into().unwrap())
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_note(value: u64) -> (Note, SpendingKey, Vec<[u8; 32]>, Vec<bool>) {
        let mut randomness = [0u8; 32];
        getrandom::getrandom(&mut randomness).unwrap();

        let mut nullifier_key = [0u8; 32];
        getrandom::getrandom(&mut nullifier_key).unwrap();

        let note = Note::new(value, randomness, nullifier_key);

        // Create mock spending key
        let view_key = ViewKey::generate().unwrap();
        let spend_key = SpendKey::generate().unwrap();
        let stealth = StealthAddress::new(&view_key, &spend_key);
        let (ota, _) = OneTimeAddress::derive_for_recipient(&stealth).unwrap();
        let (spending_key, _) = ota.recover(&view_key, &spend_key).unwrap();

        // Mock merkle path (32 levels)
        let merkle_path: Vec<[u8; 32]> = (0..32).map(|i| [i as u8; 32]).collect();
        let merkle_indices: Vec<bool> = (0..32).map(|i| i % 2 == 0).collect();

        (note, spending_key, merkle_path, merkle_indices)
    }

    #[test]
    fn test_transaction_builder_creation() {
        let builder = TransactionBuilder::new();
        assert_eq!(builder.input_sum(), 0);
        assert_eq!(builder.output_sum(), 0);
    }

    #[test]
    fn test_input_output_sum() {
        let mut builder = TransactionBuilder::new();

        let (note1, sk1, mp1, mi1) = create_test_note(1000);
        let (note2, sk2, mp2, mi2) = create_test_note(500);

        builder.add_input(TransactionInput {
            note: note1,
            spending_key: sk1,
            merkle_path: mp1,
            merkle_indices: mi1,
        });
        builder.add_input(TransactionInput {
            note: note2,
            spending_key: sk2,
            merkle_path: mp2,
            merkle_indices: mi2,
        });

        assert_eq!(builder.input_sum(), 1500);

        let view_key = ViewKey::generate().unwrap();
        let spend_key = SpendKey::generate().unwrap();
        let recipient = StealthAddress::new(&view_key, &spend_key);

        builder.add_output_to(300, recipient.clone());
        builder.add_output_to(200, recipient);

        assert_eq!(builder.output_sum(), 500);
    }

    #[test]
    fn test_fee_calculation() {
        let mut builder = TransactionBuilder::new();

        let (note, sk, mp, mi) = create_test_note(10000);
        builder.add_input(TransactionInput {
            note,
            spending_key: sk,
            merkle_path: mp,
            merkle_indices: mi,
        });

        let view_key = ViewKey::generate().unwrap();
        let spend_key = SpendKey::generate().unwrap();
        let recipient = StealthAddress::new(&view_key, &spend_key);
        builder.add_output_to(5000, recipient);

        let fee = builder.calculate_fee();
        assert!(fee >= builder.config.min_fee);
        assert!(fee <= builder.config.max_fee);
    }

    #[test]
    fn test_insufficient_balance() {
        let mut builder = TransactionBuilder::new();

        let (note, sk, mp, mi) = create_test_note(100);
        builder.add_input(TransactionInput {
            note,
            spending_key: sk,
            merkle_path: mp,
            merkle_indices: mi,
        });

        let view_key = ViewKey::generate().unwrap();
        let spend_key = SpendKey::generate().unwrap();
        let recipient = StealthAddress::new(&view_key, &spend_key);
        builder.add_output_to(10000, recipient);

        let result = builder.build();
        assert!(matches!(result, Err(TransactionError::UnbalancedTransaction { .. })));
    }

    #[test]
    fn test_note_manager() {
        let mut manager = NoteManager::new();
        assert_eq!(manager.balance(), 0);

        let (note, sk, mp, mi) = create_test_note(1000);
        manager.add_note(OwnedNote {
            note: note.clone(),
            spending_key: sk,
            merkle_path: mp,
            merkle_indices: mi,
            block_height: 1,
        });

        assert_eq!(manager.balance(), 1000);

        // Mark as spent
        manager.mark_spent(&[note.nullifier()]);
        assert_eq!(manager.balance(), 0);
    }

    #[test]
    fn test_amount_encryption() {
        let value = 12345678u64;
        let key = [42u8; 32];

        let encrypted = encrypt_amount(value, &key);
        let decrypted = decrypt_amount(&encrypted, &key);

        assert_eq!(value, decrypted);
    }

    #[test]
    fn test_commitment_computation() {
        let value = 1000u64;
        let randomness = [1u8; 32];

        let c1 = compute_commitment(value, &randomness);
        let c2 = compute_commitment(value, &randomness);

        // Same inputs = same commitment
        assert_eq!(c1, c2);

        // Different value = different commitment
        let c3 = compute_commitment(1001, &randomness);
        assert_ne!(c1, c3);

        // Different randomness = different commitment
        let c4 = compute_commitment(value, &[2u8; 32]);
        assert_ne!(c1, c4);
    }

    #[test]
    fn test_full_transaction_build() {
        // This test may be slow due to proof generation
        let mut builder = TransactionBuilder::new();
        builder.set_merkle_root([0u8; 32]);

        let (note, sk, mp, mi) = create_test_note(10000);
        builder.add_input(TransactionInput {
            note,
            spending_key: sk,
            merkle_path: mp,
            merkle_indices: mi,
        });

        let view_key = ViewKey::generate().unwrap();
        let spend_key = SpendKey::generate().unwrap();
        let recipient = StealthAddress::new(&view_key, &spend_key);

        builder.add_output_to(5000, recipient.clone());
        builder.add_change_output(recipient).unwrap();

        let tx = builder.build();
        assert!(tx.is_ok(), "Transaction build failed: {:?}", tx.err());

        let tx = tx.unwrap();
        assert!(!tx.nullifiers.is_empty());
        assert!(!tx.output_commitments.is_empty());
        assert!(tx.fee > 0);
    }
}
