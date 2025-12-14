//! Note management

use serde::{Deserialize, Serialize};

/// A private note owned by the wallet
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Note {
    pub commitment: [u8; 32],
    pub value: u64,
    pub randomness: [u8; 32],
    pub nullifier_key: [u8; 32],
    pub spent: bool,
}

impl Note {
    pub fn new(value: u64, randomness: [u8; 32], nullifier_key: [u8; 32]) -> Self {
        let commitment = Self::compute_commitment(value, &randomness);
        Self {
            commitment,
            value,
            randomness,
            nullifier_key,
            spent: false,
        }
    }

    fn compute_commitment(value: u64, randomness: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"note_commitment");
        hasher.update(&value.to_le_bytes());
        hasher.update(randomness);
        *hasher.finalize().as_bytes()
    }

    pub fn nullifier(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(&self.nullifier_key);
        hasher.update(&self.commitment);
        *hasher.finalize().as_bytes()
    }
}
