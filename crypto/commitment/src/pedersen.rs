//! Pedersen Commitment (placeholder - see phantom-esl for main impl)

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PedersenCommitment([u8; 32]);

impl PedersenCommitment {
    pub fn commit(value: u64, randomness: &[u8; 32]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"pedersen");
        hasher.update(&value.to_le_bytes());
        hasher.update(randomness);
        Self(*hasher.finalize().as_bytes())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
