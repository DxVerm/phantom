//! PHANTOM Hash Functions
//!
//! - BLAKE3: Fast general-purpose hashing
//! - Poseidon: ZK-friendly algebraic hash for nullifiers and commitments

pub mod poseidon;

pub use blake3;
pub use poseidon::{PoseidonHasher, poseidon_hash, poseidon_hash_two, PoseidonParams};

/// Hash data using BLAKE3
pub fn hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Hash multiple inputs with BLAKE3
pub fn hash_many(inputs: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for input in inputs {
        hasher.update(input);
    }
    *hasher.finalize().as_bytes()
}

/// Keyed hash using BLAKE3 (for PRF)
pub fn keyed_hash(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    *blake3::keyed_hash(key, data).as_bytes()
}
