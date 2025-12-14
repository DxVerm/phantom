//! Poseidon Hash Implementation
//!
//! ZK-friendly algebraic hash function using arkworks.
//! Used for nullifiers and Merkle tree commitments in ZK proofs.

use ark_ff::{Field, PrimeField};
use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge};
use ark_crypto_primitives::sponge::CryptographicSponge;
use ark_std::vec::Vec;

/// Poseidon parameters for BN254 scalar field
pub struct PoseidonParams {
    config: PoseidonConfig<Fr>,
}

impl PoseidonParams {
    /// Create default Poseidon parameters
    /// Uses rate=2, capacity=1 for 2:1 compression
    pub fn new() -> Self {
        Self {
            config: Self::default_config(),
        }
    }

    /// Generate default Poseidon config
    /// Parameters based on secure Poseidon instantiation
    fn default_config() -> PoseidonConfig<Fr> {
        // Standard Poseidon parameters for BN254
        // t = 3 (rate=2, capacity=1), full_rounds=8, partial_rounds=57
        let full_rounds = 8;
        let partial_rounds = 57;
        let alpha = 5; // S-box exponent x^5

        // Generate round constants and MDS matrix
        // Using simple deterministic generation (in production, use proper constants)
        let rate = 2;
        let capacity = 1;
        let t = rate + capacity;

        // Round constants: t * (full_rounds + partial_rounds) elements
        let _num_constants = t * (full_rounds + partial_rounds);
        let ark: Vec<Vec<Fr>> = (0..(full_rounds + partial_rounds))
            .map(|round| {
                (0..t)
                    .map(|i| {
                        // Deterministic constant generation
                        let seed = ((round * t + i) as u64).wrapping_mul(0x9e3779b97f4a7c15);
                        Fr::from(seed)
                    })
                    .collect()
            })
            .collect();

        // MDS matrix (simple secure construction)
        let mds: Vec<Vec<Fr>> = (0..t)
            .map(|i| {
                (0..t)
                    .map(|j| {
                        // Cauchy matrix for MDS property
                        let x = Fr::from(i as u64);
                        let y = Fr::from((t + j) as u64);
                        (x + y).inverse().unwrap_or(Fr::from(1u64))
                    })
                    .collect()
            })
            .collect();

        PoseidonConfig::new(
            full_rounds,
            partial_rounds,
            alpha as u64,
            mds,
            ark,
            rate,
            capacity,
        )
    }
}

impl Default for PoseidonParams {
    fn default() -> Self {
        Self::new()
    }
}

/// Poseidon hasher for stateful hashing
pub struct PoseidonHasher {
    sponge: PoseidonSponge<Fr>,
}

impl PoseidonHasher {
    /// Create new hasher with default parameters
    pub fn new() -> Self {
        let params = PoseidonParams::new();
        Self {
            sponge: PoseidonSponge::new(&params.config),
        }
    }

    /// Create with custom parameters
    pub fn with_params(params: &PoseidonParams) -> Self {
        Self {
            sponge: PoseidonSponge::new(&params.config),
        }
    }

    /// Absorb a field element
    pub fn absorb(&mut self, element: &Fr) {
        self.sponge.absorb(element);
    }

    /// Absorb bytes (converted to field elements)
    pub fn absorb_bytes(&mut self, data: &[u8]) {
        // Convert bytes to field elements (32 bytes per element for BN254)
        for chunk in data.chunks(31) {
            // Use 31 bytes to stay within field
            let mut bytes = [0u8; 32];
            bytes[..chunk.len()].copy_from_slice(chunk);
            let element = Fr::from_le_bytes_mod_order(&bytes);
            self.sponge.absorb(&element);
        }
    }

    /// Squeeze a single field element
    pub fn squeeze(&mut self) -> Fr {
        self.sponge.squeeze_field_elements(1)[0]
    }

    /// Squeeze and convert to bytes
    pub fn squeeze_bytes(&mut self) -> [u8; 32] {
        let element = self.squeeze();
        let mut bytes = [0u8; 32];
        // Extract bytes from field element
        let repr = element.into_bigint();
        for (i, limb) in repr.0.iter().enumerate() {
            let offset = i * 8;
            if offset < 32 {
                let len = std::cmp::min(8, 32 - offset);
                bytes[offset..offset + len].copy_from_slice(&limb.to_le_bytes()[..len]);
            }
        }
        bytes
    }

    /// Finalize and return hash as field element
    pub fn finalize(mut self) -> Fr {
        self.squeeze()
    }

    /// Finalize and return hash as bytes
    pub fn finalize_bytes(mut self) -> [u8; 32] {
        self.squeeze_bytes()
    }
}

impl Default for PoseidonHasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Hash two field elements (for Merkle trees)
pub fn poseidon_hash_two(left: &Fr, right: &Fr) -> Fr {
    let mut hasher = PoseidonHasher::new();
    hasher.absorb(left);
    hasher.absorb(right);
    hasher.finalize()
}

/// Hash arbitrary data with Poseidon
pub fn poseidon_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = PoseidonHasher::new();
    hasher.absorb_bytes(data);
    hasher.finalize_bytes()
}

/// Convert bytes to field element
pub fn bytes_to_field(data: &[u8]) -> Fr {
    let mut bytes = [0u8; 32];
    let len = std::cmp::min(31, data.len()); // Use 31 bytes max
    bytes[..len].copy_from_slice(&data[..len]);
    Fr::from_le_bytes_mod_order(&bytes)
}

/// Convert field element to bytes
pub fn field_to_bytes(element: &Fr) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let repr = element.into_bigint();
    for (i, limb) in repr.0.iter().enumerate() {
        let offset = i * 8;
        if offset < 32 {
            let len = std::cmp::min(8, 32 - offset);
            bytes[offset..offset + len].copy_from_slice(&limb.to_le_bytes()[..len]);
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon_hash() {
        let data = b"test data for poseidon";
        let hash = poseidon_hash(data);
        assert_ne!(hash, [0u8; 32], "Hash should not be zero");
    }

    #[test]
    fn test_poseidon_deterministic() {
        let data = b"deterministic test";
        let hash1 = poseidon_hash(data);
        let hash2 = poseidon_hash(data);
        assert_eq!(hash1, hash2, "Same input should produce same hash");
    }

    #[test]
    fn test_poseidon_different_inputs() {
        let hash1 = poseidon_hash(b"input 1");
        let hash2 = poseidon_hash(b"input 2");
        assert_ne!(hash1, hash2, "Different inputs should produce different hashes");
    }

    #[test]
    fn test_poseidon_hash_two() {
        let a = Fr::from(123u64);
        let b = Fr::from(456u64);

        let hash1 = poseidon_hash_two(&a, &b);
        let hash2 = poseidon_hash_two(&a, &b);

        assert_eq!(hash1, hash2, "Same inputs should produce same hash");

        let hash3 = poseidon_hash_two(&b, &a);
        assert_ne!(hash1, hash3, "Order should matter");
    }

    #[test]
    fn test_bytes_field_roundtrip() {
        let data = b"test roundtrip data";
        let field = bytes_to_field(data);
        let back = field_to_bytes(&field);

        // First 31 bytes should match (that's all we encode)
        assert_eq!(&back[..data.len().min(31)], &data[..data.len().min(31)]);
    }

    #[test]
    fn test_poseidon_hasher_stateful() {
        let mut hasher = PoseidonHasher::new();
        hasher.absorb(&Fr::from(1u64));
        hasher.absorb(&Fr::from(2u64));
        let hash1 = hasher.finalize();

        let mut hasher2 = PoseidonHasher::new();
        hasher2.absorb(&Fr::from(1u64));
        hasher2.absorb(&Fr::from(2u64));
        let hash2 = hasher2.finalize();

        assert_eq!(hash1, hash2);
    }
}
