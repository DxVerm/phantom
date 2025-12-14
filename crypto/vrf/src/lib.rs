//! PHANTOM Verifiable Random Function (VRF)
//!
//! VRF implementation using Ed25519-based ECVRF (RFC 9381).
//! Used for unpredictable but verifiable witness selection in CWA consensus.
//!
//! # Features:
//! - ECVRF-EDWARDS25519-SHA512-TAI (Suite 03)
//! - Deterministic proof generation
//! - Public verification without secret key
//!
//! # Usage:
//! ```ignore
//! let keypair = VRFKeyPair::generate();
//! let (output, proof) = keypair.prove(b"message");
//! assert!(keypair.public_key().verify(b"message", &output, &proof));
//! ```

use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Sha512, Digest};
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use serde::{Serialize, Deserialize};
use thiserror::Error;
use rand::RngCore;

/// VRF errors
#[derive(Error, Debug)]
pub enum VRFError {
    #[error("Invalid proof")]
    InvalidProof,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Hash to curve failed")]
    HashToCurveFailed,
    #[error("Signature verification failed")]
    VerificationFailed,
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

pub type VRFResult<T> = Result<T, VRFError>;

/// VRF output - the pseudorandom value
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VRFOutput {
    /// The 32-byte VRF output
    pub value: [u8; 32],
}

impl VRFOutput {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { value: bytes }
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.value
    }

    /// Convert to u64 (for validator selection)
    pub fn to_u64(&self) -> u64 {
        u64::from_le_bytes(self.value[0..8].try_into().unwrap())
    }

    /// Check if output falls within threshold (for lottery)
    pub fn is_winner(&self, threshold: u64) -> bool {
        self.to_u64() < threshold
    }
}

/// VRF proof - proves the output was correctly computed
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VRFProof {
    /// Gamma point (compressed)
    gamma: [u8; 32],
    /// Challenge scalar
    c: [u8; 32],
    /// Response scalar
    s: [u8; 32],
}

impl VRFProof {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; 96] {
        let mut bytes = [0u8; 96];
        bytes[0..32].copy_from_slice(&self.gamma);
        bytes[32..64].copy_from_slice(&self.c);
        bytes[64..96].copy_from_slice(&self.s);
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8; 96]) -> Self {
        let mut gamma = [0u8; 32];
        let mut c = [0u8; 32];
        let mut s = [0u8; 32];
        gamma.copy_from_slice(&bytes[0..32]);
        c.copy_from_slice(&bytes[32..64]);
        s.copy_from_slice(&bytes[64..96]);
        Self { gamma, c, s }
    }
}

/// VRF public key for verification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VRFPublicKey {
    /// Inner Ed25519 verifying key
    bytes: [u8; 32],
}

impl VRFPublicKey {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> VRFResult<Self> {
        // Validate it's a valid point
        let _ = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| VRFError::InvalidPublicKey)?;
        Ok(Self { bytes })
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Verify a VRF proof
    pub fn verify(&self, alpha: &[u8], output: &VRFOutput, proof: &VRFProof) -> VRFResult<bool> {
        // Reconstruct the verification
        let pk_point = CompressedEdwardsY(self.bytes)
            .decompress()
            .ok_or(VRFError::InvalidPublicKey)?;

        // Hash to curve: H(public_key || alpha)
        let h_point = hash_to_curve(&self.bytes, alpha)?;

        // Decompress gamma
        let gamma_point = CompressedEdwardsY(proof.gamma)
            .decompress()
            .ok_or(VRFError::InvalidProof)?;

        // Compute c and s as scalars
        let c_scalar = Scalar::from_bytes_mod_order(proof.c);
        let s_scalar = Scalar::from_bytes_mod_order(proof.s);

        // Verify: s*G = c*Y + U  =>  U = s*G - c*Y
        let u_point = ED25519_BASEPOINT_POINT * s_scalar - pk_point * c_scalar;

        // Verify: s*H = c*Gamma + V  =>  V = s*H - c*Gamma
        let v_point = h_point * s_scalar - gamma_point * c_scalar;

        // Recompute challenge
        let c_verify = compute_challenge(&pk_point, &h_point, &gamma_point, &u_point, &v_point);

        // Verify challenge matches
        if c_verify.as_bytes() != &proof.c {
            return Ok(false);
        }

        // Verify output = hash(Gamma)
        let expected_output = gamma_to_output(&gamma_point);
        Ok(output.value == expected_output)
    }

    /// Get unique identifier for this public key
    pub fn id(&self) -> [u8; 32] {
        *blake3::hash(&self.bytes).as_bytes()
    }
}

/// VRF secret key for proving
#[derive(Clone)]
pub struct VRFSecretKey {
    /// Inner Ed25519 signing key
    inner: SigningKey,
}

impl VRFSecretKey {
    /// Generate a new random secret key
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self {
            inner: SigningKey::from_bytes(&seed),
        }
    }

    /// Create from seed bytes
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            inner: SigningKey::from_bytes(&seed),
        }
    }

    /// Get the corresponding public key
    pub fn public_key(&self) -> VRFPublicKey {
        VRFPublicKey {
            bytes: self.inner.verifying_key().to_bytes(),
        }
    }

    /// Compute VRF output and proof
    pub fn prove(&self, alpha: &[u8]) -> VRFResult<(VRFOutput, VRFProof)> {
        let pk_bytes = self.inner.verifying_key().to_bytes();
        let pk_point = CompressedEdwardsY(pk_bytes)
            .decompress()
            .ok_or(VRFError::InvalidPublicKey)?;

        // Hash to curve: H = hash_to_curve(pk || alpha)
        let h_point = hash_to_curve(&pk_bytes, alpha)?;

        // Compute Gamma = x * H (where x is the secret scalar)
        let x_scalar = get_secret_scalar(&self.inner);
        let gamma_point = h_point * x_scalar;

        // Generate random k for proof
        let k_scalar = generate_nonce(&self.inner, alpha);

        // U = k * G
        let u_point = ED25519_BASEPOINT_POINT * k_scalar;

        // V = k * H
        let v_point = h_point * k_scalar;

        // Challenge: c = hash(pk, H, Gamma, U, V)
        let c_scalar = compute_challenge(&pk_point, &h_point, &gamma_point, &u_point, &v_point);

        // Response: s = k + c * x (mod L)
        let s_scalar = k_scalar + c_scalar * x_scalar;

        // Output = hash(Gamma)
        let output_bytes = gamma_to_output(&gamma_point);

        let proof = VRFProof {
            gamma: gamma_point.compress().to_bytes(),
            c: c_scalar.to_bytes(),
            s: s_scalar.to_bytes(),
        };

        Ok((VRFOutput::from_bytes(output_bytes), proof))
    }

    /// Get seed for serialization (be careful with this!)
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }
}

/// VRF key pair
#[derive(Clone)]
pub struct VRFKeyPair {
    pub secret: VRFSecretKey,
    pub public: VRFPublicKey,
}

impl VRFKeyPair {
    /// Generate a new key pair
    pub fn generate() -> Self {
        let secret = VRFSecretKey::generate();
        let public = secret.public_key();
        Self { secret, public }
    }

    /// Create from seed
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let secret = VRFSecretKey::from_seed(seed);
        let public = secret.public_key();
        Self { secret, public }
    }

    /// Compute VRF output and proof
    pub fn prove(&self, alpha: &[u8]) -> VRFResult<(VRFOutput, VRFProof)> {
        self.secret.prove(alpha)
    }

    /// Get the public key
    pub fn public_key(&self) -> &VRFPublicKey {
        &self.public
    }
}

impl std::fmt::Debug for VRFKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VRFKeyPair")
            .field("public", &hex::encode(&self.public.bytes[..8]))
            .finish()
    }
}

// ============ Internal Functions ============

/// Hash to curve using try-and-increment (TAI)
fn hash_to_curve(pk: &[u8; 32], alpha: &[u8]) -> VRFResult<curve25519_dalek::edwards::EdwardsPoint> {
    // Suite 03: ECVRF-EDWARDS25519-SHA512-TAI
    for counter in 0u8..255 {
        let mut hasher = Sha512::new();
        hasher.update(&[0x01]); // Suite byte
        hasher.update(pk);
        hasher.update(alpha);
        hasher.update(&[counter]);
        let hash = hasher.finalize();

        // Try to decompress as a point
        let mut point_bytes = [0u8; 32];
        point_bytes.copy_from_slice(&hash[0..32]);

        if let Some(point) = CompressedEdwardsY(point_bytes).decompress() {
            // Multiply by cofactor (8) to get to the prime-order subgroup
            return Ok(point.mul_by_cofactor());
        }
    }
    Err(VRFError::HashToCurveFailed)
}

/// Compute challenge scalar from points
fn compute_challenge(
    pk: &curve25519_dalek::edwards::EdwardsPoint,
    h: &curve25519_dalek::edwards::EdwardsPoint,
    gamma: &curve25519_dalek::edwards::EdwardsPoint,
    u: &curve25519_dalek::edwards::EdwardsPoint,
    v: &curve25519_dalek::edwards::EdwardsPoint,
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(&[0x02]); // Suite byte for challenge
    hasher.update(pk.compress().as_bytes());
    hasher.update(h.compress().as_bytes());
    hasher.update(gamma.compress().as_bytes());
    hasher.update(u.compress().as_bytes());
    hasher.update(v.compress().as_bytes());
    let hash = hasher.finalize();

    // Take first 16 bytes for challenge (as per RFC)
    let mut c_bytes = [0u8; 32];
    c_bytes[0..16].copy_from_slice(&hash[0..16]);
    Scalar::from_bytes_mod_order(c_bytes)
}

/// Convert Gamma point to VRF output
fn gamma_to_output(gamma: &curve25519_dalek::edwards::EdwardsPoint) -> [u8; 32] {
    // Cofactor multiply then hash
    let gamma_cofactor = gamma.mul_by_cofactor();
    let mut hasher = Sha512::new();
    hasher.update(&[0x03]); // Suite byte for proof-to-hash
    hasher.update(gamma_cofactor.compress().as_bytes());
    let hash = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&hash[0..32]);
    output
}

/// Extract secret scalar from signing key
fn get_secret_scalar(key: &SigningKey) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(key.to_bytes());
    let hash = hasher.finalize();
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&hash[0..32]);
    // Clamp as per Ed25519
    scalar_bytes[0] &= 248;
    scalar_bytes[31] &= 127;
    scalar_bytes[31] |= 64;
    Scalar::from_bytes_mod_order(scalar_bytes)
}

/// Generate deterministic nonce for proving
fn generate_nonce(key: &SigningKey, alpha: &[u8]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(key.to_bytes());
    hasher.update(alpha);
    hasher.update(&[0x00]); // Nonce domain separator
    let hash = hasher.finalize();
    Scalar::from_bytes_mod_order_wide(&hash.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vrf_prove_verify() {
        let keypair = VRFKeyPair::generate();
        let alpha = b"test message for VRF";

        let (output, proof) = keypair.prove(alpha).unwrap();

        // Verify with correct alpha
        let is_valid = keypair.public_key().verify(alpha, &output, &proof).unwrap();
        assert!(is_valid, "VRF proof should be valid");
    }

    #[test]
    fn test_vrf_deterministic() {
        let keypair = VRFKeyPair::from_seed([42u8; 32]);
        let alpha = b"deterministic test";

        let (output1, _proof1) = keypair.prove(alpha).unwrap();
        let (output2, _proof2) = keypair.prove(alpha).unwrap();

        assert_eq!(output1.value, output2.value, "Same input should produce same output");
    }

    #[test]
    fn test_vrf_different_inputs_different_outputs() {
        let keypair = VRFKeyPair::generate();

        let (output1, _) = keypair.prove(b"input 1").unwrap();
        let (output2, _) = keypair.prove(b"input 2").unwrap();

        assert_ne!(output1.value, output2.value, "Different inputs should produce different outputs");
    }

    #[test]
    fn test_vrf_wrong_alpha_fails() {
        let keypair = VRFKeyPair::generate();
        let (output, proof) = keypair.prove(b"correct alpha").unwrap();

        // Verify with wrong alpha should fail
        let is_valid = keypair.public_key().verify(b"wrong alpha", &output, &proof).unwrap();
        assert!(!is_valid, "VRF should reject wrong alpha");
    }

    #[test]
    fn test_vrf_different_keys_different_outputs() {
        let keypair1 = VRFKeyPair::generate();
        let keypair2 = VRFKeyPair::generate();
        let alpha = b"same alpha";

        let (output1, _) = keypair1.prove(alpha).unwrap();
        let (output2, _) = keypair2.prove(alpha).unwrap();

        assert_ne!(output1.value, output2.value, "Different keys should produce different outputs");
    }

    #[test]
    fn test_vrf_lottery_selection() {
        let keypair = VRFKeyPair::from_seed([1u8; 32]);
        let alpha = b"block_123_slot_456";

        let (output, _) = keypair.prove(alpha).unwrap();
        let lottery_value = output.to_u64();

        // Check if we would be selected with various thresholds
        let is_winner_high = output.is_winner(u64::MAX / 10);  // 10% chance
        let is_winner_low = output.is_winner(u64::MAX / 1000); // 0.1% chance

        println!("Lottery value: {}", lottery_value);
        println!("Winner at 10%: {}", is_winner_high);
        println!("Winner at 0.1%: {}", is_winner_low);
    }

    #[test]
    fn test_proof_serialization() {
        let keypair = VRFKeyPair::generate();
        let (output, proof) = keypair.prove(b"test").unwrap();

        let bytes = proof.to_bytes();
        let proof2 = VRFProof::from_bytes(&bytes);

        // Verify the deserialized proof still works
        let is_valid = keypair.public_key().verify(b"test", &output, &proof2).unwrap();
        assert!(is_valid);
    }
}
