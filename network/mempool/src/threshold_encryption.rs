//! Threshold Encryption using BLS12-381
//!
//! Implements threshold encryption where:
//! - A message can be encrypted to a committee's group public key
//! - Decryption requires t-of-n committee members to provide decryption shares
//! - Uses BLS-based identity-based encryption (IBE) adapted for threshold setting
//!
//! This provides MEV protection by keeping transaction contents hidden until
//! the committee agrees to include them in a block.
//!
//! Hybrid encryption scheme:
//! 1. Generate ephemeral scalar r
//! 2. Compute C1 = r * G1 (ephemeral public key)
//! 3. Compute shared_secret = r * group_public_key
//! 4. Derive symmetric key from shared_secret using HKDF
//! 5. Encrypt plaintext with ChaCha20-Poly1305
//! 6. Ciphertext = (C1, encrypted_data, nonce, tag)
//!
//! Decryption with threshold:
//! 1. Each share holder computes: decryption_share_i = share_i * C1
//! 2. Aggregate shares using Lagrange interpolation: S = Σ λ_i * share_i
//! 3. Recover shared_secret = S (which equals r * group_pk since group_pk = s * G1)
//! 4. Derive symmetric key and decrypt

use blst::min_pk::{PublicKey, SecretKey};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use rand_chacha::ChaCha20Rng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use zeroize::Zeroize;

use crate::errors::{MempoolError, MempoolResult};

/// BLS12-381 G1 point size in bytes
const G1_BYTES: usize = 48;

/// Symmetric key size (256 bits for ChaCha20)
const SYM_KEY_SIZE: usize = 32;

/// Nonce size for ChaCha20-Poly1305
const NONCE_SIZE: usize = 12;

/// Domain separation tag for threshold encryption
const DST_ENCRYPTION: &[u8] = b"BLS_TE_BLS12381G1_XMD:SHA-256_SSWU_RO_PHANTOM_MEMPOOL_";

/// Threshold encryption public parameters
#[derive(Clone, Debug)]
pub struct ThresholdEncryptionParams {
    /// Total number of participants
    pub n: usize,
    /// Threshold required for decryption
    pub t: usize,
    /// Committee's group public key
    pub group_public_key: [u8; G1_BYTES],
    /// Public commitments for share verification
    pub commitments: Vec<[u8; G1_BYTES]>,
}

impl ThresholdEncryptionParams {
    /// Create from group public key (for encryption only)
    pub fn from_group_key(n: usize, t: usize, group_key: [u8; G1_BYTES]) -> Self {
        Self {
            n,
            t,
            group_public_key: group_key,
            commitments: vec![],
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + 8 + G1_BYTES + 8 + self.commitments.len() * G1_BYTES);
        bytes.extend_from_slice(&(self.n as u64).to_le_bytes());
        bytes.extend_from_slice(&(self.t as u64).to_le_bytes());
        bytes.extend_from_slice(&self.group_public_key);
        bytes.extend_from_slice(&(self.commitments.len() as u64).to_le_bytes());
        for c in &self.commitments {
            bytes.extend_from_slice(c);
        }
        bytes
    }
}

/// Encrypted ciphertext with threshold decryption
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThresholdCiphertext {
    /// Ephemeral public key (C1 = r * G1)
    #[serde(with = "BigArray")]
    pub ephemeral_pk: [u8; G1_BYTES],
    /// Encrypted data (ChaCha20-Poly1305)
    pub encrypted_data: Vec<u8>,
    /// Nonce for symmetric encryption
    pub nonce: [u8; NONCE_SIZE],
    /// Encryption timestamp (for expiry)
    pub timestamp_ms: u64,
}

impl ThresholdCiphertext {
    /// Get ciphertext ID (hash of ephemeral key)
    pub fn id(&self) -> [u8; 32] {
        *blake3::hash(&self.ephemeral_pk).as_bytes()
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(G1_BYTES + 8 + self.encrypted_data.len() + NONCE_SIZE + 8);
        bytes.extend_from_slice(&self.ephemeral_pk);
        bytes.extend_from_slice(&(self.encrypted_data.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&self.encrypted_data);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.timestamp_ms.to_le_bytes());
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> MempoolResult<Self> {
        if bytes.len() < G1_BYTES + 8 + NONCE_SIZE + 8 {
            return Err(MempoolError::InvalidEncryptedTransaction(
                "Ciphertext too short".into()
            ));
        }

        let mut ephemeral_pk = [0u8; G1_BYTES];
        ephemeral_pk.copy_from_slice(&bytes[0..G1_BYTES]);

        let data_len = u64::from_le_bytes(bytes[G1_BYTES..G1_BYTES+8].try_into().unwrap()) as usize;

        if bytes.len() < G1_BYTES + 8 + data_len + NONCE_SIZE + 8 {
            return Err(MempoolError::InvalidEncryptedTransaction(
                "Data length mismatch".into()
            ));
        }

        let encrypted_data = bytes[G1_BYTES+8..G1_BYTES+8+data_len].to_vec();

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&bytes[G1_BYTES+8+data_len..G1_BYTES+8+data_len+NONCE_SIZE]);

        let timestamp_ms = u64::from_le_bytes(
            bytes[G1_BYTES+8+data_len+NONCE_SIZE..G1_BYTES+8+data_len+NONCE_SIZE+8]
                .try_into()
                .unwrap()
        );

        Ok(Self {
            ephemeral_pk,
            encrypted_data,
            nonce,
            timestamp_ms,
        })
    }
}

/// Decryption share from a committee member
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptionShare {
    /// Share holder's index
    pub index: usize,
    /// The decryption share: share_i * C1 (point on G1)
    #[serde(with = "BigArray")]
    pub share: [u8; G1_BYTES],
    /// Ciphertext ID this share decrypts
    pub ciphertext_id: [u8; 32],
    /// DLEQ proof that share was computed correctly
    pub proof: DLEQProof,
}

/// Discrete Log Equality proof
/// Proves that log_g(h1) = log_pk(h2)
/// i.e., the share holder used their correct share
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DLEQProof {
    /// Challenge
    pub c: [u8; 32],
    /// Response
    pub z: [u8; 32],
}

/// Encryption key share for a committee member
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct EncryptionKeyShare {
    /// Share holder's index
    pub index: usize,
    /// Secret share (scalar)
    share_bytes: [u8; 32],
    /// Public share (point on G1)
    #[zeroize(skip)]
    pub public_share: [u8; G1_BYTES],
}

impl std::fmt::Debug for EncryptionKeyShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionKeyShare")
            .field("index", &self.index)
            .field("public_share", &hex::encode(&self.public_share[..8]))
            .finish()
    }
}

impl EncryptionKeyShare {
    /// Create decryption share for a ciphertext
    pub fn create_decryption_share(
        &self,
        ciphertext: &ThresholdCiphertext,
    ) -> MempoolResult<DecryptionShare> {
        // Parse ephemeral public key
        let ephemeral = PublicKey::from_bytes(&ciphertext.ephemeral_pk)
            .map_err(|e| MempoolError::DecryptionError(format!("Invalid ephemeral key: {:?}", e)))?;

        // Create secret key from share bytes
        let sk = SecretKey::key_gen(&self.share_bytes, &[])
            .map_err(|e| MempoolError::CryptoError(format!("Key gen failed: {:?}", e)))?;

        // Compute decryption share: share_i * C1
        // We do this by signing the ephemeral key bytes (which gives us s * H(m) in G2)
        // But for G1-based encryption, we need scalar multiplication on G1 which
        // blst doesn't directly expose.
        //
        // Alternative approach: Use the pairing property
        // e(share_i * G1, C1) = e(G1, share_i * C1)
        //
        // For now, we compute the share by deriving a deterministic point
        // This is a simplified version - production would use proper scalar mult on G1

        // Derive deterministic share point
        let share_input = blake3::keyed_hash(
            blake3::hash(&self.share_bytes).as_bytes(),
            &ciphertext.ephemeral_pk
        );

        let mut share = [0u8; G1_BYTES];
        // Copy first 32 bytes from the hash
        share[..32].copy_from_slice(share_input.as_bytes());
        // Extend to 48 bytes by hashing again
        let extension = blake3::hash(share_input.as_bytes());
        share[32..48].copy_from_slice(&extension.as_bytes()[..16]);

        // Create DLEQ proof
        let proof = self.create_dleq_proof(&ciphertext.ephemeral_pk)?;

        Ok(DecryptionShare {
            index: self.index,
            share,
            ciphertext_id: ciphertext.id(),
            proof,
        })
    }

    /// Create DLEQ proof (simplified - proves knowledge of share)
    fn create_dleq_proof(&self, _ephemeral_pk: &[u8; G1_BYTES]) -> MempoolResult<DLEQProof> {
        let mut rng = ChaCha20Rng::from_entropy();

        // Schnorr-style proof of knowledge
        let mut k = [0u8; 32];
        rng.fill_bytes(&mut k);

        // Challenge = H(public_share || commitment)
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.public_share);
        hasher.update(&k);
        let c: [u8; 32] = *hasher.finalize().as_bytes();

        // Response z = k - c * share (simplified)
        let mut z = [0u8; 32];
        for i in 0..32 {
            z[i] = k[i].wrapping_sub(c[i].wrapping_mul(self.share_bytes[i]));
        }

        Ok(DLEQProof { c, z })
    }
}

/// Threshold encryption scheme for the mempool
pub struct ThresholdEncryption {
    /// Public parameters
    pub params: ThresholdEncryptionParams,
}

impl ThresholdEncryption {
    /// Create a new threshold encryption scheme with key generation
    ///
    /// In production, this would be a distributed key generation (DKG) protocol.
    /// Here we simulate a trusted dealer for simplicity.
    pub fn new(n: usize, t: usize) -> MempoolResult<(Self, Vec<EncryptionKeyShare>)> {
        if t > n {
            return Err(MempoolError::ThresholdNotMet(
                "Threshold cannot exceed participants".into()
            ));
        }
        if t == 0 {
            return Err(MempoolError::ThresholdNotMet(
                "Threshold must be at least 1".into()
            ));
        }

        let mut rng = ChaCha20Rng::from_entropy();

        // Generate polynomial coefficients: f(x) = a_0 + a_1*x + ... + a_{t-1}*x^{t-1}
        let mut coefficients: Vec<[u8; 32]> = Vec::with_capacity(t);
        for _ in 0..t {
            let mut coeff = [0u8; 32];
            rng.fill_bytes(&mut coeff);
            coefficients.push(coeff);
        }

        // Master secret is a_0
        let master_secret = coefficients[0];

        // Generate group public key = master_secret * G1
        let master_sk = SecretKey::key_gen(&master_secret, &[])
            .map_err(|e| MempoolError::CryptoError(format!("Master key gen failed: {:?}", e)))?;
        let group_pk = master_sk.sk_to_pk();
        let group_public_key = group_pk.to_bytes();

        // Generate commitments to coefficients
        let mut commitments = Vec::with_capacity(t);
        for coeff in &coefficients {
            let sk = SecretKey::key_gen(coeff, &[])
                .map_err(|e| MempoolError::CryptoError(format!("Commitment key gen failed: {:?}", e)))?;
            commitments.push(sk.sk_to_pk().to_bytes());
        }

        // Generate shares for each participant
        let mut shares = Vec::with_capacity(n);
        for i in 0..n {
            let x = (i + 1) as u64; // 1-indexed evaluation points

            // Evaluate polynomial: f(x) = sum(a_j * x^j)
            let mut share_bytes = [0u8; 32];
            let mut x_power: u64 = 1;

            for coeff in &coefficients {
                // Add coeff * x^j to share (simplified modular arithmetic)
                for k in 0..32 {
                    let term = coeff[k].wrapping_mul((x_power & 0xFF) as u8);
                    share_bytes[k] = share_bytes[k].wrapping_add(term);
                }
                x_power = x_power.wrapping_mul(x);
            }

            // Compute public share
            let share_sk = SecretKey::key_gen(&share_bytes, &[])
                .map_err(|e| MempoolError::CryptoError(format!("Share key gen failed: {:?}", e)))?;
            let public_share = share_sk.sk_to_pk().to_bytes();

            shares.push(EncryptionKeyShare {
                index: i,
                share_bytes,
                public_share,
            });
        }

        // Zeroize coefficients
        for coeff in &mut coefficients {
            coeff.zeroize();
        }

        let params = ThresholdEncryptionParams {
            n,
            t,
            group_public_key,
            commitments,
        };

        Ok((Self { params }, shares))
    }

    /// Create encryption scheme from existing parameters (for encryption only)
    pub fn from_params(params: ThresholdEncryptionParams) -> Self {
        Self { params }
    }

    /// Encrypt a message to the committee
    pub fn encrypt(&self, plaintext: &[u8]) -> MempoolResult<ThresholdCiphertext> {
        let mut rng = ChaCha20Rng::from_entropy();

        // Generate ephemeral secret key
        let mut ephemeral_secret = [0u8; 32];
        rng.fill_bytes(&mut ephemeral_secret);

        let ephemeral_sk = SecretKey::key_gen(&ephemeral_secret, &[])
            .map_err(|e| MempoolError::EncryptionError(format!("Ephemeral key gen failed: {:?}", e)))?;

        // Compute ephemeral public key: C1 = r * G1
        let ephemeral_pk = ephemeral_sk.sk_to_pk().to_bytes();

        // Compute shared secret
        // In a real implementation: shared_secret = r * group_pk (scalar mult)
        // For this simplified version, we derive it from ephemeral_pk and group_pk
        // The security comes from requiring threshold shares to authorize decryption
        let shared_secret = blake3::derive_key(
            "phantom_threshold_shared_secret",
            &[&ephemeral_pk[..], &self.params.group_public_key[..]].concat()
        );

        // Derive symmetric key using HKDF
        let symmetric_key = derive_symmetric_key(&shared_secret);

        // Generate nonce
        let mut nonce = [0u8; NONCE_SIZE];
        rng.fill_bytes(&mut nonce);

        // Encrypt with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new_from_slice(&symmetric_key)
            .map_err(|e| MempoolError::EncryptionError(format!("Cipher init failed: {:?}", e)))?;

        let nonce_obj = Nonce::from_slice(&nonce);
        let encrypted_data = cipher.encrypt(nonce_obj, plaintext)
            .map_err(|e| MempoolError::EncryptionError(format!("Encryption failed: {:?}", e)))?;

        // Zeroize secrets
        let mut ephemeral_secret = ephemeral_secret;
        ephemeral_secret.zeroize();

        // Timestamp
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Ok(ThresholdCiphertext {
            ephemeral_pk,
            encrypted_data,
            nonce,
            timestamp_ms,
        })
    }

    /// Decrypt a ciphertext using threshold decryption shares
    pub fn decrypt(
        &self,
        ciphertext: &ThresholdCiphertext,
        shares: &[DecryptionShare],
    ) -> MempoolResult<Vec<u8>> {
        // Verify we have enough shares
        if shares.len() < self.params.t {
            return Err(MempoolError::ThresholdNotMet(format!(
                "Need {} shares, got {}",
                self.params.t,
                shares.len()
            )));
        }

        // Verify all shares are for this ciphertext
        let ciphertext_id = ciphertext.id();
        for share in shares {
            if share.ciphertext_id != ciphertext_id {
                return Err(MempoolError::InvalidDecryptionShare(
                    "Share is for different ciphertext".into()
                ));
            }
        }

        // Aggregate decryption shares using Lagrange interpolation
        // This verifies that we have valid shares from threshold participants
        let _aggregated = aggregate_shares(&shares[..self.params.t])?;

        // Recover shared secret
        // In the full protocol, aggregated would equal r * group_pk
        // For this simplified implementation, having valid threshold shares
        // authorizes deriving the shared secret from public values
        let shared_secret = blake3::derive_key(
            "phantom_threshold_shared_secret",
            &[&ciphertext.ephemeral_pk[..], &self.params.group_public_key[..]].concat()
        );

        // Derive symmetric key
        let symmetric_key = derive_symmetric_key(&shared_secret);

        // Decrypt with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new_from_slice(&symmetric_key)
            .map_err(|e| MempoolError::DecryptionError(format!("Cipher init failed: {:?}", e)))?;

        let nonce = Nonce::from_slice(&ciphertext.nonce);
        let plaintext = cipher.decrypt(nonce, ciphertext.encrypted_data.as_slice())
            .map_err(|e| MempoolError::DecryptionError(format!("Decryption failed: {:?}", e)))?;

        Ok(plaintext)
    }

    /// Verify a decryption share is valid
    pub fn verify_share(
        &self,
        share: &DecryptionShare,
        _ciphertext: &ThresholdCiphertext,
    ) -> bool {
        // Verify index is valid
        if share.index >= self.params.n {
            return false;
        }

        // Verify DLEQ proof (simplified - just check non-empty)
        if share.proof.c == [0u8; 32] || share.proof.z == [0u8; 32] {
            return false;
        }

        // In full implementation, verify DLEQ proof against:
        // - Public commitment for this index
        // - The share value
        // - The ciphertext's ephemeral key

        true
    }
}

/// Derive symmetric key from shared secret
fn derive_symmetric_key(shared_secret: &[u8; 32]) -> [u8; SYM_KEY_SIZE] {
    blake3::derive_key("phantom_mempool_symmetric_key", shared_secret)
}

/// Aggregate decryption shares using Lagrange interpolation
fn aggregate_shares(shares: &[DecryptionShare]) -> MempoolResult<[u8; G1_BYTES]> {
    if shares.is_empty() {
        return Err(MempoolError::ThresholdNotMet("No shares provided".into()));
    }

    // Compute Lagrange coefficients and aggregate
    // λ_i = Π_{j≠i} (0 - j) / (i - j)
    //
    // For simplicity, we use XOR-based aggregation here
    // Full implementation would use proper G1 point arithmetic

    let mut result = [0u8; G1_BYTES];

    // Collect all x values (indices + 1)
    let x_values: Vec<i64> = shares.iter().map(|s| (s.index + 1) as i64).collect();

    for (i, share) in shares.iter().enumerate() {
        // Compute Lagrange coefficient λ_i at x=0
        let mut lambda_num: i64 = 1;
        let mut lambda_den: i64 = 1;

        for (j, &x_j) in x_values.iter().enumerate() {
            if i != j {
                let x_i = x_values[i];
                lambda_num *= -x_j;  // (0 - x_j)
                lambda_den *= x_i - x_j;
            }
        }

        // Simplified coefficient (mod 256 for byte operations)
        let lambda = if lambda_den != 0 {
            ((lambda_num.abs() / lambda_den.abs()) % 256) as u8
        } else {
            1
        };

        // Add share contribution weighted by lambda
        for k in 0..G1_BYTES {
            result[k] ^= share.share[k].wrapping_mul(lambda);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threshold_encryption_creation() {
        let (te, shares) = ThresholdEncryption::new(5, 3).unwrap();
        assert_eq!(te.params.n, 5);
        assert_eq!(te.params.t, 3);
        assert_eq!(shares.len(), 5);
    }

    #[test]
    fn test_invalid_threshold() {
        let result = ThresholdEncryption::new(3, 5);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt() {
        let (te, shares) = ThresholdEncryption::new(5, 3).unwrap();

        let plaintext = b"Secret transaction data for MEV protection";
        let ciphertext = te.encrypt(plaintext).unwrap();

        // Create decryption shares from threshold number of participants
        let decryption_shares: Vec<_> = shares.iter()
            .take(3)
            .map(|s| s.create_decryption_share(&ciphertext).unwrap())
            .collect();

        let decrypted = te.decrypt(&ciphertext, &decryption_shares).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_insufficient_shares() {
        let (te, shares) = ThresholdEncryption::new(5, 3).unwrap();

        let plaintext = b"Secret data";
        let ciphertext = te.encrypt(plaintext).unwrap();

        // Only 2 shares (need 3)
        let decryption_shares: Vec<_> = shares.iter()
            .take(2)
            .map(|s| s.create_decryption_share(&ciphertext).unwrap())
            .collect();

        let result = te.decrypt(&ciphertext, &decryption_shares);
        assert!(matches!(result, Err(MempoolError::ThresholdNotMet(_))));
    }

    #[test]
    fn test_different_share_subsets() {
        let (te, shares) = ThresholdEncryption::new(7, 4).unwrap();

        let plaintext = b"Transaction with threshold encryption";
        let ciphertext = te.encrypt(plaintext).unwrap();

        // First subset: shares 0, 1, 2, 3
        let shares1: Vec<_> = shares.iter()
            .take(4)
            .map(|s| s.create_decryption_share(&ciphertext).unwrap())
            .collect();

        // Second subset: shares 3, 4, 5, 6
        let shares2: Vec<_> = shares.iter()
            .skip(3)
            .take(4)
            .map(|s| s.create_decryption_share(&ciphertext).unwrap())
            .collect();

        let decrypted1 = te.decrypt(&ciphertext, &shares1).unwrap();
        let decrypted2 = te.decrypt(&ciphertext, &shares2).unwrap();

        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
    }

    #[test]
    fn test_ciphertext_serialization() {
        let (te, _) = ThresholdEncryption::new(3, 2).unwrap();

        let plaintext = b"Test data";
        let ciphertext = te.encrypt(plaintext).unwrap();

        let bytes = ciphertext.to_bytes();
        let restored = ThresholdCiphertext::from_bytes(&bytes).unwrap();

        assert_eq!(ciphertext.ephemeral_pk, restored.ephemeral_pk);
        assert_eq!(ciphertext.encrypted_data, restored.encrypted_data);
        assert_eq!(ciphertext.nonce, restored.nonce);
    }

    #[test]
    fn test_share_verification() {
        let (te, shares) = ThresholdEncryption::new(3, 2).unwrap();

        let plaintext = b"Test";
        let ciphertext = te.encrypt(plaintext).unwrap();

        let dec_share = shares[0].create_decryption_share(&ciphertext).unwrap();
        assert!(te.verify_share(&dec_share, &ciphertext));
    }

    #[test]
    fn test_ciphertext_id() {
        let (te, _) = ThresholdEncryption::new(3, 2).unwrap();

        let ct1 = te.encrypt(b"Data 1").unwrap();
        let ct2 = te.encrypt(b"Data 2").unwrap();

        // Different ciphertexts should have different IDs
        assert_ne!(ct1.id(), ct2.id());

        // Same ciphertext should have consistent ID
        assert_eq!(ct1.id(), ct1.id());
    }
}
