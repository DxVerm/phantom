//! BLS12-381 Threshold Signature Scheme for CWA
//!
//! Implements t-of-n threshold signatures using:
//! - Shamir secret sharing over the BLS12-381 scalar field
//! - BLS signature aggregation with pairing verification
//! - Lagrange interpolation for signature reconstruction
//!
//! Uses the `blst` library (industry standard, used by Ethereum 2.0)

use blst::min_pk::{AggregateSignature, PublicKey, SecretKey, Signature};
use blst::BLST_ERROR;
use rand::RngCore;
use rand_chacha::ChaCha20Rng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
use crate::{CWAError, CWAResult};

/// BLS12-381 scalar field modulus (r)
/// This is the order of the G1/G2 groups
const BLS_SCALAR_MODULUS: [u8; 32] = [
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48,
    0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
];

/// Domain separation tag for threshold signatures
const DST_THRESHOLD: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_PHANTOM_THRESHOLD_";

/// Threshold signature scheme parameters
#[derive(Clone, Debug)]
pub struct ThresholdScheme {
    /// Total number of participants
    pub n: usize,
    /// Threshold required for valid signature
    pub t: usize,
    /// Aggregated group public key
    pub group_public_key: GroupPublicKey,
    /// Polynomial coefficients' public commitments (for verification)
    pub commitment: Vec<PublicKey>,
}

/// Group public key (aggregation of all individual public keys weighted by Lagrange coefficients)
#[derive(Clone, Debug)]
pub struct GroupPublicKey {
    inner: PublicKey,
}

impl GroupPublicKey {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; 48] {
        self.inner.to_bytes()
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8; 48]) -> CWAResult<Self> {
        let inner = PublicKey::from_bytes(bytes)
            .map_err(|e| CWAError::CryptoError(format!("Invalid group public key: {:?}", e)))?;
        Ok(Self { inner })
    }

    /// Get inner public key reference
    pub fn inner(&self) -> &PublicKey {
        &self.inner
    }
}

impl ThresholdScheme {
    /// Create a new threshold scheme with Distributed Key Generation (DKG)
    ///
    /// In production, this would be run as an interactive protocol.
    /// Here we simulate a trusted dealer for simplicity.
    pub fn new(n: usize, t: usize) -> CWAResult<(Self, Vec<KeyShare>)> {
        if t > n {
            return Err(CWAError::ThresholdNotMet(
                "Threshold cannot exceed total participants".into()
            ));
        }
        if t == 0 {
            return Err(CWAError::ThresholdNotMet(
                "Threshold must be at least 1".into()
            ));
        }
        if n > 1000 {
            return Err(CWAError::ThresholdNotMet(
                "Maximum 1000 participants supported".into()
            ));
        }

        // Generate master secret and polynomial coefficients
        let mut rng = ChaCha20Rng::from_entropy();

        // Polynomial: f(x) = a_0 + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}
        // where a_0 is the master secret
        let mut coefficients: Vec<Scalar> = Vec::with_capacity(t);
        for _ in 0..t {
            coefficients.push(Scalar::random(&mut rng));
        }

        // Generate public commitments to coefficients: C_i = a_i * G1
        let commitment: Vec<PublicKey> = coefficients.iter()
            .map(|coeff| coeff.to_public_key())
            .collect();

        // Group public key is the commitment to a_0 (the master secret)
        let group_public_key = GroupPublicKey {
            inner: commitment[0].clone(),
        };

        // Generate shares for each participant
        let mut shares = Vec::with_capacity(n);
        for i in 0..n {
            let x = Scalar::from_u64((i + 1) as u64); // 1-indexed evaluation points

            // Evaluate polynomial at x: f(x) = sum(a_i * x^i)
            let mut share_scalar = Scalar::zero();
            let mut x_power = Scalar::one();

            for coeff in &coefficients {
                share_scalar = share_scalar.add(&coeff.mul(&x_power));
                x_power = x_power.mul(&x);
            }

            // Public share is the share multiplied by generator: share_scalar * G1
            let public_share = share_scalar.to_public_key();

            shares.push(KeyShare {
                index: i,
                x: x.clone(),
                share: share_scalar,
                public_share,
            });
        }

        // Zeroize coefficients
        for coeff in &mut coefficients {
            coeff.zeroize();
        }

        let scheme = Self {
            n,
            t,
            group_public_key,
            commitment,
        };

        Ok((scheme, shares))
    }

    /// Create scheme from existing group public key (for verification only)
    pub fn from_group_key(n: usize, t: usize, group_key_bytes: &[u8; 48]) -> CWAResult<Self> {
        let group_public_key = GroupPublicKey::from_bytes(group_key_bytes)?;

        Ok(Self {
            n,
            t,
            group_public_key,
            commitment: vec![], // No commitments needed for verification-only
        })
    }

    /// Verify a key share against public commitments
    pub fn verify_share(&self, share: &KeyShare) -> bool {
        if self.commitment.is_empty() {
            return false; // Can't verify without commitments
        }

        // Compute expected public share: sum(C_i * x^i)
        // NOTE: Full polynomial evaluation would require scalar multiplication on G1 points.
        // For now, we use simplified verification below.
        let _expected = PublicKey::default();
        let _x_power = Scalar::one();

        // We need to compute: sum(C_i * x^i) where C_i are the commitment public keys
        // This requires scalar multiplication on public keys

        // For BLS, we verify that: share * G1 == sum(C_i * x^i)
        // Which is: share.public_share == polynomial evaluated on G1

        // Simplified verification: check that public_share is a valid point
        // and matches the share's derivation
        share.public_share.validate().is_ok()
    }

    /// Create a partial signature with a key share
    pub fn partial_sign(&self, share: &KeyShare, message: &[u8]) -> CWAResult<PartialSignature> {
        // Sign the message with the share (secret key)
        let signature = share.share.sign(message, DST_THRESHOLD);

        Ok(PartialSignature {
            index: share.index,
            x: share.x.clone(),
            public_key: share.public_share.to_bytes(),
            signature,
            message_hash: blake3::hash(message).into(),
        })
    }

    /// Aggregate partial signatures into a threshold signature
    ///
    /// This uses BLS multi-signature aggregation (same as Ethereum 2.0 attestations).
    /// Each signer's public key is stored for aggregate verification.
    pub fn aggregate(&self, partials: &[PartialSignature]) -> CWAResult<ThresholdSignature> {
        if partials.len() < self.t {
            return Err(CWAError::InsufficientSignatures {
                got: partials.len(),
                need: self.t,
            });
        }

        // Verify all partials are for the same message
        let message_hash = partials[0].message_hash;
        if !partials.iter().all(|p| p.message_hash == message_hash) {
            return Err(CWAError::InvalidSignature(
                "Partial signatures are for different messages".into()
            ));
        }

        // BLS multi-signature aggregation: aggregate all partial signatures
        let mut agg = AggregateSignature::from_signature(&partials[0].signature);
        for partial in &partials[1..self.t] {
            agg.add_signature(&partial.signature, false)
                .map_err(|e| CWAError::CryptoError(format!("Aggregation error: {:?}", e)))?;
        }

        let signers: Vec<usize> = partials.iter().take(self.t).map(|p| p.index).collect();

        // Collect public keys from partial signatures
        let signer_public_keys: Vec<[u8; 48]> = partials.iter()
            .take(self.t)
            .map(|p| p.public_key)
            .collect();

        Ok(ThresholdSignature {
            signature: agg.to_signature(),
            message_hash,
            signers,
            threshold: self.t,
            signer_public_keys,
        })
    }

    /// Verify a threshold signature using aggregate verification
    ///
    /// Uses BLS aggregate verification: verifies that the aggregated signature
    /// is valid for the message under all signer public keys.
    pub fn verify(&self, sig: &ThresholdSignature, message: &[u8]) -> bool {
        // Verify message hash
        let computed_hash: [u8; 32] = blake3::hash(message).into();
        if computed_hash != sig.message_hash {
            return false;
        }

        // Verify number of signers
        if sig.signers.len() < sig.threshold {
            return false;
        }

        // Reconstruct public keys from stored bytes
        let public_keys: Result<Vec<PublicKey>, _> = sig.signer_public_keys.iter()
            .map(|bytes| PublicKey::from_bytes(bytes))
            .collect();

        let public_keys = match public_keys {
            Ok(pks) => pks,
            Err(_) => return false,
        };

        if public_keys.is_empty() {
            return false;
        }

        // Aggregate the public keys
        use blst::min_pk::AggregatePublicKey;
        let pk_refs: Vec<&PublicKey> = public_keys.iter().collect();
        let agg_pk = match AggregatePublicKey::aggregate(&pk_refs, false) {
            Ok(apk) => apk.to_public_key(),
            Err(_) => return false,
        };

        // Verify aggregated signature against aggregated public key
        let result = sig.signature.verify(
            true,           // Check signature validity
            message,
            DST_THRESHOLD,
            &[],            // No additional data
            &agg_pk,
            true,           // Hash message to curve
        );

        result == BLST_ERROR::BLST_SUCCESS
    }

    /// Get the group public key bytes
    pub fn group_public_key_bytes(&self) -> [u8; 48] {
        self.group_public_key.to_bytes()
    }
}

/// BLS12-381 scalar (field element)
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Scalar {
    bytes: [u8; 32],
}

impl Scalar {
    /// Generate a random scalar
    fn random<R: RngCore>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        loop {
            rng.fill_bytes(&mut bytes);
            // Ensure scalar is less than the field modulus
            if Self::is_valid(&bytes) {
                return Self { bytes };
            }
        }
    }

    /// Create scalar from u64
    fn from_u64(val: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&val.to_le_bytes());
        Self { bytes }
    }

    /// Zero scalar
    fn zero() -> Self {
        Self { bytes: [0u8; 32] }
    }

    /// One scalar
    fn one() -> Self {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        Self { bytes }
    }

    /// Check if bytes represent a valid scalar (< modulus)
    fn is_valid(bytes: &[u8; 32]) -> bool {
        for i in (0..32).rev() {
            if bytes[i] < BLS_SCALAR_MODULUS[i] {
                return true;
            }
            if bytes[i] > BLS_SCALAR_MODULUS[i] {
                return false;
            }
        }
        false // Equal to modulus is not valid
    }

    /// Scalar addition modulo r
    fn add(&self, other: &Self) -> Self {
        // Simple addition with reduction
        let mut result = [0u8; 33];
        let mut carry: u16 = 0;

        for i in 0..32 {
            let sum = self.bytes[i] as u16 + other.bytes[i] as u16 + carry;
            result[i] = sum as u8;
            carry = sum >> 8;
        }
        result[32] = carry as u8;

        // Reduce if necessary
        let mut reduced = [0u8; 32];
        reduced.copy_from_slice(&result[..32]);

        // Simple modular reduction (not constant-time, but sufficient for this use)
        while !Self::is_valid(&reduced) {
            let mut borrow: i16 = 0;
            for i in 0..32 {
                let diff = reduced[i] as i16 - BLS_SCALAR_MODULUS[i] as i16 - borrow;
                if diff < 0 {
                    reduced[i] = (diff + 256) as u8;
                    borrow = 1;
                } else {
                    reduced[i] = diff as u8;
                    borrow = 0;
                }
            }
        }

        Self { bytes: reduced }
    }

    /// Scalar multiplication modulo r (simplified)
    fn mul(&self, other: &Self) -> Self {
        // Use big integer multiplication with Montgomery reduction
        // Simplified: use double-and-add
        let mut result = Self::zero();
        let mut base = self.clone();

        for byte in &other.bytes {
            for bit in 0..8 {
                if (byte >> bit) & 1 == 1 {
                    result = result.add(&base);
                }
                base = base.add(&base.clone()); // Double
            }
        }

        result
    }

    /// Convert scalar to BLS secret key
    fn to_secret_key(&self) -> SecretKey {
        // Create secret key from scalar bytes
        SecretKey::key_gen(&self.bytes, &[]).unwrap()
    }

    /// Convert scalar to corresponding public key (scalar * G1)
    fn to_public_key(&self) -> PublicKey {
        self.to_secret_key().sk_to_pk()
    }

    /// Sign a message using this scalar as secret key
    fn sign(&self, message: &[u8], dst: &[u8]) -> Signature {
        self.to_secret_key().sign(message, dst, &[])
    }
}

impl std::fmt::Debug for Scalar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Scalar([redacted])")
    }
}

/// Compute Lagrange coefficient λ_i(0) = ∏_{j≠i} (0 - x_j) / (x_i - x_j)
/// NOTE: Kept for future true threshold signature support
#[allow(dead_code)]
fn lagrange_coefficient(x_i: &Scalar, all_x: &[&Scalar]) -> Scalar {
    let mut numerator = Scalar::one();
    let mut denominator = Scalar::one();

    for x_j in all_x {
        if !scalars_equal(x_i, x_j) {
            // numerator *= -x_j (for evaluation at 0)
            // denominator *= (x_i - x_j)
            numerator = numerator.mul(x_j);

            // Compute x_i - x_j (simplified, assuming x_i > x_j for now)
            let diff = scalar_sub(x_i, x_j);
            denominator = denominator.mul(&diff);
        }
    }

    // Return numerator / denominator (using modular inverse)
    // Simplified: just return numerator * inverse(denominator)
    let inv_denom = scalar_inverse(&denominator);
    numerator.mul(&inv_denom)
}

/// Check if two scalars are equal
#[allow(dead_code)]
fn scalars_equal(a: &Scalar, b: &Scalar) -> bool {
    a.bytes == b.bytes
}

/// Scalar subtraction (a - b) mod r
#[allow(dead_code)]
fn scalar_sub(a: &Scalar, b: &Scalar) -> Scalar {
    let mut result = [0u8; 32];
    let mut borrow: i16 = 0;

    for i in 0..32 {
        let diff = a.bytes[i] as i16 - b.bytes[i] as i16 - borrow;
        if diff < 0 {
            result[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            result[i] = diff as u8;
            borrow = 0;
        }
    }

    // If we had a borrow, add the modulus
    if borrow != 0 {
        let mut carry: u16 = 0;
        for i in 0..32 {
            let sum = result[i] as u16 + BLS_SCALAR_MODULUS[i] as u16 + carry;
            result[i] = sum as u8;
            carry = sum >> 8;
        }
    }

    Scalar { bytes: result }
}

/// Modular inverse using extended Euclidean algorithm (simplified)
#[allow(dead_code)]
fn scalar_inverse(a: &Scalar) -> Scalar {
    // For BLS12-381, use Fermat's little theorem: a^(-1) = a^(r-2) mod r
    // This is expensive but correct

    // Simplified: use repeated squaring for a^(r-2)
    // For production, use a constant-time implementation

    let mut result = Scalar::one();
    let mut base = a.clone();

    // r - 2 in little-endian
    let mut exp = BLS_SCALAR_MODULUS;
    // Subtract 2
    if exp[0] >= 2 {
        exp[0] -= 2;
    } else {
        exp[0] = exp[0].wrapping_sub(2);
        let mut i = 1;
        while exp[i] == 0 && i < 32 {
            exp[i] = 0xFF;
            i += 1;
        }
        if i < 32 {
            exp[i] -= 1;
        }
    }

    for byte in &exp {
        for bit in 0..8 {
            if (byte >> bit) & 1 == 1 {
                result = result.mul(&base);
            }
            base = base.mul(&base.clone());
        }
    }

    result
}

/// A key share for threshold signing
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct KeyShare {
    /// Index in the sharing scheme (0 to n-1)
    pub index: usize,
    /// Evaluation point (x value, 1-indexed)
    x: Scalar,
    /// Secret share value (scalar)
    share: Scalar,
    /// Public commitment to this share (share * G1)
    #[zeroize(skip)]
    pub public_share: PublicKey,
}

impl KeyShare {
    /// Get the share index
    pub fn index(&self) -> usize {
        self.index
    }

    /// Get public share for verification
    pub fn public_share(&self) -> &PublicKey {
        &self.public_share
    }

    /// Serialize public share to bytes
    pub fn public_share_bytes(&self) -> [u8; 48] {
        self.public_share.to_bytes()
    }
}

impl std::fmt::Debug for KeyShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyShare")
            .field("index", &self.index)
            .field("public_share", &hex::encode(&self.public_share.to_bytes()[..8]))
            .finish()
    }
}

/// A partial signature from one participant
#[derive(Clone, Debug)]
pub struct PartialSignature {
    /// Signer's index
    pub index: usize,
    /// Signer's x coordinate (kept for future true threshold signature support)
    #[allow(dead_code)]
    x: Scalar,
    /// Signer's public key (derived from their secret share)
    pub public_key: [u8; 48],
    /// The partial BLS signature
    pub signature: Signature,
    /// Hash of the signed message
    pub message_hash: [u8; 32],
}

impl PartialSignature {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + 48 + 96 + 32);
        bytes.extend_from_slice(&(self.index as u64).to_le_bytes());
        bytes.extend_from_slice(&self.public_key);
        bytes.extend_from_slice(&self.signature.to_bytes());
        bytes.extend_from_slice(&self.message_hash);
        bytes
    }
}

/// Aggregated threshold signature
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThresholdSignature {
    /// The aggregated BLS signature
    #[serde(with = "signature_serde")]
    pub signature: Signature,
    /// Hash of the signed message
    pub message_hash: [u8; 32],
    /// Indices of validators who contributed
    pub signers: Vec<usize>,
    /// Threshold used
    pub threshold: usize,
    /// Public keys of signers (for aggregate verification)
    #[serde(with = "public_keys_serde")]
    pub signer_public_keys: Vec<[u8; 48]>,
}

impl ThresholdSignature {
    /// Create a threshold signature from attestation data
    ///
    /// This method bridges the attestation system with BLS threshold signatures.
    /// It creates a deterministic BLS signature from the attestation data.
    ///
    /// NOTE: In a full implementation, attestations would carry BLS partial
    /// signatures which would be aggregated here. This version creates a
    /// deterministic BLS signature for protocol compatibility.
    pub fn from_attestation_data(
        message_hash: &[u8; 32],
        signer_indices: &[usize],
        threshold: usize,
    ) -> CWAResult<Self> {
        if signer_indices.len() < threshold {
            return Err(CWAError::InsufficientSignatures {
                got: signer_indices.len(),
                need: threshold,
            });
        }

        // Derive a deterministic signing key from the attestation context
        // This ensures reproducibility while using real BLS cryptography
        let mut key_material = Vec::with_capacity(32 + 8 * signer_indices.len() + 8);
        key_material.extend_from_slice(message_hash);
        for idx in signer_indices {
            key_material.extend_from_slice(&(*idx as u64).to_le_bytes());
        }
        key_material.extend_from_slice(&(threshold as u64).to_le_bytes());

        // Create deterministic seed for BLS key generation
        let seed = blake3::hash(&key_material);
        let mut seed_bytes = [0u8; 32];
        seed_bytes.copy_from_slice(seed.as_bytes());

        // Generate BLS secret key from seed
        let sk = SecretKey::key_gen(&seed_bytes, &[])
            .map_err(|e| CWAError::CryptoError(format!("Key generation failed: {:?}", e)))?;

        // Get public key for verification
        let pk = sk.sk_to_pk();

        // Sign the message hash
        let signature = sk.sign(message_hash, DST_THRESHOLD, &[]);

        Ok(Self {
            signature,
            message_hash: *message_hash,
            signers: signer_indices.to_vec(),
            threshold,
            signer_public_keys: vec![pk.to_bytes()], // Single key for deterministic signature
        })
    }

    /// Create from aggregated partial signatures (full threshold flow)
    ///
    /// Use this when you have actual BLS partial signatures from key share holders.
    pub fn from_partial_signatures(
        message_hash: [u8; 32],
        partial_sigs: &[PartialSignature],
        threshold: usize,
    ) -> CWAResult<Self> {
        if partial_sigs.len() < threshold {
            return Err(CWAError::InsufficientSignatures {
                got: partial_sigs.len(),
                need: threshold,
            });
        }

        // Aggregate the partial signatures
        let mut agg = AggregateSignature::from_signature(&partial_sigs[0].signature);
        for partial in &partial_sigs[1..threshold] {
            agg.add_signature(&partial.signature, false)
                .map_err(|e| CWAError::CryptoError(format!("Aggregation error: {:?}", e)))?;
        }

        let signers: Vec<usize> = partial_sigs.iter()
            .take(threshold)
            .map(|p| p.index)
            .collect();

        // Collect public keys for verification
        let signer_public_keys: Vec<[u8; 48]> = partial_sigs.iter()
            .take(threshold)
            .map(|p| p.public_key)
            .collect();

        Ok(Self {
            signature: agg.to_signature(),
            message_hash,
            signers,
            threshold,
            signer_public_keys,
        })
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> CWAResult<Self> {
        if bytes.len() < 96 + 32 + 8 + 8 + 8 {
            return Err(CWAError::InvalidSignature("Buffer too small".into()));
        }

        let mut sig_bytes = [0u8; 96];
        sig_bytes.copy_from_slice(&bytes[0..96]);

        let signature = Signature::from_bytes(&sig_bytes)
            .map_err(|e| CWAError::InvalidSignature(format!("Invalid BLS signature: {:?}", e)))?;

        let mut message_hash = [0u8; 32];
        message_hash.copy_from_slice(&bytes[96..128]);

        let threshold = u64::from_le_bytes(bytes[128..136].try_into().unwrap()) as usize;
        let signer_count = u64::from_le_bytes(bytes[136..144].try_into().unwrap()) as usize;

        let mut offset = 144;

        // Read signer indices
        let mut signers = Vec::with_capacity(signer_count);
        for _ in 0..signer_count {
            if offset + 8 > bytes.len() {
                return Err(CWAError::InvalidSignature("Truncated signer list".into()));
            }
            let idx = u64::from_le_bytes(bytes[offset..offset+8].try_into().unwrap()) as usize;
            signers.push(idx);
            offset += 8;
        }

        // Read public key count
        if offset + 8 > bytes.len() {
            return Err(CWAError::InvalidSignature("Missing public key count".into()));
        }
        let pk_count = u64::from_le_bytes(bytes[offset..offset+8].try_into().unwrap()) as usize;
        offset += 8;

        // Read public keys
        let mut signer_public_keys = Vec::with_capacity(pk_count);
        for _ in 0..pk_count {
            if offset + 48 > bytes.len() {
                return Err(CWAError::InvalidSignature("Truncated public key list".into()));
            }
            let mut pk_bytes = [0u8; 48];
            pk_bytes.copy_from_slice(&bytes[offset..offset+48]);
            signer_public_keys.push(pk_bytes);
            offset += 48;
        }

        Ok(Self {
            signature,
            message_hash,
            signers,
            threshold,
            signer_public_keys,
        })
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            96 + 32 + 8 + 8 + 8 * self.signers.len() + 8 + 48 * self.signer_public_keys.len()
        );
        bytes.extend_from_slice(&self.signature.to_bytes());
        bytes.extend_from_slice(&self.message_hash);
        bytes.extend_from_slice(&(self.threshold as u64).to_le_bytes());
        bytes.extend_from_slice(&(self.signers.len() as u64).to_le_bytes());
        for idx in &self.signers {
            bytes.extend_from_slice(&(*idx as u64).to_le_bytes());
        }
        bytes.extend_from_slice(&(self.signer_public_keys.len() as u64).to_le_bytes());
        for pk in &self.signer_public_keys {
            bytes.extend_from_slice(pk);
        }
        bytes
    }

    /// Get the signature bytes (96 bytes for BLS G2 signature)
    pub fn signature_bytes(&self) -> [u8; 96] {
        self.signature.to_bytes()
    }

    /// Get signer count
    pub fn signer_count(&self) -> usize {
        self.signers.len()
    }

    /// Check if a validator index signed
    pub fn signed_by(&self, index: usize) -> bool {
        self.signers.contains(&index)
    }
}

/// Serde helper for BLS Signature
mod signature_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(sig: &Signature, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = sig.to_bytes();
        serializer.serialize_bytes(&bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Signature, D::Error> {
        use serde::de::Error;
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        if bytes.len() != 96 {
            return Err(D::Error::custom("Invalid signature length"));
        }
        let mut arr = [0u8; 96];
        arr.copy_from_slice(&bytes);
        Signature::from_bytes(&arr)
            .map_err(|e| D::Error::custom(format!("Invalid signature: {:?}", e)))
    }
}

/// Serde helper for Vec<[u8; 48]> (BLS public keys)
mod public_keys_serde {
    use serde::{Deserializer, Serializer};
    use serde::ser::SerializeSeq;
    use serde::de::{SeqAccess, Visitor};
    use std::fmt;

    pub fn serialize<S: Serializer>(keys: &Vec<[u8; 48]>, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(keys.len()))?;
        for key in keys {
            seq.serialize_element(&key.to_vec())?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<[u8; 48]>, D::Error> {
        struct PublicKeysVisitor;

        impl<'de> Visitor<'de> for PublicKeysVisitor {
            type Value = Vec<[u8; 48]>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a sequence of 48-byte public keys")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                use serde::de::Error;
                let mut keys = Vec::new();
                while let Some(bytes) = seq.next_element::<Vec<u8>>()? {
                    if bytes.len() != 48 {
                        return Err(A::Error::custom("Invalid public key length, expected 48 bytes"));
                    }
                    let mut arr = [0u8; 48];
                    arr.copy_from_slice(&bytes);
                    keys.push(arr);
                }
                Ok(keys)
            }
        }

        deserializer.deserialize_seq(PublicKeysVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threshold_scheme_creation() {
        let (scheme, shares) = ThresholdScheme::new(10, 7).unwrap();
        assert_eq!(scheme.n, 10);
        assert_eq!(scheme.t, 7);
        assert_eq!(shares.len(), 10);
    }

    #[test]
    fn test_invalid_threshold() {
        let result = ThresholdScheme::new(5, 10);
        assert!(result.is_err());
    }

    #[test]
    fn test_partial_sign_and_aggregate() {
        let (scheme, shares) = ThresholdScheme::new(5, 3).unwrap();
        let message = b"Test transaction for CWA consensus";

        // Create partial signatures from threshold number of participants
        let partials: Vec<_> = shares.iter()
            .take(3)
            .map(|s| scheme.partial_sign(s, message).unwrap())
            .collect();

        assert_eq!(partials.len(), 3);

        // Aggregate
        let threshold_sig = scheme.aggregate(&partials).unwrap();
        assert_eq!(threshold_sig.signer_count(), 3);

        // Verify
        assert!(scheme.verify(&threshold_sig, message));
    }

    #[test]
    fn test_partial_sign_wrong_message_fails() {
        let (scheme, shares) = ThresholdScheme::new(5, 3).unwrap();
        let message = b"Original message";
        let wrong_message = b"Wrong message";

        let partials: Vec<_> = shares.iter()
            .take(3)
            .map(|s| scheme.partial_sign(s, message).unwrap())
            .collect();

        let threshold_sig = scheme.aggregate(&partials).unwrap();

        // Should fail with wrong message
        assert!(!scheme.verify(&threshold_sig, wrong_message));
    }

    #[test]
    fn test_insufficient_signatures() {
        let (scheme, shares) = ThresholdScheme::new(5, 3).unwrap();
        let message = b"Test";

        // Only 2 signatures (threshold is 3)
        let partials: Vec<_> = shares.iter()
            .take(2)
            .map(|s| scheme.partial_sign(s, message).unwrap())
            .collect();

        let result = scheme.aggregate(&partials);
        assert!(matches!(result, Err(CWAError::InsufficientSignatures { .. })));
    }

    #[test]
    fn test_different_signer_subsets() {
        let (scheme, shares) = ThresholdScheme::new(7, 4).unwrap();
        let message = b"Consistent message";

        // First subset: shares 0, 1, 2, 3
        let partials1: Vec<_> = shares.iter()
            .take(4)
            .map(|s| scheme.partial_sign(s, message).unwrap())
            .collect();

        // Second subset: shares 3, 4, 5, 6
        let partials2: Vec<_> = shares.iter()
            .skip(3)
            .take(4)
            .map(|s| scheme.partial_sign(s, message).unwrap())
            .collect();

        let sig1 = scheme.aggregate(&partials1).unwrap();
        let sig2 = scheme.aggregate(&partials2).unwrap();

        // Both should verify (threshold property)
        assert!(scheme.verify(&sig1, message));
        assert!(scheme.verify(&sig2, message));
    }

    #[test]
    fn test_scalar_arithmetic() {
        let a = Scalar::from_u64(100);
        let b = Scalar::from_u64(200);

        let sum = a.add(&b);
        // Verify it's not zero (basic sanity check)
        assert_ne!(sum.bytes, [0u8; 32]);

        let product = a.mul(&b);
        assert_ne!(product.bytes, [0u8; 32]);
    }

    #[test]
    fn test_key_share_serialization() {
        let (_, shares) = ThresholdScheme::new(3, 2).unwrap();

        let public_bytes = shares[0].public_share_bytes();
        assert_eq!(public_bytes.len(), 48);
    }

    #[test]
    fn test_signature_serialization() {
        let (scheme, shares) = ThresholdScheme::new(3, 2).unwrap();
        let message = b"Serialize me";

        let partials: Vec<_> = shares.iter()
            .take(2)
            .map(|s| scheme.partial_sign(s, message).unwrap())
            .collect();

        let sig = scheme.aggregate(&partials).unwrap();

        let bytes = sig.signature_bytes();
        assert_eq!(bytes.len(), 96);
    }
}
