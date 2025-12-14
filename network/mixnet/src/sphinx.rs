//! Sphinx packet format for onion routing
//!
//! Implements the Sphinx packet format for anonymous communication:
//! - Constant-size packets prevent traffic analysis
//! - Layered encryption with per-hop keys
//! - SURB (Single-Use Reply Block) support for anonymous replies

use serde::{Deserialize, Serialize};
use crate::errors::{MixnetError, MixnetResult};

/// Maximum payload size in bytes
pub const MAX_PAYLOAD_SIZE: usize = 4096;

/// Header size per hop
pub const HOP_HEADER_SIZE: usize = 64;

/// Maximum number of hops
pub const MAX_HOPS: usize = 10;

/// Tag size for authentication
pub const TAG_SIZE: usize = 16;

/// A Sphinx packet with layered encryption
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SphinxPacket {
    /// Version byte
    pub version: u8,
    /// Ephemeral public key for ECDH
    pub ephemeral_key: [u8; 32],
    /// Encrypted routing info (headers for each hop)
    pub routing_info: Vec<u8>,
    /// Authentication tag
    pub tag: [u8; TAG_SIZE],
    /// Encrypted payload
    pub payload: Vec<u8>,
}

/// Routing information for a single hop
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HopInfo {
    /// Next hop identifier (or final destination marker)
    pub next_hop: [u8; 32],
    /// Delay in milliseconds (for timing attack resistance)
    pub delay_ms: u32,
    /// Flags (e.g., is_final, requires_ack)
    pub flags: u8,
    /// Padding/reserved
    pub reserved: [u8; 27],
}

/// Flags for hop routing
pub mod hop_flags {
    pub const IS_FINAL: u8 = 0x01;
    pub const REQUIRES_ACK: u8 = 0x02;
    pub const IS_SURB_REPLY: u8 = 0x04;
}

impl HopInfo {
    /// Create hop info for an intermediate node
    pub fn intermediate(next_hop: [u8; 32], delay_ms: u32) -> Self {
        Self {
            next_hop,
            delay_ms,
            flags: 0,
            reserved: [0u8; 27],
        }
    }

    /// Create hop info for the final destination
    pub fn final_hop(destination: [u8; 32]) -> Self {
        Self {
            next_hop: destination,
            delay_ms: 0,
            flags: hop_flags::IS_FINAL,
            reserved: [0u8; 27],
        }
    }

    /// Check if this is the final hop
    pub fn is_final(&self) -> bool {
        self.flags & hop_flags::IS_FINAL != 0
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; HOP_HEADER_SIZE] {
        let mut bytes = [0u8; HOP_HEADER_SIZE];
        bytes[0..32].copy_from_slice(&self.next_hop);
        bytes[32..36].copy_from_slice(&self.delay_ms.to_le_bytes());
        bytes[36] = self.flags;
        bytes[37..64].copy_from_slice(&self.reserved);
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8; HOP_HEADER_SIZE]) -> Self {
        let mut next_hop = [0u8; 32];
        next_hop.copy_from_slice(&bytes[0..32]);
        let delay_ms = u32::from_le_bytes(bytes[32..36].try_into().unwrap());
        let flags = bytes[36];
        let mut reserved = [0u8; 27];
        reserved.copy_from_slice(&bytes[37..64]);

        Self {
            next_hop,
            delay_ms,
            flags,
            reserved,
        }
    }
}

impl SphinxPacket {
    /// Current protocol version
    pub const VERSION: u8 = 1;

    /// Create a new Sphinx packet
    pub fn create(
        payload: &[u8],
        route: &[MixNodeInfo],
        destination: &[u8; 32],
    ) -> MixnetResult<Self> {
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(MixnetError::PacketTooLarge {
                size: payload.len(),
                max: MAX_PAYLOAD_SIZE,
            });
        }

        if route.len() > MAX_HOPS {
            return Err(MixnetError::InvalidRouting(
                format!("Too many hops: {} > {}", route.len(), MAX_HOPS)
            ));
        }

        if route.is_empty() {
            return Err(MixnetError::InvalidRouting("Empty route".into()));
        }

        // Generate ephemeral keypair
        let mut ephemeral_secret_raw = [0u8; 32];
        getrandom::getrandom(&mut ephemeral_secret_raw)
            .map_err(|e| MixnetError::CryptoError(e.to_string()))?;

        // Pre-clamp the ephemeral secret for consistent Sphinx blinding
        let ephemeral_secret = clamp_secret(&ephemeral_secret_raw);
        let ephemeral_key = derive_public_key(&ephemeral_secret);

        // Build routing info (encrypted headers) from last hop to first
        let mut routing_info = Vec::new();
        let mut shared_secrets = Vec::with_capacity(route.len());

        // Compute shared secrets for each hop, simulating the Sphinx blinding process
        // Each hop receives a blinded ephemeral key, so we must compute what
        // shared secret each hop will derive when it processes the packet
        let mut current_ephemeral_public = ephemeral_key;
        let mut current_ephemeral_secret = ephemeral_secret;

        for node in route.iter() {
            // This hop computes: ECDH(node.private_key, current_ephemeral_public)
            // Which equals: ECDH(current_ephemeral_secret, node.public_key)
            let shared = compute_shared_secret(&current_ephemeral_secret, &node.public_key);
            shared_secrets.push(shared);

            // Simulate what the hop will do: blind the ephemeral key for the next hop
            // The blinding multiplies the ephemeral by a factor derived from shared secret
            current_ephemeral_public = blind_key(&current_ephemeral_public, &shared);
            // Update the "effective" secret by multiplying with the blinding factor
            current_ephemeral_secret = derive_blinded_secret(&current_ephemeral_secret, &shared);
        }

        // Build headers in reverse order
        for (i, node) in route.iter().enumerate().rev() {
            let hop_info = if i == route.len() - 1 {
                HopInfo::final_hop(*destination)
            } else {
                HopInfo::intermediate(route[i + 1].id, random_delay())
            };

            let header_bytes = hop_info.to_bytes();

            // Encrypt header with this hop's shared secret
            let encrypted = encrypt_header(&header_bytes, &shared_secrets[i]);

            // Prepend to routing info
            let mut new_routing = encrypted;
            new_routing.extend_from_slice(&routing_info);
            routing_info = new_routing;
        }

        // Pad routing info to constant size
        let target_size = MAX_HOPS * HOP_HEADER_SIZE;
        if routing_info.len() < target_size {
            let padding_len = target_size - routing_info.len();
            let mut padding = vec![0u8; padding_len];
            getrandom::getrandom(&mut padding)
                .map_err(|e| MixnetError::CryptoError(e.to_string()))?;
            routing_info.extend_from_slice(&padding);
        }

        // Encrypt payload with all shared secrets (outermost first)
        let mut encrypted_payload = payload.to_vec();
        // Pad payload to constant size
        encrypted_payload.resize(MAX_PAYLOAD_SIZE, 0);

        for secret in shared_secrets.iter().rev() {
            encrypted_payload = encrypt_payload(&encrypted_payload, secret);
        }

        // Compute authentication tag
        let tag = compute_tag(&ephemeral_key, &routing_info, &encrypted_payload);

        Ok(Self {
            version: Self::VERSION,
            ephemeral_key,
            routing_info,
            tag,
            payload: encrypted_payload,
        })
    }

    /// Process packet at a mix node (peel one layer)
    ///
    /// Uses real X25519 ECDH and ChaCha20-Poly1305 AEAD for cryptographic operations.
    pub fn process(&self, private_key: &[u8; 32]) -> MixnetResult<ProcessedPacket> {
        // Verify version
        if self.version != Self::VERSION {
            return Err(MixnetError::InvalidPacket(
                format!("Unknown version: {}", self.version)
            ));
        }

        // Clamp the private key for consistent ECDH computation
        let clamped_private = clamp_secret(private_key);

        // Compute shared secret using raw curve25519 ECDH (not x25519 which re-clamps)
        let shared_secret = compute_shared_secret(&clamped_private, &self.ephemeral_key);

        // Verify packet-level tag (authenticates the entire packet structure)
        let expected_tag = compute_tag(&self.ephemeral_key, &self.routing_info, &self.payload);
        if !constant_time_eq(&self.tag, &expected_tag) {
            return Err(MixnetError::AuthenticationFailed);
        }

        // Account for AEAD tag overhead in encrypted headers (16 bytes for Poly1305)
        let encrypted_header_size = HOP_HEADER_SIZE + 16; // 64 + 16 = 80 bytes

        // Decrypt first header using ChaCha20-Poly1305
        if self.routing_info.len() < encrypted_header_size {
            return Err(MixnetError::InvalidPacket(
                format!("Routing info too short: {} < {}", self.routing_info.len(), encrypted_header_size)
            ));
        }

        let encrypted_header = &self.routing_info[..encrypted_header_size];
        let header_bytes = decrypt_header(encrypted_header, &shared_secret)?;
        let hop_info = HopInfo::from_bytes(&header_bytes);

        // Decrypt payload using ChaCha20-Poly1305
        let decrypted_payload = decrypt_payload(&self.payload, &shared_secret)?;

        if hop_info.is_final() {
            // Strip padding from payload (find last non-zero byte)
            let actual_len = decrypted_payload.iter()
                .rposition(|&b| b != 0)
                .map(|i| i + 1)
                .unwrap_or(0);

            Ok(ProcessedPacket::Final {
                destination: hop_info.next_hop,
                payload: decrypted_payload[..actual_len].to_vec(),
            })
        } else {
            // Shift routing info and blind ephemeral key for next hop
            let new_routing_info = shift_routing_info(&self.routing_info, &shared_secret);
            let new_ephemeral = blind_key(&self.ephemeral_key, &shared_secret);
            let new_tag = compute_tag(&new_ephemeral, &new_routing_info, &decrypted_payload);

            let next_packet = SphinxPacket {
                version: self.version,
                ephemeral_key: new_ephemeral,
                routing_info: new_routing_info,
                tag: new_tag,
                payload: decrypted_payload,
            };

            Ok(ProcessedPacket::Forward {
                next_hop: hop_info.next_hop,
                delay_ms: hop_info.delay_ms,
                packet: next_packet,
            })
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.version);
        bytes.extend_from_slice(&self.ephemeral_key);
        bytes.extend_from_slice(&(self.routing_info.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.routing_info);
        bytes.extend_from_slice(&self.tag);
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> MixnetResult<Self> {
        if bytes.len() < 1 + 32 + 4 + TAG_SIZE {
            return Err(MixnetError::InvalidPacket("Too short".into()));
        }

        let version = bytes[0];
        let mut ephemeral_key = [0u8; 32];
        ephemeral_key.copy_from_slice(&bytes[1..33]);

        let routing_len = u32::from_le_bytes(bytes[33..37].try_into().unwrap()) as usize;

        if bytes.len() < 37 + routing_len + TAG_SIZE {
            return Err(MixnetError::InvalidPacket("Invalid routing length".into()));
        }

        let routing_info = bytes[37..37 + routing_len].to_vec();
        let mut tag = [0u8; TAG_SIZE];
        tag.copy_from_slice(&bytes[37 + routing_len..37 + routing_len + TAG_SIZE]);
        let payload = bytes[37 + routing_len + TAG_SIZE..].to_vec();

        Ok(Self {
            version,
            ephemeral_key,
            routing_info,
            tag,
            payload,
        })
    }
}

/// Result of processing a Sphinx packet
#[derive(Clone, Debug)]
pub enum ProcessedPacket {
    /// Packet should be forwarded to next hop
    Forward {
        next_hop: [u8; 32],
        delay_ms: u32,
        packet: SphinxPacket,
    },
    /// Final destination reached
    Final {
        destination: [u8; 32],
        payload: Vec<u8>,
    },
}

/// Information about a mix node for route construction
#[derive(Clone, Debug)]
pub struct MixNodeInfo {
    /// Node identifier
    pub id: [u8; 32],
    /// Node public key for ECDH
    pub public_key: [u8; 32],
}

/// Single-Use Reply Block for anonymous replies
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SURB {
    /// Pre-computed first hop
    pub first_hop: [u8; 32],
    /// Pre-encrypted routing info
    pub routing_info: Vec<u8>,
    /// Keys for decrypting reply
    pub decryption_keys: Vec<[u8; 32]>,
}

impl SURB {
    /// Create a SURB for receiving anonymous replies
    pub fn create(
        route: &[MixNodeInfo],
        destination_key: &[u8; 32],
    ) -> MixnetResult<Self> {
        if route.is_empty() {
            return Err(MixnetError::InvalidRouting("Empty route".into()));
        }

        // Generate random keys for each hop
        let mut decryption_keys = Vec::with_capacity(route.len());
        let mut routing_info = Vec::new();

        for (i, node) in route.iter().enumerate().rev() {
            let mut key = [0u8; 32];
            getrandom::getrandom(&mut key)
                .map_err(|e| MixnetError::CryptoError(e.to_string()))?;

            let hop_info = if i == route.len() - 1 {
                let mut dest = HopInfo::final_hop([0u8; 32]);
                dest.flags |= hop_flags::IS_SURB_REPLY;
                dest
            } else {
                HopInfo::intermediate(route[i + 1].id, random_delay())
            };

            let encrypted = encrypt_header(&hop_info.to_bytes(), &key);
            let mut new_routing = encrypted;
            new_routing.extend_from_slice(&routing_info);
            routing_info = new_routing;

            decryption_keys.push(key);
        }

        // Reverse decryption keys so they're in the right order
        decryption_keys.reverse();

        Ok(Self {
            first_hop: route[0].id,
            routing_info,
            decryption_keys,
        })
    }

    /// Create a reply packet using this SURB
    pub fn create_reply(&self, payload: &[u8]) -> MixnetResult<SphinxPacket> {
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(MixnetError::PacketTooLarge {
                size: payload.len(),
                max: MAX_PAYLOAD_SIZE,
            });
        }

        let mut ephemeral_key = [0u8; 32];
        getrandom::getrandom(&mut ephemeral_key)
            .map_err(|e| MixnetError::CryptoError(e.to_string()))?;

        // Encrypt payload with SURB keys
        let mut encrypted_payload = payload.to_vec();
        encrypted_payload.resize(MAX_PAYLOAD_SIZE, 0);

        for key in self.decryption_keys.iter().rev() {
            encrypted_payload = encrypt_payload(&encrypted_payload, key);
        }

        let tag = compute_tag(&ephemeral_key, &self.routing_info, &encrypted_payload);

        Ok(SphinxPacket {
            version: SphinxPacket::VERSION,
            ephemeral_key,
            routing_info: self.routing_info.clone(),
            tag,
            payload: encrypted_payload,
        })
    }

    /// Decrypt a reply received via this SURB
    pub fn decrypt_reply(&self, payload: &[u8]) -> MixnetResult<Vec<u8>> {
        let mut decrypted = payload.to_vec();

        for key in &self.decryption_keys {
            decrypted = decrypt_payload(&decrypted, key)?;
        }

        // Strip padding
        let actual_len = decrypted.iter()
            .rposition(|&b| b != 0)
            .map(|i| i + 1)
            .unwrap_or(0);

        Ok(decrypted[..actual_len].to_vec())
    }
}

// =============================================================================
// REAL CRYPTOGRAPHIC IMPLEMENTATIONS
// Using curve25519 for ECDH, ChaCha20-Poly1305 for AEAD, HKDF for key derivation
// =============================================================================

use chacha20poly1305::{
    aead::{Aead, KeyInit, Nonce},
    ChaCha20Poly1305, Key,
};
use hkdf::Hkdf;
use sha2::Sha256;
// zeroize available for secure memory wiping when needed
#[allow(unused_imports)]
use zeroize::Zeroize;

/// Nonce size for ChaCha20-Poly1305
const NONCE_SIZE: usize = 12;

/// Poly1305 authentication tag overhead
const AEAD_TAG_SIZE: usize = 16;

/// Domain separation labels for HKDF
mod hkdf_labels {
    pub const HEADER_KEY: &[u8] = b"phantom-sphinx-header-key";
    pub const PAYLOAD_KEY: &[u8] = b"phantom-sphinx-payload-key";
    pub const BLINDING_FACTOR: &[u8] = b"phantom-sphinx-blinding";
    pub const MAC_KEY: &[u8] = b"phantom-sphinx-mac-key";
}

/// Derive public key from secret using curve25519
/// Clamps the secret first for X25519 compatibility
fn derive_public_key(secret: &[u8; 32]) -> [u8; 32] {
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::constants::X25519_BASEPOINT;

    // Clamp the secret for X25519 compatibility
    let clamped = clamp_secret(secret);

    // Convert secret to scalar and compute public key: secret * basepoint
    let secret_scalar = Scalar::from_bytes_mod_order(clamped);
    let public_point = secret_scalar * X25519_BASEPOINT;
    public_point.to_bytes()
}

/// Clamp a secret key per X25519 spec (done once at key generation)
/// Sets bits 0,1,2 to 0, bit 255 to 0, bit 254 to 1
fn clamp_secret(secret: &[u8; 32]) -> [u8; 32] {
    let mut clamped = *secret;
    clamped[0] &= 248;      // Clear bottom 3 bits
    clamped[31] &= 127;     // Clear top bit
    clamped[31] |= 64;      // Set second-highest bit
    clamped
}

/// Compute shared secret using raw curve25519 Montgomery multiplication
/// This avoids re-clamping the secret key, which is necessary for Sphinx blinding to work
fn compute_shared_secret(our_secret: &[u8; 32], their_public: &[u8; 32]) -> [u8; 32] {
    use curve25519_dalek::montgomery::MontgomeryPoint;
    use curve25519_dalek::scalar::Scalar;

    // Convert secret to scalar (no clamping - assume already clamped if needed)
    let secret_scalar = Scalar::from_bytes_mod_order(*our_secret);

    // Convert public key to Montgomery point
    let public_point = MontgomeryPoint(*their_public);

    // Compute scalar multiplication: shared = secret * public
    let shared_point = secret_scalar * public_point;
    let shared_bytes = shared_point.to_bytes();

    // Use HKDF to derive a uniform key from the shared secret
    let hkdf = Hkdf::<Sha256>::new(None, &shared_bytes);
    let mut output = [0u8; 32];
    hkdf.expand(b"phantom-ecdh-shared-secret", &mut output)
        .expect("HKDF output length is valid");
    output
}

/// Derive encryption key for header using HKDF
fn derive_header_key(shared_secret: &[u8; 32]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0u8; 32];
    hkdf.expand(hkdf_labels::HEADER_KEY, &mut key)
        .expect("HKDF output length is valid");
    key
}

/// Derive encryption key for payload using HKDF
fn derive_payload_key(shared_secret: &[u8; 32]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0u8; 32];
    hkdf.expand(hkdf_labels::PAYLOAD_KEY, &mut key)
        .expect("HKDF output length is valid");
    key
}

/// Encrypt header with ChaCha20-Poly1305 AEAD
/// Note: We use a deterministic nonce derived from the shared secret
/// since each header is encrypted with a unique per-hop key
fn encrypt_header(header: &[u8; HOP_HEADER_SIZE], shared_secret: &[u8; 32]) -> Vec<u8> {
    let key_bytes = derive_header_key(shared_secret);
    let key = Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);

    // Derive nonce from shared secret (unique per hop)
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    hkdf.expand(b"phantom-header-nonce", &mut nonce_bytes)
        .expect("HKDF output length is valid");
    let nonce = Nonce::<ChaCha20Poly1305>::from_slice(&nonce_bytes);

    // Encrypt with authentication
    cipher.encrypt(nonce, header.as_ref())
        .expect("Header encryption should not fail")
}

/// Decrypt header with ChaCha20-Poly1305 AEAD
fn decrypt_header(encrypted: &[u8], shared_secret: &[u8; 32]) -> Result<[u8; HOP_HEADER_SIZE], MixnetError> {
    let key_bytes = derive_header_key(shared_secret);
    let key = Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);

    // Derive same nonce
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    hkdf.expand(b"phantom-header-nonce", &mut nonce_bytes)
        .expect("HKDF output length is valid");
    let nonce = Nonce::<ChaCha20Poly1305>::from_slice(&nonce_bytes);

    // Decrypt and verify authentication
    let decrypted = cipher.decrypt(nonce, encrypted)
        .map_err(|_| MixnetError::AuthenticationFailed)?;

    if decrypted.len() != HOP_HEADER_SIZE {
        return Err(MixnetError::InvalidPacket("Invalid header size after decryption".into()));
    }

    let mut result = [0u8; HOP_HEADER_SIZE];
    result.copy_from_slice(&decrypted);
    Ok(result)
}

/// Encrypt payload with ChaCha20-Poly1305 AEAD
fn encrypt_payload(payload: &[u8], shared_secret: &[u8; 32]) -> Vec<u8> {
    let key_bytes = derive_payload_key(shared_secret);
    let key = Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);

    // Derive nonce from shared secret
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    hkdf.expand(b"phantom-payload-nonce", &mut nonce_bytes)
        .expect("HKDF output length is valid");
    let nonce = Nonce::<ChaCha20Poly1305>::from_slice(&nonce_bytes);

    cipher.encrypt(nonce, payload)
        .expect("Payload encryption should not fail")
}

/// Decrypt payload with ChaCha20-Poly1305 AEAD
fn decrypt_payload(encrypted: &[u8], shared_secret: &[u8; 32]) -> Result<Vec<u8>, MixnetError> {
    let key_bytes = derive_payload_key(shared_secret);
    let key = Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);

    // Derive same nonce
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    hkdf.expand(b"phantom-payload-nonce", &mut nonce_bytes)
        .expect("HKDF output length is valid");
    let nonce = Nonce::<ChaCha20Poly1305>::from_slice(&nonce_bytes);

    cipher.decrypt(nonce, encrypted)
        .map_err(|_| MixnetError::AuthenticationFailed)
}

/// Compute authentication tag using BLAKE3 keyed MAC
fn compute_tag(
    ephemeral: &[u8; 32],
    routing_info: &[u8],
    payload: &[u8],
) -> [u8; TAG_SIZE] {
    // Derive MAC key from ephemeral public key
    let hkdf = Hkdf::<Sha256>::new(None, ephemeral);
    let mut mac_key = [0u8; 32];
    hkdf.expand(hkdf_labels::MAC_KEY, &mut mac_key)
        .expect("HKDF output length is valid");

    // Compute keyed MAC
    let mut hasher = blake3::Hasher::new_keyed(&mac_key);
    hasher.update(b"phantom-sphinx-packet-tag");
    hasher.update(&(routing_info.len() as u64).to_le_bytes());
    hasher.update(routing_info);
    hasher.update(&(payload.len() as u64).to_le_bytes());
    hasher.update(payload);

    let hash = hasher.finalize();
    let mut tag = [0u8; TAG_SIZE];
    tag.copy_from_slice(&hash.as_bytes()[..TAG_SIZE]);
    tag
}

/// Constant-time comparison to prevent timing attacks
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    // Use XOR accumulator for constant-time comparison
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    // Subtle: ensure comparison doesn't short-circuit
    result == 0
}

/// Shift routing info after processing one hop
/// Removes the first header and pads with encrypted random bytes
fn shift_routing_info(routing_info: &[u8], shared_secret: &[u8; 32]) -> Vec<u8> {
    // Account for AEAD overhead in encrypted headers
    let encrypted_header_size = HOP_HEADER_SIZE + AEAD_TAG_SIZE;

    if routing_info.len() <= encrypted_header_size {
        // Generate random padding for last hop
        let mut padding = vec![0u8; routing_info.len()];
        let _ = getrandom::getrandom(&mut padding);
        return padding;
    }

    // Shift left by one encrypted header
    let mut new_routing = routing_info[encrypted_header_size..].to_vec();

    // Generate encrypted random padding
    let mut padding = [0u8; HOP_HEADER_SIZE];
    let _ = getrandom::getrandom(&mut padding);

    // Encrypt padding with a derived key to make it indistinguishable
    let encrypted_padding = encrypt_header(&padding, shared_secret);
    new_routing.extend_from_slice(&encrypted_padding);

    new_routing
}

/// Derive the blinding factor from shared secret
fn derive_blinding_factor(shared_secret: &[u8; 32]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
    let mut blinding_factor = [0u8; 32];
    hkdf.expand(hkdf_labels::BLINDING_FACTOR, &mut blinding_factor)
        .expect("HKDF output length is valid");
    blinding_factor
}

/// Blind the ephemeral public key for the next hop
/// Uses proper elliptic curve scalar multiplication: new_public = blinding_factor * ephemeral
fn blind_key(ephemeral: &[u8; 32], shared_secret: &[u8; 32]) -> [u8; 32] {
    use curve25519_dalek::montgomery::MontgomeryPoint;
    use curve25519_dalek::scalar::Scalar;

    let blinding_factor = derive_blinding_factor(shared_secret);

    // Convert ephemeral public key to Montgomery point
    let ephemeral_point = MontgomeryPoint(*ephemeral);

    // Convert blinding factor to scalar
    let blinding_scalar = Scalar::from_bytes_mod_order(blinding_factor);

    // Compute: blinding_factor * ephemeral_point
    let blinded_point = blinding_scalar * ephemeral_point;

    blinded_point.to_bytes()
}

/// Derive the blinded ephemeral secret for Sphinx key evolution
/// This computes: new_secret = original_secret * blinding_factor (scalar multiplication)
/// Used during packet creation to track how the ephemeral secret evolves through hops
fn derive_blinded_secret(original_secret: &[u8; 32], shared_secret: &[u8; 32]) -> [u8; 32] {
    use curve25519_dalek::scalar::Scalar;

    let blinding_factor = derive_blinding_factor(shared_secret);

    // Interpret both as scalars and multiply (mod curve order)
    // This gives us the secret corresponding to the blinded public key
    let original_scalar = Scalar::from_bytes_mod_order(*original_secret);
    let blinding_scalar = Scalar::from_bytes_mod_order(blinding_factor);

    // new_secret = original * blinding (mod l)
    let new_scalar = original_scalar * blinding_scalar;
    new_scalar.to_bytes()
}

/// Generate random delay for timing attack resistance
fn random_delay() -> u32 {
    let mut bytes = [0u8; 4];
    let _ = getrandom::getrandom(&mut bytes);
    // Random delay between 100-2000ms (uniform distribution)
    100 + (u32::from_le_bytes(bytes) % 1900)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_node(id: u8) -> MixNodeInfo {
        let mut node_id = [0u8; 32];
        node_id[0] = id;
        let public_key = derive_public_key(&node_id);
        MixNodeInfo { id: node_id, public_key }
    }

    #[test]
    fn test_hop_info_serialization() {
        let hop = HopInfo::intermediate([1u8; 32], 500);
        let bytes = hop.to_bytes();
        let restored = HopInfo::from_bytes(&bytes);

        assert_eq!(hop.next_hop, restored.next_hop);
        assert_eq!(hop.delay_ms, restored.delay_ms);
        assert_eq!(hop.flags, restored.flags);
    }

    #[test]
    fn test_packet_creation() {
        let route: Vec<MixNodeInfo> = (1..=5).map(create_test_node).collect();
        let destination = [99u8; 32];
        let payload = b"Hello, anonymous world!";

        let packet = SphinxPacket::create(payload, &route, &destination).unwrap();

        assert_eq!(packet.version, SphinxPacket::VERSION);
        // With AEAD, each hop adds 16 bytes (Poly1305 tag)
        // 5 hops × 16 bytes = 80 bytes overhead
        let expected_size = MAX_PAYLOAD_SIZE + route.len() * 16;
        assert_eq!(packet.payload.len(), expected_size);
    }

    #[test]
    fn test_packet_serialization() {
        let route: Vec<MixNodeInfo> = (1..=3).map(create_test_node).collect();
        let destination = [99u8; 32];
        let payload = b"Test message";

        let packet = SphinxPacket::create(payload, &route, &destination).unwrap();
        let bytes = packet.to_bytes();
        let restored = SphinxPacket::from_bytes(&bytes).unwrap();

        assert_eq!(packet.version, restored.version);
        assert_eq!(packet.ephemeral_key, restored.ephemeral_key);
        assert_eq!(packet.tag, restored.tag);
    }

    #[test]
    fn test_empty_route_rejected() {
        let result = SphinxPacket::create(b"test", &[], &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_payload_too_large() {
        let route = vec![create_test_node(1)];
        let payload = vec![0u8; MAX_PAYLOAD_SIZE + 1];

        let result = SphinxPacket::create(&payload, &route, &[0u8; 32]);
        assert!(matches!(result, Err(MixnetError::PacketTooLarge { .. })));
    }

    /// Comprehensive end-to-end test of Sphinx packet processing with real crypto
    /// Tests: X25519 ECDH key exchange, ChaCha20-Poly1305 AEAD, EC key blinding
    #[test]
    fn test_end_to_end_packet_processing() {
        // Create a 3-hop route with real keypairs
        let node_secrets: Vec<[u8; 32]> = (1..=3).map(|i| {
            let mut secret = [0u8; 32];
            secret[0] = i;
            secret
        }).collect();

        let route: Vec<MixNodeInfo> = node_secrets.iter().enumerate().map(|(i, secret)| {
            let public_key = derive_public_key(secret);
            let mut id = [0u8; 32];
            id[0] = (i + 1) as u8;
            MixNodeInfo { id, public_key }
        }).collect();

        let destination = [0xFFu8; 32];
        let original_payload = b"Secret message through the mixnet!";

        // Create packet with real X25519+ChaCha20-Poly1305
        let packet = SphinxPacket::create(original_payload, &route, &destination)
            .expect("Packet creation should succeed");

        // Process through hop 1 (using real ECDH and AEAD decryption)
        let result1 = packet.process(&node_secrets[0])
            .expect("Hop 1 processing should succeed");

        let (next_hop1, packet1) = match result1 {
            ProcessedPacket::Forward { next_hop, packet, .. } => (next_hop, packet),
            ProcessedPacket::Final { .. } => panic!("Should forward, not final"),
        };
        assert_eq!(next_hop1, route[1].id, "Should forward to hop 2");

        // Process through hop 2
        let result2 = packet1.process(&node_secrets[1])
            .expect("Hop 2 processing should succeed");

        let (next_hop2, packet2) = match result2 {
            ProcessedPacket::Forward { next_hop, packet, .. } => (next_hop, packet),
            ProcessedPacket::Final { .. } => panic!("Should forward, not final"),
        };
        assert_eq!(next_hop2, route[2].id, "Should forward to hop 3");

        // Process through hop 3 (final hop)
        let result3 = packet2.process(&node_secrets[2])
            .expect("Hop 3 processing should succeed");

        match result3 {
            ProcessedPacket::Final { destination: dest, payload } => {
                assert_eq!(dest, destination, "Destination should match");
                assert_eq!(payload, original_payload, "Payload should be decrypted correctly");
            }
            ProcessedPacket::Forward { .. } => panic!("Should be final, not forward"),
        }
    }

    /// Test that wrong keys fail authentication (AEAD integrity)
    #[test]
    fn test_wrong_key_fails_authentication() {
        let route = vec![create_test_node(1)];
        let destination = [0xFFu8; 32];
        let payload = b"Test message";

        let packet = SphinxPacket::create(payload, &route, &destination).unwrap();

        // Try to process with wrong key
        let wrong_key = [0xFFu8; 32];
        let result = packet.process(&wrong_key);

        // Should fail with authentication error (AEAD tag mismatch)
        assert!(result.is_err(), "Wrong key should fail authentication");
    }

    /// Test X25519 key derivation consistency
    #[test]
    fn test_x25519_key_derivation() {
        let secret = [42u8; 32];
        let public1 = derive_public_key(&secret);
        let public2 = derive_public_key(&secret);

        assert_eq!(public1, public2, "Key derivation should be deterministic");
        assert_ne!(public1, secret, "Public key should differ from secret");
    }

    /// Test ECDH shared secret computation
    #[test]
    fn test_ecdh_shared_secret() {
        let alice_secret_raw = [1u8; 32];
        let bob_secret_raw = [2u8; 32];

        // Clamp secrets for proper ECDH (as derive_public_key does internally)
        let alice_secret = clamp_secret(&alice_secret_raw);
        let bob_secret = clamp_secret(&bob_secret_raw);

        let alice_public = derive_public_key(&alice_secret_raw);
        let bob_public = derive_public_key(&bob_secret_raw);

        // Both parties should derive the same shared secret when using clamped keys
        let shared_alice = compute_shared_secret(&alice_secret, &bob_public);
        let shared_bob = compute_shared_secret(&bob_secret, &alice_public);

        assert_eq!(shared_alice, shared_bob, "ECDH should produce same shared secret");
    }

    /// Test ChaCha20-Poly1305 AEAD round-trip
    #[test]
    fn test_chacha20_poly1305_roundtrip() {
        let shared_secret = [42u8; 32];
        let original = [0u8; HOP_HEADER_SIZE];

        // Encrypt
        let encrypted = encrypt_header(&original, &shared_secret);
        assert!(encrypted.len() > original.len(), "AEAD should add tag");

        // Decrypt
        let decrypted = decrypt_header(&encrypted, &shared_secret)
            .expect("Decryption should succeed");

        assert_eq!(decrypted, original, "Round-trip should preserve data");
    }

    /// Test payload encryption/decryption round-trip
    #[test]
    fn test_payload_roundtrip() {
        let shared_secret = [99u8; 32];
        let original = b"This is a test payload for AEAD encryption";

        let encrypted = encrypt_payload(original, &shared_secret);
        let decrypted = decrypt_payload(&encrypted, &shared_secret)
            .expect("Payload decryption should succeed");

        assert_eq!(decrypted, original.to_vec(), "Payload round-trip should preserve data");
    }

    /// Test that EC key blinding produces different but valid keys
    #[test]
    fn test_ec_key_blinding() {
        let ephemeral = derive_public_key(&[1u8; 32]);
        let shared_secret = [2u8; 32];

        let blinded = blind_key(&ephemeral, &shared_secret);

        assert_ne!(blinded, ephemeral, "Blinded key should differ from original");
        assert_ne!(blinded, [0u8; 32], "Blinded key should not be zero");
    }

    // =========================================================================
    // SURB (Single-Use Reply Block) Tests
    // =========================================================================

    /// Test SURB creation with a valid route
    #[test]
    fn test_surb_creation() {
        let route: Vec<MixNodeInfo> = (1..=3).map(create_test_node).collect();

        let destination_key = [99u8; 32];
        let surb = SURB::create(&route, &destination_key).unwrap();

        assert_eq!(surb.first_hop, route[0].id, "First hop should match route start");
        assert!(!surb.routing_info.is_empty(), "Routing info should not be empty");
        assert_eq!(surb.decryption_keys.len(), route.len(), "Should have key per hop");
    }

    /// Test SURB creation with empty route fails
    #[test]
    fn test_surb_empty_route_rejected() {
        let destination_key = [99u8; 32];
        let result = SURB::create(&[], &destination_key);

        assert!(result.is_err(), "Empty route should fail");
        match result {
            Err(MixnetError::InvalidRouting(_)) => (),
            _ => panic!("Expected InvalidRouting error"),
        }
    }

    /// Test SURB reply creation
    #[test]
    fn test_surb_reply_creation() {
        let route: Vec<MixNodeInfo> = (1..=3).map(create_test_node).collect();
        let destination_key = [99u8; 32];

        let surb = SURB::create(&route, &destination_key).unwrap();
        let reply_payload = b"This is a reply message";

        let reply_packet = surb.create_reply(reply_payload).unwrap();

        assert_eq!(reply_packet.version, SphinxPacket::VERSION);
        assert!(!reply_packet.payload.is_empty());
        assert_eq!(reply_packet.routing_info, surb.routing_info);
    }

    /// Test SURB reply with payload too large
    #[test]
    fn test_surb_reply_payload_too_large() {
        let route: Vec<MixNodeInfo> = (1..=3).map(create_test_node).collect();
        let destination_key = [99u8; 32];

        let surb = SURB::create(&route, &destination_key).unwrap();
        let oversized_payload = vec![0u8; MAX_PAYLOAD_SIZE + 1];

        let result = surb.create_reply(&oversized_payload);
        assert!(matches!(result, Err(MixnetError::PacketTooLarge { .. })));
    }

    /// Test full SURB roundtrip: create SURB, create reply, decrypt reply
    #[test]
    fn test_surb_end_to_end_roundtrip() {
        let route: Vec<MixNodeInfo> = (1..=3).map(create_test_node).collect();
        let destination_key = [99u8; 32];

        // Create SURB
        let surb = SURB::create(&route, &destination_key).unwrap();

        // Create reply
        let original_message = b"Secret reply through SURB!";
        let reply_packet = surb.create_reply(original_message).unwrap();

        // Decrypt reply using SURB keys
        let decrypted = surb.decrypt_reply(&reply_packet.payload).unwrap();

        assert_eq!(decrypted, original_message.to_vec(), "Decrypted reply should match original");
    }

    /// Test SURB with single hop
    #[test]
    fn test_surb_single_hop() {
        let route = vec![create_test_node(1)];
        let destination_key = [99u8; 32];

        let surb = SURB::create(&route, &destination_key).unwrap();
        assert_eq!(surb.decryption_keys.len(), 1);

        let message = b"Single hop SURB test";
        let reply = surb.create_reply(message).unwrap();
        let decrypted = surb.decrypt_reply(&reply.payload).unwrap();

        assert_eq!(decrypted, message.to_vec());
    }

    /// Test SURB with maximum hops (5)
    #[test]
    fn test_surb_five_hops() {
        let route: Vec<MixNodeInfo> = (1..=5).map(create_test_node).collect();
        let destination_key = [99u8; 32];

        let surb = SURB::create(&route, &destination_key).unwrap();
        assert_eq!(surb.decryption_keys.len(), 5);
        assert_eq!(surb.first_hop, route[0].id);

        let message = b"Five hop SURB test with more encryption layers";
        let reply = surb.create_reply(message).unwrap();
        let decrypted = surb.decrypt_reply(&reply.payload).unwrap();

        assert_eq!(decrypted, message.to_vec());
    }

    /// Test SURB decryption key ordering is correct
    #[test]
    fn test_surb_key_ordering() {
        let route: Vec<MixNodeInfo> = (1..=3).map(create_test_node).collect();
        let destination_key = [99u8; 32];

        let surb = SURB::create(&route, &destination_key).unwrap();

        // Keys should be unique (each hop has different key)
        let unique_keys: std::collections::HashSet<[u8; 32]> =
            surb.decryption_keys.iter().cloned().collect();
        assert_eq!(unique_keys.len(), route.len(), "All keys should be unique");
    }

    /// Test multiple SURBs have different keys (randomness)
    #[test]
    fn test_surb_randomness() {
        let route: Vec<MixNodeInfo> = (1..=3).map(create_test_node).collect();
        let destination_key = [99u8; 32];

        let surb1 = SURB::create(&route, &destination_key).unwrap();
        let surb2 = SURB::create(&route, &destination_key).unwrap();

        // Keys should be different due to random generation
        assert_ne!(surb1.decryption_keys, surb2.decryption_keys,
            "Different SURBs should have different keys");
        assert_ne!(surb1.routing_info, surb2.routing_info,
            "Different SURBs should have different routing info");
    }

    /// Test SURB serialization/deserialization
    #[test]
    fn test_surb_serialization() {
        let route: Vec<MixNodeInfo> = (1..=3).map(create_test_node).collect();
        let destination_key = [99u8; 32];

        let surb = SURB::create(&route, &destination_key).unwrap();

        // Serialize and deserialize using serde_json
        let serialized = serde_json::to_vec(&surb).unwrap();
        let deserialized: SURB = serde_json::from_slice(&serialized).unwrap();

        assert_eq!(deserialized.first_hop, surb.first_hop);
        assert_eq!(deserialized.routing_info, surb.routing_info);
        assert_eq!(deserialized.decryption_keys, surb.decryption_keys);

        // Verify deserialized SURB works correctly
        let message = b"Testing serialized SURB";
        let reply = deserialized.create_reply(message).unwrap();
        let decrypted = deserialized.decrypt_reply(&reply.payload).unwrap();
        assert_eq!(decrypted, message.to_vec());
    }

    /// Test SURB with binary payload containing null bytes
    #[test]
    fn test_surb_binary_payload() {
        let route: Vec<MixNodeInfo> = (1..=3).map(create_test_node).collect();
        let destination_key = [99u8; 32];

        let surb = SURB::create(&route, &destination_key).unwrap();

        // Binary payload with embedded nulls
        let binary_payload: Vec<u8> = vec![0x00, 0xFF, 0x00, 0xAB, 0x00, 0xCD, 0xEF, 0x00];
        let reply = surb.create_reply(&binary_payload).unwrap();
        let decrypted = surb.decrypt_reply(&reply.payload).unwrap();

        // Note: trailing nulls get stripped by decrypt_reply
        // So we compare up to the last non-null byte
        let trimmed: Vec<u8> = binary_payload.iter()
            .take(binary_payload.iter().rposition(|&b| b != 0).map(|i| i + 1).unwrap_or(0))
            .cloned()
            .collect();
        assert_eq!(decrypted, trimmed);
    }

    /// Test SURB with maximum payload size
    #[test]
    fn test_surb_max_payload() {
        let route: Vec<MixNodeInfo> = (1..=3).map(create_test_node).collect();
        let destination_key = [99u8; 32];

        let surb = SURB::create(&route, &destination_key).unwrap();

        // Exactly MAX_PAYLOAD_SIZE bytes (fill with non-null to test)
        let max_payload: Vec<u8> = (0..MAX_PAYLOAD_SIZE).map(|i| (i % 255 + 1) as u8).collect();
        let reply = surb.create_reply(&max_payload).unwrap();
        let decrypted = surb.decrypt_reply(&reply.payload).unwrap();

        assert_eq!(decrypted.len(), MAX_PAYLOAD_SIZE);
        assert_eq!(decrypted, max_payload);
    }
}
