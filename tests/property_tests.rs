//! Property-Based Tests for PHANTOM Crypto Primitives
//!
//! Uses proptest to generate random inputs and verify cryptographic properties hold.

use proptest::prelude::*;
use phantom_pq::{kyber, dilithium, SecurityLevel};
use phantom_esl::nullifier::{Nullifier, NullifierSet, NullifierTree};

// =============================================================================
// PROPTEST STRATEGIES
// =============================================================================

/// Strategy for generating random 32-byte arrays
fn bytes32() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

/// Strategy for generating random byte vectors of given length range
fn byte_vec(len: impl Into<prop::collection::SizeRange>) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), len)
}

/// Strategy for security levels
fn security_level() -> impl Strategy<Value = SecurityLevel> {
    prop_oneof![
        Just(SecurityLevel::Level1),
        Just(SecurityLevel::Level3),
        Just(SecurityLevel::Level5),
    ]
}

// =============================================================================
// POST-QUANTUM PROPERTY TESTS
// =============================================================================

proptest! {
    /// Property: Kyber key sizes should match expected sizes for security level
    #[test]
    fn kyber_key_sizes_are_correct(level in security_level()) {
        let keypair = kyber::generate_keypair(level).unwrap();

        let expected_pk = kyber::KyberPublicKey::expected_size(level);
        let expected_sk = kyber::KyberSecretKey::expected_size(level);

        prop_assert_eq!(keypair.public_key.as_bytes().len(), expected_pk);
        prop_assert_eq!(keypair.secret_key.as_bytes().len(), expected_sk);
    }

    /// Property: Kyber encapsulation always produces 32-byte shared secret
    #[test]
    fn kyber_shared_secret_is_32_bytes(level in security_level()) {
        let keypair = kyber::generate_keypair(level).unwrap();
        let (_, shared_secret) = kyber::encapsulate(&keypair.public_key).unwrap();

        prop_assert_eq!(shared_secret.as_bytes().len(), 32);
    }

    /// Property: Kyber ciphertext size matches expected for security level
    #[test]
    fn kyber_ciphertext_size_is_correct(level in security_level()) {
        let keypair = kyber::generate_keypair(level).unwrap();
        let (ciphertext, _) = kyber::encapsulate(&keypair.public_key).unwrap();

        let expected = kyber::KyberCiphertext::expected_size(level);
        prop_assert_eq!(ciphertext.as_bytes().len(), expected);
    }

    /// Property: Dilithium signature sizes match expected for security level
    #[test]
    fn dilithium_signature_sizes_are_correct(
        level in security_level(),
        message in byte_vec(32..1024)
    ) {
        let keypair = dilithium::generate_keypair(level).unwrap();
        let signature = dilithium::sign(&keypair.secret_key, &message).unwrap();

        let expected = dilithium::DilithiumSignature::expected_size(level);
        prop_assert_eq!(signature.as_bytes().len(), expected);
    }

    /// Property: Dilithium signature verification returns result (no panic)
    #[test]
    fn dilithium_verify_doesnt_panic(
        level in security_level(),
        message in byte_vec(1..1024)
    ) {
        let keypair = dilithium::generate_keypair(level).unwrap();
        let signature = dilithium::sign(&keypair.secret_key, &message).unwrap();

        // Should not panic
        let _ = dilithium::verify(&keypair.public_key, &message, &signature);
    }
}

// =============================================================================
// NULLIFIER PROPERTY TESTS
// =============================================================================

proptest! {
    /// Property: Nullifier derivation is deterministic
    #[test]
    fn nullifier_derivation_is_deterministic(
        secret in bytes32(),
        commitment in bytes32()
    ) {
        let n1 = Nullifier::derive(&secret, &commitment);
        let n2 = Nullifier::derive(&secret, &commitment);

        prop_assert_eq!(n1, n2);
    }

    /// Property: Different secrets produce different nullifiers (with high probability)
    #[test]
    fn different_secrets_produce_different_nullifiers(
        secret1 in bytes32(),
        secret2 in bytes32(),
        commitment in bytes32()
    ) {
        prop_assume!(secret1 != secret2);

        let n1 = Nullifier::derive(&secret1, &commitment);
        let n2 = Nullifier::derive(&secret2, &commitment);

        prop_assert_ne!(n1, n2);
    }

    /// Property: Different commitments produce different nullifiers
    #[test]
    fn different_commitments_produce_different_nullifiers(
        secret in bytes32(),
        commitment1 in bytes32(),
        commitment2 in bytes32()
    ) {
        prop_assume!(commitment1 != commitment2);

        let n1 = Nullifier::derive(&secret, &commitment1);
        let n2 = Nullifier::derive(&secret, &commitment2);

        prop_assert_ne!(n1, n2);
    }

    /// Property: Nullifier hex roundtrip preserves value
    #[test]
    fn nullifier_hex_roundtrip(bytes in bytes32()) {
        let original = Nullifier::from_bytes(bytes);
        let hex = original.to_hex();
        let recovered = Nullifier::from_hex(&hex).unwrap();

        prop_assert_eq!(original, recovered);
    }

    /// Property: Nullifier set detects all duplicates
    #[test]
    fn nullifier_set_detects_duplicates(
        bytes in bytes32(),
        extra_nullifiers in prop::collection::vec(bytes32(), 0..100)
    ) {
        let mut set = NullifierSet::new();

        // Add the target nullifier
        let target = Nullifier::from_bytes(bytes);
        set.insert(target).unwrap();

        // Add other nullifiers
        for extra_bytes in &extra_nullifiers {
            if *extra_bytes != bytes {
                let n = Nullifier::from_bytes(*extra_bytes);
                let _ = set.insert(n); // May fail if duplicate in random set
            }
        }

        // Target should definitely be detected as duplicate
        let result = set.insert(target);
        prop_assert!(result.is_err());
    }

    /// Property: NullifierTree contains what was inserted
    #[test]
    fn nullifier_tree_contains_inserted(
        nullifiers in prop::collection::vec(bytes32(), 1..50)
    ) {
        let mut tree = NullifierTree::with_depth(32);
        let mut inserted = Vec::new();

        for bytes in nullifiers {
            let n = Nullifier::from_bytes(bytes);
            if tree.insert(n).is_ok() {
                inserted.push(n);
            }
        }

        // All successfully inserted nullifiers should be found
        for n in inserted {
            prop_assert!(tree.contains(&n));
        }
    }
}

// =============================================================================
// SPHINX PACKET PROPERTY TESTS
// =============================================================================

proptest! {
    /// Property: Sphinx packet serialization roundtrip preserves data
    #[test]
    fn sphinx_packet_serialization_roundtrip(
        payload in byte_vec(1..256),
        destination in bytes32()
    ) {
        use phantom_mixnet::{SphinxPacket, MixNode, MixDirectory, MixNodeInfo};

        // Create a simple directory
        let mut directory = MixDirectory::new(3);
        for layer in 0..3u8 {
            for i in 0..3u8 {
                let mut id = [0u8; 32];
                id[0] = layer;
                id[1] = i;
                let node = MixNode::new(id, id, format!("127.0.0.1:{}", 10000 + layer as u16 * 10 + i as u16), layer);
                directory.add_node(node);
            }
        }

        let route = directory.select_route(3);
        prop_assume!(route.is_ok());
        let route = route.unwrap();

        let packet = SphinxPacket::create(&payload, &route, &destination);
        prop_assume!(packet.is_ok());
        let packet = packet.unwrap();

        // Serialize and deserialize
        let bytes = packet.to_bytes();
        let recovered = SphinxPacket::from_bytes(&bytes);

        prop_assert!(recovered.is_ok());
        let recovered = recovered.unwrap();

        prop_assert_eq!(packet.version, recovered.version);
        prop_assert_eq!(packet.ephemeral_key, recovered.ephemeral_key);
        prop_assert_eq!(packet.tag, recovered.tag);
    }
}

// =============================================================================
// CWA PROPERTY TESTS
// =============================================================================

proptest! {
    /// Property: VRF evaluation is deterministic
    #[test]
    fn vrf_evaluation_is_deterministic(
        secret_key in bytes32(),
        input in byte_vec(1..100)
    ) {
        use phantom_cwa::vrf::vrf_evaluate;

        let output1 = vrf_evaluate(&secret_key, &input);
        let output2 = vrf_evaluate(&secret_key, &input);

        prop_assert_eq!(output1.output, output2.output);
        prop_assert_eq!(output1.proof, output2.proof);
    }

    /// Property: Different inputs produce different VRF outputs (with high probability)
    #[test]
    fn vrf_different_inputs_different_outputs(
        secret_key in bytes32(),
        input1 in byte_vec(1..100),
        input2 in byte_vec(1..100)
    ) {
        prop_assume!(input1 != input2);

        use phantom_cwa::vrf::vrf_evaluate;

        let output1 = vrf_evaluate(&secret_key, &input1);
        let output2 = vrf_evaluate(&secret_key, &input2);

        prop_assert_ne!(output1.output, output2.output);
    }

    /// Property: Committee selection doesn't have duplicates
    #[test]
    fn committee_has_no_duplicates(
        seed in bytes32(),
        num_validators in 10..30usize,
        committee_size in 3..10usize
    ) {
        prop_assume!(committee_size < num_validators);

        use phantom_cwa::{Validator, vrf::Committee};

        let validators: Vec<Validator> = (0..num_validators)
            .map(|i| {
                let mut id = [0u8; 32];
                id[0] = (i / 256) as u8;
                id[1] = (i % 256) as u8;
                Validator::new(id, vec![], [0u8; 32], 1_000_000)
            })
            .collect();

        let committee = Committee::select(1, &validators, &seed, committee_size, 1);
        prop_assume!(committee.is_ok());
        let committee = committee.unwrap();

        // Check for duplicates
        let mut seen_ids = std::collections::HashSet::new();
        for member in &committee.members {
            prop_assert!(!seen_ids.contains(&member.id), "Found duplicate in committee");
            seen_ids.insert(member.id);
        }
    }

    /// Property: Threshold scheme rejects insufficient signatures
    #[test]
    fn threshold_rejects_insufficient_sigs(
        t in 3..8usize,
        n in 8..15usize,
        message in byte_vec(1..100)
    ) {
        prop_assume!(t <= n);

        use phantom_cwa::threshold::ThresholdScheme;

        let result = ThresholdScheme::new(n, t);
        prop_assume!(result.is_ok());
        let (scheme, shares) = result.unwrap();

        // Create fewer than threshold signatures
        let insufficient_count = t - 1;
        let partials: Vec<_> = shares.iter()
            .take(insufficient_count)
            .filter_map(|s| scheme.partial_sign(s, &message).ok())
            .collect();

        if partials.len() == insufficient_count {
            let result = scheme.aggregate(&partials);
            let is_insufficient = result.is_err();
            prop_assert!(is_insufficient, "Expected InsufficientSignatures error");
        }
    }
}

// =============================================================================
// EDGE CASE TESTS (Not proptest)
// =============================================================================

#[cfg(test)]
mod edge_cases {
    use super::*;

    #[test]
    fn test_nullifier_all_zeros() {
        let secret = [0u8; 32];
        let commitment = [0u8; 32];
        let n = Nullifier::derive(&secret, &commitment);

        // Should still produce a valid nullifier (not all zeros due to hashing)
        assert_ne!(n.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_nullifier_all_ones() {
        let secret = [0xFFu8; 32];
        let commitment = [0xFFu8; 32];
        let n = Nullifier::derive(&secret, &commitment);

        // Should still produce a valid nullifier
        assert_ne!(n.as_bytes(), &[0xFFu8; 32]);
    }

    #[test]
    fn test_empty_validator_set_committee() {
        use phantom_cwa::{Validator, vrf::Committee};

        let validators: Vec<Validator> = vec![];
        let randomness = [1u8; 32];

        let result = Committee::select(1, &validators, &randomness, 5, 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_threshold_scheme_boundary_t_equals_n() {
        use phantom_cwa::threshold::ThresholdScheme;

        let n = 5;
        let t = 5; // t == n is the boundary

        let (scheme, shares) = ThresholdScheme::new(n, t).unwrap();

        let message = b"boundary test";

        // Need all 5 signatures
        let partials: Vec<_> = shares.iter()
            .map(|s| scheme.partial_sign(s, message).unwrap())
            .collect();

        let result = scheme.aggregate(&partials);
        assert!(result.is_ok());
    }

    #[test]
    fn test_nullifier_set_large_scale() {
        let mut set = NullifierSet::with_capacity(10000);

        // Insert 10000 unique nullifiers
        for i in 0..10000u64 {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&i.to_le_bytes());
            let n = Nullifier::from_bytes(bytes);
            set.insert(n).expect("Should insert unique nullifier");
        }

        assert_eq!(set.len(), 10000);

        // Verify all are contained
        for i in 0..10000u64 {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&i.to_le_bytes());
            let n = Nullifier::from_bytes(bytes);
            assert!(set.contains(&n));
        }
    }

    #[test]
    fn test_kyber_multiple_encapsulations_same_key() {
        let keypair = kyber::generate_keypair(SecurityLevel::Level5).unwrap();

        // Multiple encapsulations should all succeed
        for _ in 0..100 {
            let result = kyber::encapsulate(&keypair.public_key);
            assert!(result.is_ok());
        }
    }
}
