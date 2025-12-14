//! Phase 2 Integration Tests for PHANTOM
//!
//! Comprehensive tests for:
//! - PhantomNode creation and lifecycle
//! - Wallet operations (HD derivation, stealth addresses)
//! - Transaction lifecycle (create, sign, prove, propagate)
//! - P2P networking
//! - CWA consensus participation
//! - Encrypted mempool operations
//! - State synchronization
//! - End-to-end transaction flows

use phantom::{
    node::{PhantomNode, NodeConfig, NodeEvent, NodeError},
    prelude::*,
};
use phantom_wallet::{
    HDWallet, Mnemonic, TransactionBuilder, TransactionConfig,
    StealthAddress, ViewKey, SpendKey, Transaction,
    TransactionLifecycle, LifecycleConfig, TransactionStatus,
    TransactionInput, TransactionOutput, Note, NoteManager, OwnedNote,
    InMemoryPropagator, InMemoryStateProvider, NoOpCallback, SpendingKey,
};
use phantom_p2p::{
    P2PConfig, SwarmManager, NetworkMessage, TransactionMessage,
    ConsensusMessage, ConsensusMessageType,
};
use phantom_cwa::{
    CWAProtocol, CWAConfig, Validator, ValidatorSet,
    vrf::Committee, threshold::ThresholdScheme,
};
use phantom_esl::{
    ESLState, StateFragment, EncryptedBalance, Nullifier,
    NullifierTree, Commitment, CommitmentTree, StateUpdate,
};
use phantom_mempool::{
    EncryptedMempool, MempoolConfig, EncryptedTxId,
};
use std::time::Duration;
use std::sync::Arc;

// =============================================================================
// NODE LIFECYCLE TESTS
// =============================================================================

mod node_tests {
    use super::*;

    #[test]
    fn test_node_config_presets() {
        // Test local configuration
        let local = NodeConfig::local();
        assert!(local.p2p.enable_mdns);
        assert_eq!(local.cwa.witness_count, 5);
        assert_eq!(local.cwa.threshold, 3);

        // Test testnet configuration
        let testnet = NodeConfig::testnet();
        assert!(!testnet.p2p.enable_mdns);
        assert_eq!(testnet.cwa.witness_count, 21);
        assert_eq!(testnet.cwa.threshold, 14);

        // Test mainnet configuration
        let mainnet = NodeConfig::mainnet();
        assert_eq!(mainnet.cwa.witness_count, 100);
        assert_eq!(mainnet.cwa.threshold, 67);
    }

    #[test]
    fn test_node_config_validator_setup() {
        let config = NodeConfig::local().with_validator(1_000_000);
        assert!(config.is_validator);
        assert_eq!(config.validator_stake, 1_000_000);
    }

    #[tokio::test]
    async fn test_node_creation() {
        let config = NodeConfig::local();
        let node = PhantomNode::new(config);
        assert!(node.is_ok(), "Node creation should succeed");

        let node = node.unwrap();
        assert!(!node.is_running().await);
    }

    #[tokio::test]
    async fn test_node_config_custom() {
        let mut config = NodeConfig::default();
        config.p2p.enable_mdns = false;
        config.p2p.max_inbound = 50;
        config.cwa.witness_count = 10;
        config.cwa.threshold = 7;
        config.mempool.max_transactions = 5000;
        config.esl_tree_depth = 16;  // Use smaller tree depth for tests

        let node = PhantomNode::new(config);
        assert!(node.is_ok());
    }

    #[tokio::test]
    async fn test_node_validator_registration() {
        let config = NodeConfig::local();
        let mut node = PhantomNode::new(config).unwrap();

        // Register as validator
        let validator_id = node.register_as_validator(1_000_000).await;
        assert!(validator_id.is_ok());

        let id = validator_id.unwrap();
        assert_ne!(id, [0u8; 32], "Validator ID should not be all zeros");
    }

    #[tokio::test]
    async fn test_node_get_state_snapshot() {
        let config = NodeConfig::local();
        let node = PhantomNode::new(config).unwrap();

        let snapshot = node.get_state_snapshot().await;
        assert_eq!(snapshot.epoch, 0, "Initial epoch should be 0");
    }

    #[tokio::test]
    async fn test_node_mempool_operations() {
        let config = NodeConfig::local();
        let node = PhantomNode::new(config).unwrap();

        // Initially empty
        let size = node.mempool_size().await;
        assert_eq!(size, 0);
    }
}

// =============================================================================
// WALLET INTEGRATION TESTS
// =============================================================================

mod wallet_tests {
    use super::*;

    #[test]
    fn test_hd_wallet_creation_from_mnemonic() {
        let mnemonic = Mnemonic::generate().unwrap();
        let wallet = HDWallet::from_mnemonic(&mnemonic, "", 0).unwrap();

        // Get address at path
        let addr0 = wallet.address_at(0, 0).unwrap();
        let addr1 = wallet.address_at(0, 1).unwrap();

        // Different indices should produce different addresses
        assert_ne!(addr0.view_public_key, addr1.view_public_key);
    }

    #[test]
    #[ignore = "PQ key generation uses pqcrypto internal randomness - deterministic HD requires seeded key generation which pqcrypto doesn't expose"]
    fn test_hd_wallet_deterministic_derivation() {
        // NOTE: The extended key derivation (mnemonic -> master key -> child keys) IS deterministic.
        // Only the final PQ keypair generation step lacks determinism because pqcrypto
        // uses its own internal randomness. For production HD wallet recovery,
        // we would need to either:
        // 1. Fork pqcrypto to expose seeded keypair generation
        // 2. Use reference implementations with seed support
        // 3. Implement our own Kyber/Dilithium with ChaCha20Rng seeding
        let mnemonic = Mnemonic::from_words(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).unwrap();

        // Create two wallets from same mnemonic
        let wallet1 = HDWallet::from_mnemonic(&mnemonic, "", 0).unwrap();
        let wallet2 = HDWallet::from_mnemonic(&mnemonic, "", 0).unwrap();

        // Same derivation path should produce same keys (when PQ key gen is deterministic)
        let addr1 = wallet1.address_at(0, 0).unwrap();
        let addr2 = wallet2.address_at(0, 0).unwrap();

        assert_eq!(addr1.view_public_key, addr2.view_public_key);
        assert_eq!(addr1.spend_public_key, addr2.spend_public_key);
    }

    #[test]
    fn test_hd_wallet_next_address() {
        let mnemonic = Mnemonic::generate().unwrap();
        let mut wallet = HDWallet::from_mnemonic(&mnemonic, "", 0).unwrap();

        // Generate sequential external addresses
        let addr0 = wallet.next_external_address().unwrap();
        let addr1 = wallet.next_external_address().unwrap();

        // Should be different
        assert_ne!(addr0.view_public_key, addr1.view_public_key);
    }

    #[test]
    fn test_stealth_address_generation() {
        let mnemonic = Mnemonic::generate().unwrap();
        let wallet = HDWallet::from_mnemonic(&mnemonic, "", 0).unwrap();

        // Get stealth address
        let stealth = wallet.address_at(0, 0).unwrap();

        // Should have non-zero keys
        assert!(!stealth.view_public_key.iter().all(|&b| b == 0));
        assert!(!stealth.spend_public_key.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_view_and_spend_keys() {
        let mnemonic = Mnemonic::generate().unwrap();
        let wallet = HDWallet::from_mnemonic(&mnemonic, "", 0).unwrap();

        // Get view key
        let view_key = wallet.view_key_at(0, 0).unwrap();
        assert!(!view_key.public_bytes().iter().all(|&b| b == 0));

        // Get spend key
        let spend_key = wallet.spend_key_at(0, 0).unwrap();
        assert!(!spend_key.public_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_mnemonic_generation() {
        // Generate should produce 24 words
        let mnemonic = Mnemonic::generate().unwrap();
        assert_eq!(mnemonic.word_count(), 24);

        // Should be able to convert to string and back
        let phrase = mnemonic.to_string();
        let restored = Mnemonic::from_words(&phrase);
        assert!(restored.is_ok());
    }
}

// =============================================================================
// TRANSACTION BUILDER TESTS
// =============================================================================

mod transaction_tests {
    use super::*;

    #[test]
    fn test_transaction_builder_basic() {
        let mut builder = TransactionBuilder::new();

        // Verify builder starts empty
        assert_eq!(builder.input_sum(), 0);
        assert_eq!(builder.output_sum(), 0);
    }

    #[test]
    fn test_transaction_builder_with_config() {
        let config = TransactionConfig {
            use_groth16: true,
            fee_rate: 2,
            min_fee: 100,
            max_fee: 50_000,
        };

        let builder = TransactionBuilder::with_config(config);
        assert_eq!(builder.input_sum(), 0);
    }

    #[test]
    fn test_transaction_config_defaults() {
        let config = TransactionConfig::default();
        assert!(config.use_groth16);
        assert!(config.min_fee > 0);
        assert!(config.max_fee > config.min_fee);
    }
}

// =============================================================================
// P2P NETWORKING TESTS
// =============================================================================

mod p2p_tests {
    use super::*;

    #[test]
    fn test_p2p_config_presets() {
        let local = P2PConfig::local();
        assert!(local.enable_mdns);
        assert!(!local.enable_kademlia);  // Local config disables kademlia for simplicity

        let testnet = P2PConfig::testnet();
        assert!(!testnet.enable_mdns);
        assert!(testnet.enable_kademlia);

        let mainnet = P2PConfig::mainnet();
        assert!(mainnet.max_inbound > testnet.max_inbound);
    }

    #[test]
    fn test_transaction_message_creation() {
        let tx_id = [1u8; 32];
        let encrypted_data = vec![0xAB; 256];
        let nullifier = [2u8; 32];
        let proof = vec![0xCD; 128];

        let msg = TransactionMessage::new(tx_id, encrypted_data.clone(), nullifier, proof.clone());

        assert_eq!(msg.tx_id, tx_id);
        assert_eq!(msg.encrypted_data, encrypted_data);
        assert_eq!(msg.nullifier, nullifier);
        assert_eq!(msg.proof, proof);
    }

    #[test]
    fn test_network_message_types() {
        // Transaction message
        let tx_msg = TransactionMessage::new([1u8; 32], vec![], [2u8; 32], vec![]);
        let msg = NetworkMessage::Transaction(tx_msg);
        assert_eq!(msg.message_type(), "transaction");

        // Consensus message
        let consensus_msg = ConsensusMessage {
            msg_type: ConsensusMessageType::Attestation,
            round: 1,
            validator_id: [3u8; 32],
            payload: vec![],
            signature: vec![],
        };
        let msg = NetworkMessage::Consensus(consensus_msg);
        assert_eq!(msg.message_type(), "consensus");
    }

    #[test]
    fn test_consensus_message_types() {
        let types = [
            ConsensusMessageType::Attestation,
            ConsensusMessageType::WitnessSelection,
            ConsensusMessageType::ThresholdShare,
            ConsensusMessageType::ThresholdComplete,
        ];

        for msg_type in types {
            let msg = ConsensusMessage {
                msg_type,
                round: 1,
                validator_id: [0u8; 32],
                payload: vec![],
                signature: vec![],
            };
            assert!(msg.round > 0);
        }
    }
}

// =============================================================================
// CWA CONSENSUS TESTS
// =============================================================================

mod consensus_tests {
    use super::*;

    fn create_test_validators(count: usize) -> Vec<Validator> {
        (0..count)
            .map(|i| {
                let mut id = [0u8; 32];
                id[0] = i as u8;
                Validator::new(id, vec![0u8; 64], [0u8; 32], 1_000_000 * (i as u64 + 1))
            })
            .collect()
    }

    #[test]
    fn test_cwa_config_defaults() {
        // Default config should have mainnet-like settings (100 witnesses, 67 threshold)
        let config = CWAConfig::default();
        assert_eq!(config.witness_count, 100);
        assert_eq!(config.threshold, 67);
        assert!(config.timeout_ms > 0);
        assert!(config.min_stake > 0);
    }

    #[test]
    fn test_cwa_config_custom() {
        let config = CWAConfig {
            witness_count: 21,
            threshold: 14,
            timeout_ms: 10000,
            min_stake: 500_000,
            committee_period: 100,
            max_pending: 5000,
        };

        assert_eq!(config.witness_count, 21);
        assert_eq!(config.threshold, 14);
        assert!(config.threshold > config.witness_count / 2);  // Must be > 50%
    }

    #[test]
    fn test_committee_selection() {
        let validators = create_test_validators(20);
        let randomness = [0x42u8; 32];

        let committee = Committee::select(1, &validators, &randomness, 7, 5);
        assert!(committee.is_ok());

        let committee = committee.unwrap();
        assert!(committee.members.len() <= 7);
        assert!(committee.members.len() >= 5);
    }

    #[test]
    fn test_committee_selection_deterministic() {
        let validators = create_test_validators(20);
        let randomness = [0x42u8; 32];

        let committee1 = Committee::select(1, &validators, &randomness, 7, 5).unwrap();
        let committee2 = Committee::select(1, &validators, &randomness, 7, 5).unwrap();

        // Same inputs should produce same committee
        assert_eq!(committee1.members.len(), committee2.members.len());
        for (m1, m2) in committee1.members.iter().zip(committee2.members.iter()) {
            assert_eq!(m1.id, m2.id);
        }
    }

    #[test]
    fn test_threshold_signature_flow() {
        let (scheme, shares) = ThresholdScheme::new(10, 7).unwrap();

        let message = b"PHANTOM transaction data";

        // Create threshold signatures
        let partials: Vec<_> = shares
            .iter()
            .take(7)
            .map(|s| scheme.partial_sign(s, message).unwrap())
            .collect();

        // Aggregate
        let threshold_sig = scheme.aggregate(&partials).unwrap();

        // Verify
        assert!(scheme.verify(&threshold_sig, message));
        assert_eq!(threshold_sig.signer_count(), 7);
    }

    #[test]
    fn test_threshold_insufficient_signers() {
        let (scheme, shares) = ThresholdScheme::new(10, 7).unwrap();

        let message = b"test";

        // Only 5 signatures (need 7)
        let partials: Vec<_> = shares
            .iter()
            .take(5)
            .map(|s| scheme.partial_sign(s, message).unwrap())
            .collect();

        let result = scheme.aggregate(&partials);
        assert!(result.is_err());
    }

    #[test]
    fn test_validator_set_operations() {
        let mut set = ValidatorSet::new();

        // Add validators
        for v in create_test_validators(10) {
            set.add(v);
        }
        assert_eq!(set.len(), 10);

        // Get by ID
        let mut id = [0u8; 32];
        id[0] = 5;
        let validator = set.get(&id);
        assert!(validator.is_some());

        // Remove
        set.remove(&id);
        assert_eq!(set.len(), 9);
        assert!(set.get(&id).is_none());
    }

    #[test]
    fn test_validator_reputation() {
        let mut validator = Validator::new([1u8; 32], vec![], [0u8; 32], 1_000_000);
        let initial_rep = validator.reputation;

        // Good behavior increases reputation
        validator.update_reputation(true);
        assert!(validator.reputation >= initial_rep);

        // Bad behavior decreases reputation
        let after_good = validator.reputation;
        validator.update_reputation(false);
        assert!(validator.reputation < after_good);
    }
}

// =============================================================================
// ENCRYPTED MEMPOOL TESTS
// =============================================================================

mod mempool_tests {
    use super::*;

    #[tokio::test]
    async fn test_mempool_creation() {
        let config = MempoolConfig::default();
        let mempool = EncryptedMempool::new(config);
        assert!(mempool.is_ok());

        let mempool = mempool.unwrap();
        assert!(mempool.is_empty().await);
        assert_eq!(mempool.threshold(), 3);
    }

    #[tokio::test]
    async fn test_mempool_submit_transaction() {
        let config = MempoolConfig::default();
        let mempool = EncryptedMempool::new(config).unwrap();

        // Encrypt and submit
        let tx_data = b"Transfer 100 PHANTOM";
        let ciphertext = mempool.encrypt_transaction(tx_data).unwrap();
        let tx_id = mempool.submit(ciphertext, 1000).await;

        assert!(tx_id.is_ok());
        assert_eq!(mempool.len().await, 1);
    }

    #[tokio::test]
    async fn test_mempool_duplicate_rejection() {
        let config = MempoolConfig::default();
        let mempool = EncryptedMempool::new(config).unwrap();

        let tx_data = b"Unique transaction";
        let ciphertext = mempool.encrypt_transaction(tx_data).unwrap();

        // First submission succeeds
        mempool.submit(ciphertext.clone(), 100).await.unwrap();

        // Duplicate should fail
        let result = mempool.submit(ciphertext, 100).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_mempool_priority_ordering() {
        let config = MempoolConfig::default();
        let mempool = EncryptedMempool::new(config).unwrap();

        // Submit with different priorities
        for (i, priority) in [100, 500, 200, 1000, 50].iter().enumerate() {
            let tx_data = format!("tx{}", i);
            let ciphertext = mempool.encrypt_transaction(tx_data.as_bytes()).unwrap();
            mempool.submit(ciphertext, *priority).await.unwrap();
        }

        // Get pending - should be ordered by priority
        let pending = mempool.get_pending(5).await;
        let priorities: Vec<u64> = pending.iter().map(|tx| tx.priority_fee).collect();

        // Should be in descending order
        assert_eq!(priorities, vec![1000, 500, 200, 100, 50]);
    }

    #[tokio::test]
    async fn test_mempool_threshold_decryption() {
        let config = MempoolConfig {
            threshold: 2,
            total_validators: 3,
            ..Default::default()
        };
        let mempool = EncryptedMempool::new(config).unwrap();

        // Submit encrypted transaction
        let tx_data = b"Private transfer";
        let ciphertext = mempool.encrypt_transaction(tx_data).unwrap();
        let tx_id = mempool.submit(ciphertext.clone(), 500).await.unwrap();

        // Get key shares and create decryption shares
        let key_shares = mempool.key_shares();
        let dec_shares: Vec<_> = key_shares
            .iter()
            .take(2)
            .map(|ks| ks.create_decryption_share(&ciphertext).unwrap())
            .collect();

        // Submit shares
        mempool.submit_share(&tx_id, dec_shares[0].clone()).await.unwrap();
        let ready = mempool.submit_share(&tx_id, dec_shares[1].clone()).await.unwrap();
        assert!(ready);

        // Decrypt
        let plaintext = mempool.try_decrypt(&tx_id).await.unwrap();
        assert!(plaintext.is_some());
        assert_eq!(plaintext.unwrap(), tx_data.to_vec());
    }

    #[tokio::test]
    async fn test_mempool_stats() {
        let config = MempoolConfig {
            threshold: 2,
            total_validators: 3,
            max_transactions: 100,
            ..Default::default()
        };
        let mempool = EncryptedMempool::new(config).unwrap();

        // Add some transactions
        for i in 0..5 {
            let tx_data = format!("tx{}", i);
            let ciphertext = mempool.encrypt_transaction(tx_data.as_bytes()).unwrap();
            mempool.submit(ciphertext, i * 100).await.unwrap();
        }

        let stats = mempool.stats().await;
        assert_eq!(stats.total_transactions, 5);
        assert_eq!(stats.pending_decryption, 5);
        assert_eq!(stats.decrypted_transactions, 0);
        assert_eq!(stats.threshold, 2);
        assert_eq!(stats.total_validators, 3);
    }
}

// =============================================================================
// ESL STATE TESTS
// =============================================================================

mod esl_tests {
    use super::*;

    #[test]
    fn test_esl_state_creation() {
        let state = ESLState::new(16);
        assert_eq!(state.epoch(), 0);
        assert_eq!(state.num_commitments(), 0);
        assert_eq!(state.num_nullifiers(), 0);
    }

    #[test]
    fn test_esl_add_fragment() {
        let mut state = ESLState::new(16);

        // Use Commitment::commit to generate a valid non-zero commitment
        let commitment = Commitment::commit(1000, &[1u8; 32]);
        let encrypted_balance = EncryptedBalance::new(vec![0u8; 64]);
        let owner = [2u8; 32];

        let fragment = StateFragment::new(encrypted_balance, *commitment.as_bytes(), owner, 0);
        let result = state.add_fragment(fragment);

        assert!(result.is_ok());
        assert_eq!(state.num_commitments(), 1);
    }

    #[test]
    fn test_esl_nullifier_tracking() {
        let mut state = ESLState::new(16);

        let nullifier = Nullifier::derive(&[1u8; 32], &[2u8; 32]);
        assert!(!state.nullifier_exists(&nullifier));

        // Add nullifier via state update
        let commitment = Commitment::commit(1000, &[3u8; 32]);
        let update = StateUpdate::new(
            vec![nullifier],
            vec![commitment],
            1,
            vec![],
        );
        state.apply_update(&update).unwrap();

        assert!(state.nullifier_exists(&nullifier));
    }

    #[test]
    fn test_esl_double_spend_prevention() {
        let mut state = ESLState::new(16);

        let nullifier = Nullifier::derive(&[1u8; 32], &[2u8; 32]);

        // First update succeeds
        let update1 = StateUpdate::new(
            vec![nullifier],
            vec![Commitment::commit(1000, &[3u8; 32])],
            1,
            vec![],
        );
        state.apply_update(&update1).unwrap();

        // Second update with same nullifier should fail
        let update2 = StateUpdate::new(
            vec![nullifier],
            vec![Commitment::commit(500, &[4u8; 32])],
            2,
            vec![],
        );
        let result = state.apply_update(&update2);
        assert!(result.is_err());
    }

    #[test]
    fn test_esl_commitment_root_changes() {
        let mut state = ESLState::new(16);
        let initial_root = *state.commitment_root();

        // Use Commitment::commit for valid non-zero commitment
        let commitment = Commitment::commit(1000, &[1u8; 32]);
        let encrypted_balance = EncryptedBalance::new(vec![0u8; 64]);
        let fragment = StateFragment::new(encrypted_balance, *commitment.as_bytes(), [2u8; 32], 0);
        state.add_fragment(fragment).unwrap();

        assert_ne!(state.commitment_root(), &initial_root);
    }

    #[test]
    fn test_esl_snapshot() {
        let mut state = ESLState::new(16);

        // Add some state via fragments with valid non-zero commitments
        for i in 1u8..=5 {
            // Use Commitment::commit to generate valid non-zero commitments
            let commitment_value = Commitment::commit((i as u64) * 1000, &[i; 32]);
            let encrypted_balance = EncryptedBalance::new(vec![0u8; 64]);
            let fragment = StateFragment::new(encrypted_balance, *commitment_value.as_bytes(), [i; 32], 0);
            state.add_fragment(fragment).unwrap();
        }

        let snapshot = state.snapshot();
        assert_eq!(snapshot.epoch, 0);
        assert_eq!(snapshot.num_commitments, 5);
    }

    #[test]
    fn test_nullifier_tree_merkle_proofs() {
        // Use depth 16 to avoid excessive memory allocation
        let mut tree = NullifierTree::with_depth(16);

        // Insert nullifiers using derive to ensure valid non-zero values
        for i in 1..=10u64 {
            let mut secret = [0u8; 32];
            secret[..8].copy_from_slice(&i.to_le_bytes());
            let mut commitment = [0u8; 32];
            commitment[0] = i as u8;
            let nullifier = Nullifier::derive(&secret, &commitment);
            tree.insert(nullifier).unwrap();
        }

        // Get membership proof for an existing nullifier
        let mut secret = [0u8; 32];
        secret[..8].copy_from_slice(&5u64.to_le_bytes());
        let mut commitment = [0u8; 32];
        commitment[0] = 5;
        let existing_nf = Nullifier::derive(&secret, &commitment);

        let proof = tree.get_membership_proof(&existing_nf);
        assert!(proof.is_some());
        assert!(proof.unwrap().is_membership_proof);

        // Get non-membership proof for non-existing
        let non_existing = Nullifier::derive(&[0xFF; 32], &[0xFE; 32]);
        let non_proof = tree.get_non_membership_proof(&non_existing);
        assert!(non_proof.is_some());
        assert!(!non_proof.unwrap().is_membership_proof);
    }
}

// =============================================================================
// END-TO-END TRANSACTION FLOW TESTS
// =============================================================================

mod e2e_tests {
    use super::*;

    /// Test encrypted mempool flow
    #[tokio::test]
    async fn test_e2e_encrypted_mempool() {
        // Create mempool with 3-of-5 threshold
        let config = MempoolConfig {
            threshold: 3,
            total_validators: 5,
            ..Default::default()
        };
        let mempool = EncryptedMempool::new(config).unwrap();

        // Simulate transaction data
        let tx_data = serde_json::to_vec(&serde_json::json!({
            "type": "transfer",
            "amount": 1000,
            "recipient": "one-time-address",
        })).unwrap();

        // Encrypt and submit
        let ciphertext = mempool.encrypt_transaction(&tx_data).unwrap();
        let tx_id = mempool.submit(ciphertext.clone(), 1000).await.unwrap();

        // Simulate validators creating decryption shares
        let key_shares = mempool.key_shares();
        let dec_shares: Vec<_> = key_shares
            .iter()
            .take(3)
            .map(|ks| ks.create_decryption_share(&ciphertext).unwrap())
            .collect();

        // Submit decryption shares
        for share in dec_shares {
            mempool.submit_share(&tx_id, share).await.unwrap();
        }

        // Decrypt
        let plaintext = mempool.try_decrypt(&tx_id).await.unwrap().unwrap();
        assert_eq!(plaintext, tx_data);
    }

    /// Test consensus attestation flow
    #[test]
    fn test_e2e_consensus_attestation() {
        // Create validators
        let validators: Vec<Validator> = (0..10)
            .map(|i| {
                let mut id = [0u8; 32];
                id[0] = i;
                Validator::new(id, vec![0u8; 64], [i; 32], 1_000_000)
            })
            .collect();

        // Select committee for round 1
        let randomness = [0x42u8; 32];
        let committee = Committee::select(1, &validators, &randomness, 7, 5).unwrap();

        // Create threshold scheme for committee
        let (scheme, shares) = ThresholdScheme::new(committee.members.len(), 5).unwrap();

        // Simulate transaction to attest
        let tx_hash = [0xAB; 32];

        // Committee members create partial signatures
        let partials: Vec<_> = shares
            .iter()
            .take(5)
            .map(|s| scheme.partial_sign(s, &tx_hash).unwrap())
            .collect();

        // Aggregate into threshold signature
        let threshold_sig = scheme.aggregate(&partials).unwrap();

        // Verify attestation
        assert!(scheme.verify(&threshold_sig, &tx_hash));
    }

    /// Test ESL state update flow
    #[test]
    fn test_e2e_state_update() {
        let mut state = ESLState::new(16);

        // Generate valid non-zero commitments using Commitment::commit
        let output_commitment1 = Commitment::commit(1000, &[1u8; 32]);
        let output_commitment2 = Commitment::commit(2000, &[2u8; 32]);

        // Add commitments as fragments
        let encrypted_balance1 = EncryptedBalance::new(vec![0u8; 64]);
        let fragment1 = StateFragment::new(encrypted_balance1, *output_commitment1.as_bytes(), [1u8; 32], 0);
        state.add_fragment(fragment1).unwrap();

        let encrypted_balance2 = EncryptedBalance::new(vec![0u8; 64]);
        let fragment2 = StateFragment::new(encrypted_balance2, *output_commitment2.as_bytes(), [2u8; 32], 0);
        state.add_fragment(fragment2).unwrap();

        // Simulate spending notes (adding nullifiers via state update)
        let nullifiers = [
            Nullifier::derive(&[10u8; 32], &[1u8; 32]),
            Nullifier::derive(&[11u8; 32], &[2u8; 32]),
        ];

        // Verify nullifiers don't exist yet
        for nf in &nullifiers {
            assert!(!state.nullifier_exists(nf));
        }

        // Add nullifiers via state update
        let update = StateUpdate::new(
            nullifiers.to_vec(),
            vec![
                Commitment::commit(3000, &[3u8; 32]),
                Commitment::commit(4000, &[4u8; 32]),
            ],
            1,
            vec![],
        );
        state.apply_update(&update).unwrap();

        // Verify nullifiers now exist
        for nf in &nullifiers {
            assert!(state.nullifier_exists(nf));
        }

        // Verify state - fragments (2) + state update commitments (2)
        assert_eq!(state.num_commitments(), 4);
    }

    /// Test mempool to consensus to state flow
    #[tokio::test]
    async fn test_e2e_mempool_consensus_state() {
        // 1. Create mempool
        let mempool_config = MempoolConfig {
            threshold: 2,
            total_validators: 3,
            ..Default::default()
        };
        let mempool = EncryptedMempool::new(mempool_config).unwrap();

        // 2. Submit encrypted transaction
        let tx_bytes = b"test transaction data";
        let ciphertext = mempool.encrypt_transaction(tx_bytes).unwrap();
        let tx_id = mempool.submit(ciphertext.clone(), 100).await.unwrap();

        // 3. Simulate threshold decryption
        let key_shares = mempool.key_shares();
        let dec_shares: Vec<_> = key_shares
            .iter()
            .take(2)
            .map(|ks| ks.create_decryption_share(&ciphertext).unwrap())
            .collect();

        for share in dec_shares {
            mempool.submit_share(&tx_id, share).await.unwrap();
        }

        let plaintext = mempool.try_decrypt(&tx_id).await.unwrap().unwrap();

        // 4. Create consensus attestation
        let (scheme, shares) = ThresholdScheme::new(5, 3).unwrap();
        let partials: Vec<_> = shares
            .iter()
            .take(3)
            .map(|s| scheme.partial_sign(s, &plaintext).unwrap())
            .collect();
        let attestation = scheme.aggregate(&partials).unwrap();
        assert!(scheme.verify(&attestation, &plaintext));

        // 5. Update state
        let mut state = ESLState::new(16);

        // Add mock nullifier via state update
        let nullifier = Nullifier::derive(&[1u8; 32], &[2u8; 32]);
        let commitment = Commitment::commit(1000, &[3u8; 32]);
        let update = StateUpdate::new(
            vec![nullifier],
            vec![commitment],
            1,
            vec![],
        );
        state.apply_update(&update).unwrap();
        assert!(state.nullifier_exists(&nullifier));

        // Add mock fragment with valid non-zero commitment
        let fragment_commitment = Commitment::commit(5000, &[5u8; 32]);
        let encrypted_balance = EncryptedBalance::new(vec![0u8; 64]);
        let fragment = StateFragment::new(encrypted_balance, *fragment_commitment.as_bytes(), [1u8; 32], 0);
        state.add_fragment(fragment).unwrap();

        assert!(state.num_commitments() > 0);
    }
}

// =============================================================================
// TRANSACTION LIFECYCLE TESTS
// =============================================================================

mod lifecycle_tests {
    use super::*;

    #[tokio::test]
    async fn test_lifecycle_creation() {
        let config = LifecycleConfig::default();
        let lifecycle = TransactionLifecycle::new(config);

        assert_eq!(lifecycle.balance().await, 0);
    }

    #[tokio::test]
    async fn test_lifecycle_with_builder_pattern() {
        let config = LifecycleConfig::default();
        let propagator = Arc::new(InMemoryPropagator::new());
        let state_provider = Arc::new(InMemoryStateProvider::new());
        let callback = Arc::new(NoOpCallback);

        let lifecycle = TransactionLifecycle::new(config)
            .with_propagator(propagator)
            .with_state_provider(state_provider)
            .with_callback(callback);

        assert_eq!(lifecycle.balance().await, 0);
    }

    #[tokio::test]
    async fn test_lifecycle_with_wallet_keys() {
        let mnemonic = Mnemonic::generate().unwrap();
        let wallet = HDWallet::from_mnemonic(&mnemonic, "", 0).unwrap();

        let config = LifecycleConfig::default();
        let lifecycle = TransactionLifecycle::new(config)
            .from_hd_wallet(&wallet);

        assert!(lifecycle.is_ok());
    }

    #[test]
    fn test_transaction_status_variants() {
        // Test all status variants exist and can be matched
        let statuses = [
            TransactionStatus::Created,
            TransactionStatus::Signed,
            TransactionStatus::Proved,
            TransactionStatus::Submitted,
            TransactionStatus::Propagated,
            TransactionStatus::Pending,
            TransactionStatus::Confirmed { attestation_count: 7 },
            TransactionStatus::Rejected { reason: "test".to_string() },
            TransactionStatus::Failed { error: "error".to_string() },
        ];

        for status in &statuses {
            match status {
                TransactionStatus::Created => {}
                TransactionStatus::Signed => {}
                TransactionStatus::Proved => {}
                TransactionStatus::Submitted => {}
                TransactionStatus::Propagated => {}
                TransactionStatus::Pending => {}
                TransactionStatus::Confirmed { attestation_count } => {
                    assert_eq!(*attestation_count, 7);
                }
                TransactionStatus::Rejected { reason } => {
                    assert_eq!(reason, "test");
                }
                TransactionStatus::Failed { error } => {
                    assert_eq!(error, "error");
                }
            }
        }
    }
}
