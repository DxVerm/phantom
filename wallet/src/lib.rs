//! PHANTOM Wallet
//!
//! Privacy-preserving wallet with:
//! - Post-quantum key generation (Kyber + Dilithium)
//! - Stealth address support (DKSAP protocol)
//! - Hierarchical deterministic key derivation (BIP32/44-style)
//! - Local ZK proof generation (Nova folding)
//! - Note management with nullifier tracking
//! - Private transaction building
//! - Complete transaction lifecycle management

pub mod keypair;
pub mod note;
pub mod transaction;
pub mod stealth;
pub mod hd;
pub mod lifecycle;

pub use keypair::Keypair;
pub use note::Note;
pub use stealth::{ViewKey, SpendKey, StealthAddress, OneTimeAddress, SpendingKey, PaymentCode, StealthError};
pub use hd::{HDWallet, Mnemonic, ExtendedKey, DerivationPath, PathComponent, HDError, PHANTOM_COIN_TYPE};
pub use transaction::{
    Transaction, TransactionBuilder, TransactionVerifier, TransactionError,
    TransactionInput, TransactionOutput, TransactionConfig, TransactionProof,
    NoteManager, OwnedNote, NovaProofData, Groth16ProofData,
};
pub use lifecycle::{
    TransactionLifecycle, TransactionStatus, LifecycleConfig, LifecycleError,
    LifecycleResult, PendingTransaction, TransactionAttestation, LifecycleCallback,
    TransactionPropagator, StateProvider, LifecycleEvent, TransactionSummary,
    InMemoryPropagator, InMemoryStateProvider, NoOpCallback,
};
