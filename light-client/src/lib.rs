//! PHANTOM Light Client
//!
//! Privacy-preserving light client for mobile and resource-constrained devices.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                 PHANTOM Light Client                        │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
//! │  │   Header    │  │    Sync     │  │   Proof     │         │
//! │  │   Chain     │  │  Protocol   │  │ Delegation  │         │
//! │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘         │
//! │         │                │                │                 │
//! │         └────────────────┼────────────────┘                 │
//! │                          ▼                                  │
//! │  ┌─────────────────────────────────────────────────────┐   │
//! │  │              Verification Layer                      │   │
//! │  │  - SPV-style proofs                                  │   │
//! │  │  - FHE proof verification                            │   │
//! │  │  - State commitment checking                         │   │
//! │  └─────────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Key Features
//!
//! - **Header Chain**: Stores only block headers (not full blocks)
//! - **Sync Protocol**: Efficient checkpoint-based synchronization
//! - **Proof Delegation**: Offload heavy FHE computations to full nodes
//! - **SPV Proofs**: Verify transaction inclusion without full state

pub mod errors;
pub mod header;
pub mod sync;
pub mod verification;
pub mod client;
pub mod delegation;
pub mod wasm;

// Re-export main types
pub use errors::{LightClientError, LightClientResult};
pub use header::{BlockHeader, HeaderChain, ChainTip};
pub use sync::{SyncConfig, SyncManager, SyncStatus, Checkpoint};
pub use verification::{ProofVerifier, InclusionProof, StateProof};
pub use client::{LightClient, ClientConfig, ClientState};
pub use wasm::{WasmLightClient, JsBlockHeader, JsInclusionProof};
pub use delegation::{
    DelegationManager, DelegationConfig, DelegationNode, DelegationStats,
    DelegationRequest, DelegationResponse, DelegatedProofType, DelegatedProofData,
    ProofDelegator, DelegationNetwork, TrustLevel, ComputationWitness,
};

/// Prelude for convenient imports
pub mod prelude {
    pub use crate::errors::{LightClientError, LightClientResult};
    pub use crate::header::{BlockHeader, HeaderChain, ChainTip};
    pub use crate::sync::{SyncConfig, SyncManager, SyncStatus};
    pub use crate::verification::{ProofVerifier, InclusionProof, StateProof};
    pub use crate::client::{LightClient, ClientConfig, ClientState};
}
