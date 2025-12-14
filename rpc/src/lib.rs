//! PHANTOM JSON-RPC 2.0 Server
//!
//! Provides HTTP and WebSocket RPC endpoints for node interaction.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                   PHANTOM RPC Server                         │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
//! │  │   HTTP/WS    │  │   Method     │  │   Node       │       │
//! │  │   Server     │──│   Router     │──│   Interface  │       │
//! │  └──────────────┘  └──────────────┘  └──────────────┘       │
//! │         │                                    │               │
//! │         └────────────────────────────────────┘               │
//! │                          │                                   │
//! │                 ┌────────▼────────┐                         │
//! │                 │  PhantomNode    │                         │
//! │                 └─────────────────┘                         │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Supported Methods
//!
//! ## Node
//! - `phantom_nodeInfo` - Get node status and version
//! - `phantom_peerCount` - Get connected peer count
//! - `phantom_syncing` - Get sync status
//!
//! ## State
//! - `phantom_getStateRoot` - Get current state Merkle root
//! - `phantom_getBalance` - Get wallet balance
//! - `phantom_getEpoch` - Get current epoch
//!
//! ## Transaction
//! - `phantom_sendTransaction` - Submit transaction
//! - `phantom_getTransaction` - Get transaction status
//! - `phantom_getMempoolSize` - Get mempool transaction count
//!
//! ## Consensus
//! - `phantom_getRound` - Get current consensus round
//! - `phantom_getValidators` - Get validator set

pub mod errors;
pub mod server;
pub mod methods;
pub mod types;

pub use errors::{RpcError, RpcResult};
pub use server::{RpcServer, RpcConfig};
pub use types::*;

/// RPC API version
pub const RPC_VERSION: &str = "1.0.0";

/// Default RPC port
pub const DEFAULT_RPC_PORT: u16 = 8545;

/// Default WebSocket port
pub const DEFAULT_WS_PORT: u16 = 8546;
