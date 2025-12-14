//! RPC Method Implementations
//!
//! Defines the JSON-RPC API using jsonrpsee macros.

use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;

use crate::types::*;

/// PHANTOM RPC API trait
///
/// All methods are prefixed with `phantom_` namespace.
#[rpc(server, namespace = "phantom")]
pub trait PhantomApi {
    // =========== Node Methods ===========

    /// Get node information and status
    #[method(name = "nodeInfo")]
    async fn node_info(&self) -> RpcResult<NodeInfo>;

    /// Get connected peer count
    #[method(name = "peerCount")]
    async fn peer_count(&self) -> RpcResult<usize>;

    /// Get sync status
    #[method(name = "syncing")]
    async fn syncing(&self) -> RpcResult<SyncStatus>;

    /// Get list of connected peers
    #[method(name = "peers")]
    async fn peers(&self) -> RpcResult<Vec<PeerInfo>>;

    // =========== State Methods ===========

    /// Get current state merkle root
    #[method(name = "getStateRoot")]
    async fn get_state_root(&self) -> RpcResult<String>;

    /// Get wallet balance
    #[method(name = "getBalance")]
    async fn get_balance(&self) -> RpcResult<BalanceResponse>;

    /// Get current epoch
    #[method(name = "getEpoch")]
    async fn get_epoch(&self) -> RpcResult<u64>;

    /// Get state proof for a commitment
    #[method(name = "getStateProof")]
    async fn get_state_proof(&self, commitment: String) -> RpcResult<StateProofResponse>;

    // =========== Transaction Methods ===========

    /// Send a transaction (high-level API)
    #[method(name = "sendTransaction")]
    async fn send_transaction(&self, request: SendTransactionRequest) -> RpcResult<SendTransactionResponse>;

    /// Send raw transaction bytes
    #[method(name = "sendRawTransaction")]
    async fn send_raw_transaction(&self, request: RawTransactionRequest) -> RpcResult<SendTransactionResponse>;

    /// Get transaction status by ID
    #[method(name = "getTransaction")]
    async fn get_transaction(&self, tx_id: String) -> RpcResult<TransactionInfo>;

    /// Get mempool information
    #[method(name = "getMempoolInfo")]
    async fn get_mempool_info(&self) -> RpcResult<MempoolInfo>;

    // =========== Consensus Methods ===========

    /// Get current consensus round
    #[method(name = "getRound")]
    async fn get_round(&self) -> RpcResult<u64>;

    /// Get validator set
    #[method(name = "getValidators")]
    async fn get_validators(&self) -> RpcResult<Vec<ValidatorInfo>>;

    // =========== Admin Methods ===========

    /// Stop the node (requires admin auth)
    #[method(name = "admin_stopNode")]
    async fn admin_stop_node(&self) -> RpcResult<bool>;

    /// Get node version
    #[method(name = "version")]
    async fn version(&self) -> RpcResult<String>;
}

/// Subscription API for real-time updates (WebSocket only)
#[rpc(server, namespace = "phantom")]
pub trait PhantomSubscriptionApi {
    /// Subscribe to new transactions
    #[subscription(name = "subscribeNewTransactions" => "newTransaction", item = TransactionInfo)]
    async fn subscribe_new_transactions(&self) -> jsonrpsee::core::SubscriptionResult;

    /// Subscribe to state updates
    #[subscription(name = "subscribeStateUpdates" => "stateUpdate", item = String)]
    async fn subscribe_state_updates(&self) -> jsonrpsee::core::SubscriptionResult;

    /// Subscribe to consensus rounds
    #[subscription(name = "subscribeRounds" => "newRound", item = u64)]
    async fn subscribe_rounds(&self) -> jsonrpsee::core::SubscriptionResult;
}
