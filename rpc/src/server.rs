//! RPC Server Implementation

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use jsonrpsee::core::{async_trait, RpcResult, SubscriptionResult};
use jsonrpsee::server::{Server, ServerHandle};
use jsonrpsee::types::ErrorObjectOwned;
use jsonrpsee::PendingSubscriptionSink;
use tokio::sync::RwLock;
use tracing::{info, warn, error};

use phantom_esl::ESLState;
use phantom_cwa::CWAProtocol;
use phantom_mempool::EncryptedMempool;
use phantom_p2p::SwarmManager;

use crate::errors::{RpcError, RpcErrorCode};
use crate::methods::{PhantomApiServer, PhantomSubscriptionApiServer};
use crate::types::*;
use crate::RPC_VERSION;

/// RPC server configuration
#[derive(Debug, Clone)]
pub struct RpcConfig {
    /// HTTP bind address
    pub http_addr: SocketAddr,
    /// WebSocket bind address (optional)
    pub ws_addr: Option<SocketAddr>,
    /// Maximum request size in bytes
    pub max_request_size: u32,
    /// Maximum response size in bytes
    pub max_response_size: u32,
    /// Maximum concurrent connections
    pub max_connections: u32,
    /// Enable CORS
    pub cors_enabled: bool,
    /// CORS allowed origins
    pub cors_origins: Vec<String>,
    /// Require authentication for admin methods
    pub require_admin_auth: bool,
    /// Admin API key (if auth required)
    pub admin_api_key: Option<String>,
    /// Network name
    pub network: String,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            http_addr: "127.0.0.1:8545".parse().unwrap(),
            ws_addr: Some("127.0.0.1:8546".parse().unwrap()),
            max_request_size: 10 * 1024 * 1024, // 10MB
            max_response_size: 10 * 1024 * 1024,
            max_connections: 100,
            cors_enabled: true,
            cors_origins: vec!["*".to_string()],
            require_admin_auth: true,
            admin_api_key: None,
            network: "local".to_string(),
        }
    }
}

impl RpcConfig {
    /// Create config for local development
    pub fn local() -> Self {
        Self::default()
    }

    /// Create config for testnet
    pub fn testnet() -> Self {
        Self {
            http_addr: "0.0.0.0:8545".parse().unwrap(),
            ws_addr: Some("0.0.0.0:8546".parse().unwrap()),
            cors_origins: vec![
                "https://phantom-testnet.io".to_string(),
                "http://localhost:*".to_string(),
            ],
            network: "testnet".to_string(),
            ..Default::default()
        }
    }

    /// Create config for mainnet
    pub fn mainnet() -> Self {
        Self {
            http_addr: "0.0.0.0:8545".parse().unwrap(),
            ws_addr: Some("0.0.0.0:8546".parse().unwrap()),
            cors_enabled: false,
            require_admin_auth: true,
            network: "mainnet".to_string(),
            ..Default::default()
        }
    }
}

/// Node context shared with RPC handlers
pub struct NodeContext {
    /// P2P swarm manager
    pub swarm: Arc<RwLock<SwarmManager>>,
    /// CWA consensus protocol
    pub consensus: Arc<RwLock<CWAProtocol>>,
    /// ESL state
    pub state: Arc<RwLock<ESLState>>,
    /// Encrypted mempool
    pub mempool: Arc<RwLock<EncryptedMempool>>,
    /// Node running flag
    pub running: Arc<RwLock<bool>>,
    /// Validator ID if this is a validator
    pub validator_id: Option<[u8; 32]>,
    /// Validator stake
    pub validator_stake: u64,
    /// Wallet balance (would come from wallet lifecycle in production)
    pub balance: Arc<RwLock<u64>>,
    /// Network name
    pub network: String,
    /// Peer ID as string
    pub peer_id: String,
}

/// The RPC server
pub struct RpcServer {
    config: RpcConfig,
    context: Arc<NodeContext>,
    handle: Option<ServerHandle>,
}

impl RpcServer {
    /// Create a new RPC server
    pub fn new(config: RpcConfig, context: NodeContext) -> Self {
        Self {
            config,
            context: Arc::new(context),
            handle: None,
        }
    }

    /// Start the HTTP RPC server
    pub async fn start(&mut self) -> Result<(), RpcError> {
        let server = Server::builder()
            .max_request_body_size(self.config.max_request_size)
            .max_response_body_size(self.config.max_response_size)
            .max_connections(self.config.max_connections)
            .build(self.config.http_addr)
            .await
            .map_err(|e| RpcError::ServerError(e.to_string()))?;

        let handler = RpcHandler::new(self.context.clone(), self.config.clone());
        let rpc_module = handler.into_rpc();

        info!("Starting RPC server on {}", self.config.http_addr);

        let handle = server.start(rpc_module);
        self.handle = Some(handle);

        Ok(())
    }

    /// Stop the RPC server
    pub async fn stop(&mut self) -> Result<(), RpcError> {
        if let Some(handle) = self.handle.take() {
            info!("Stopping RPC server");
            handle.stop().map_err(|e| RpcError::ServerError(format!("{:?}", e)))?;
        }
        Ok(())
    }

    /// Get the server address
    pub fn addr(&self) -> SocketAddr {
        self.config.http_addr
    }
}

/// RPC method handler
struct RpcHandler {
    context: Arc<NodeContext>,
    config: RpcConfig,
}

impl RpcHandler {
    fn new(context: Arc<NodeContext>, config: RpcConfig) -> Self {
        Self { context, config }
    }

    fn into_rpc(self) -> jsonrpsee::RpcModule<()> {
        let mut module = jsonrpsee::RpcModule::new(());

        // We need to merge both API servers
        let api_handler = ApiHandler {
            context: self.context.clone(),
            config: self.config.clone(),
        };

        if let Err(e) = module.merge(PhantomApiServer::into_rpc(api_handler.clone())) {
            error!("Failed to merge PhantomApi: {}", e);
        }

        if let Err(e) = module.merge(PhantomSubscriptionApiServer::into_rpc(api_handler)) {
            error!("Failed to merge PhantomSubscriptionApi: {}", e);
        }

        module
    }
}

/// API handler implementing the RPC traits
#[derive(Clone)]
struct ApiHandler {
    context: Arc<NodeContext>,
    config: RpcConfig,
}

impl ApiHandler {
    fn now_timestamp(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn hex_encode(bytes: &[u8]) -> String {
        format!("0x{}", hex::encode(bytes))
    }

    fn hex_decode(s: &str) -> Result<Vec<u8>, RpcError> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        hex::decode(s).map_err(|e| RpcError::InvalidParams(format!("Invalid hex: {}", e)))
    }
}

#[async_trait]
impl PhantomApiServer for ApiHandler {
    async fn node_info(&self) -> RpcResult<NodeInfo> {
        let is_running = *self.context.running.read().await;
        let epoch = self.context.state.read().await.epoch();
        let round = self.context.consensus.read().await.round();
        let state_root = *self.context.state.read().await.commitment_root();
        let peer_count = self.context.swarm.read().await.peer_count().await.unwrap_or(0);
        let mempool_size = self.context.mempool.read().await.len().await;

        Ok(NodeInfo {
            version: RPC_VERSION.to_string(),
            network: self.config.network.clone(),
            peer_id: self.context.peer_id.clone(),
            is_running,
            is_validator: self.context.validator_id.is_some(),
            validator_stake: if self.context.validator_id.is_some() {
                Some(self.context.validator_stake)
            } else {
                None
            },
            epoch,
            round,
            state_root: Self::hex_encode(&state_root),
            peer_count,
            mempool_size,
        })
    }

    async fn peer_count(&self) -> RpcResult<usize> {
        let count = self.context.swarm.read().await.peer_count().await.unwrap_or(0);
        Ok(count)
    }

    async fn syncing(&self) -> RpcResult<SyncStatus> {
        let current_epoch = self.context.state.read().await.epoch();
        // In a real implementation, we'd track highest known epoch from peers
        let highest_epoch = current_epoch;
        let syncing = current_epoch < highest_epoch;
        let progress = if highest_epoch > 0 {
            current_epoch as f64 / highest_epoch as f64
        } else {
            1.0
        };

        Ok(SyncStatus {
            syncing,
            current_epoch,
            highest_epoch,
            progress,
            sync_peers: 0,
        })
    }

    async fn peers(&self) -> RpcResult<Vec<PeerInfo>> {
        // In production, we'd get actual peer info from swarm
        Ok(vec![])
    }

    async fn get_state_root(&self) -> RpcResult<String> {
        let root = *self.context.state.read().await.commitment_root();
        Ok(Self::hex_encode(&root))
    }

    async fn get_balance(&self) -> RpcResult<BalanceResponse> {
        let balance = *self.context.balance.read().await;
        Ok(BalanceResponse {
            confirmed: balance,
            pending: 0,
            total: balance,
        })
    }

    async fn get_epoch(&self) -> RpcResult<u64> {
        Ok(self.context.state.read().await.epoch())
    }

    async fn get_state_proof(&self, commitment: String) -> RpcResult<StateProofResponse> {
        let commitment_bytes = Self::hex_decode(&commitment)
            .map_err(|e| ErrorObjectOwned::owned(
                RpcErrorCode::InvalidParams.code(),
                e.to_string(),
                None::<()>,
            ))?;

        if commitment_bytes.len() != 32 {
            return Err(ErrorObjectOwned::owned(
                RpcErrorCode::InvalidParams.code(),
                "Commitment must be 32 bytes",
                None::<()>,
            ));
        }

        let root = *self.context.state.read().await.commitment_root();

        // In production, we'd generate actual Merkle proof
        Ok(StateProofResponse {
            root: Self::hex_encode(&root),
            path: vec![],
            indices: vec![],
            exists: false,
        })
    }

    async fn send_transaction(&self, request: SendTransactionRequest) -> RpcResult<SendTransactionResponse> {
        // Validate address
        let to_bytes = Self::hex_decode(&request.to)
            .map_err(|e| ErrorObjectOwned::owned(
                RpcErrorCode::InvalidAddress.code(),
                e.to_string(),
                None::<()>,
            ))?;

        if to_bytes.len() != 32 {
            return Err(ErrorObjectOwned::owned(
                RpcErrorCode::InvalidAddress.code(),
                "Address must be 32 bytes",
                None::<()>,
            ));
        }

        // Create transaction data
        let tx_data = serde_json::json!({
            "to": request.to,
            "amount": request.amount,
            "fee": request.fee,
            "memo": request.memo,
            "timestamp": self.now_timestamp(),
        });

        let tx_bytes = serde_json::to_vec(&tx_data)
            .map_err(|e| ErrorObjectOwned::owned(
                RpcErrorCode::InternalError.code(),
                e.to_string(),
                None::<()>,
            ))?;

        // Hash the transaction
        let tx_id = phantom_hash::hash(&tx_bytes);

        // Encrypt and submit to mempool
        let mempool = self.context.mempool.read().await;
        let ciphertext = mempool.encrypt_transaction(&tx_bytes)
            .map_err(|e| ErrorObjectOwned::owned(
                RpcErrorCode::TransactionFailed.code(),
                e.to_string(),
                None::<()>,
            ))?;
        drop(mempool);

        self.context.mempool.read().await
            .submit(ciphertext, request.fee)
            .await
            .map_err(|e| ErrorObjectOwned::owned(
                RpcErrorCode::MempoolFull.code(),
                e.to_string(),
                None::<()>,
            ))?;

        // Submit to consensus
        self.context.consensus.write().await
            .submit_update(tx_bytes)
            .map_err(|e| ErrorObjectOwned::owned(
                RpcErrorCode::ConsensusFailed.code(),
                e.to_string(),
                None::<()>,
            ))?;

        Ok(SendTransactionResponse {
            tx_id: Self::hex_encode(&tx_id),
            status: "pending".to_string(),
        })
    }

    async fn send_raw_transaction(&self, request: RawTransactionRequest) -> RpcResult<SendTransactionResponse> {
        let tx_bytes = Self::hex_decode(&request.data)
            .map_err(|e| ErrorObjectOwned::owned(
                RpcErrorCode::InvalidParams.code(),
                e.to_string(),
                None::<()>,
            ))?;

        let tx_id = phantom_hash::hash(&tx_bytes);

        // Encrypt and submit to mempool
        let mempool = self.context.mempool.read().await;
        let ciphertext = mempool.encrypt_transaction(&tx_bytes)
            .map_err(|e| ErrorObjectOwned::owned(
                RpcErrorCode::TransactionFailed.code(),
                e.to_string(),
                None::<()>,
            ))?;
        drop(mempool);

        self.context.mempool.read().await
            .submit(ciphertext, 0)
            .await
            .map_err(|e| ErrorObjectOwned::owned(
                RpcErrorCode::MempoolFull.code(),
                e.to_string(),
                None::<()>,
            ))?;

        // Submit to consensus
        self.context.consensus.write().await
            .submit_update(tx_bytes)
            .map_err(|e| ErrorObjectOwned::owned(
                RpcErrorCode::ConsensusFailed.code(),
                e.to_string(),
                None::<()>,
            ))?;

        Ok(SendTransactionResponse {
            tx_id: Self::hex_encode(&tx_id),
            status: "pending".to_string(),
        })
    }

    async fn get_transaction(&self, tx_id: String) -> RpcResult<TransactionInfo> {
        let _tx_bytes = Self::hex_decode(&tx_id)
            .map_err(|e| ErrorObjectOwned::owned(
                RpcErrorCode::InvalidParams.code(),
                e.to_string(),
                None::<()>,
            ))?;

        // In production, we'd look up the transaction status
        Ok(TransactionInfo {
            tx_id,
            status: "unknown".to_string(),
            attestation_count: 0,
            threshold: self.context.consensus.read().await.threshold(),
            epoch: None,
            timestamp: self.now_timestamp(),
        })
    }

    async fn get_mempool_info(&self) -> RpcResult<MempoolInfo> {
        let mempool = self.context.mempool.read().await;
        let size = mempool.len().await;

        Ok(MempoolInfo {
            size,
            bytes: size * 1024, // Estimate
            max_size: 10000,    // From config
            min_fee: 0,
        })
    }

    async fn get_round(&self) -> RpcResult<u64> {
        Ok(self.context.consensus.read().await.round())
    }

    async fn get_validators(&self) -> RpcResult<Vec<ValidatorInfo>> {
        let consensus = self.context.consensus.read().await;
        let validators = consensus.validators();

        Ok(validators.iter().map(|v| {
            ValidatorInfo {
                id: Self::hex_encode(&v.id),
                stake: v.stake,
                is_active: true,
                attestation_count: 0,
            }
        }).collect())
    }

    async fn admin_stop_node(&self) -> RpcResult<bool> {
        warn!("Admin stop requested via RPC");
        *self.context.running.write().await = false;
        Ok(true)
    }

    async fn version(&self) -> RpcResult<String> {
        Ok(RPC_VERSION.to_string())
    }
}

#[async_trait]
impl PhantomSubscriptionApiServer for ApiHandler {
    async fn subscribe_new_transactions(&self, _pending: PendingSubscriptionSink) -> SubscriptionResult {
        // In production, we'd set up a channel to receive new transactions
        // and forward them to the subscription
        Ok(())
    }

    async fn subscribe_state_updates(&self, _pending: PendingSubscriptionSink) -> SubscriptionResult {
        Ok(())
    }

    async fn subscribe_rounds(&self, _pending: PendingSubscriptionSink) -> SubscriptionResult {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpc_config_default() {
        let config = RpcConfig::default();
        assert_eq!(config.http_addr.port(), 8545);
        assert!(config.cors_enabled);
    }

    #[test]
    fn test_rpc_config_testnet() {
        let config = RpcConfig::testnet();
        assert_eq!(config.network, "testnet");
    }

    #[test]
    fn test_rpc_config_mainnet() {
        let config = RpcConfig::mainnet();
        assert_eq!(config.network, "mainnet");
        assert!(!config.cors_enabled);
    }

    #[test]
    fn test_hex_encode_decode() {
        let bytes = [0xde, 0xad, 0xbe, 0xef];
        let hex = ApiHandler::hex_encode(&bytes);
        assert_eq!(hex, "0xdeadbeef");

        let decoded = ApiHandler::hex_decode(&hex).unwrap();
        assert_eq!(decoded, bytes);
    }
}
