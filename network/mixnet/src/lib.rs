//! PHANTOM P2P Mixnet Layer
//!
//! Provides network-level privacy through:
//! - 5-hop onion routing (Sphinx packets)
//! - Cover traffic injection
//! - Batch shuffling at mix nodes
//! - Encrypted mempool propagation
//! - Dandelion++ transaction propagation
//! - SURB support for anonymous replies

pub mod errors;
pub mod sphinx;
pub mod mix_node;
pub mod routing;
pub mod transport;

pub use errors::{MixnetError, MixnetResult};
pub use sphinx::{SphinxPacket, ProcessedPacket, MixNodeInfo, HopInfo, SURB};
pub use mix_node::{MixNode, MixNodeConfig, MixNodeProcessor, MixDirectory};
pub use routing::{Circuit, CircuitConfig, CircuitManager, DandelionRouter, RouteDecision};
pub use transport::{MixnetTransport, TransportConfig, TransportEvent, TransportCommand, PeerInfo};

use std::sync::Arc;
use tokio::sync::RwLock;

/// Mixnet configuration
#[derive(Clone, Debug)]
pub struct MixnetConfig {
    /// Number of hops in the circuit
    pub num_hops: usize,
    /// Cover traffic rate (messages per second)
    pub cover_traffic_rate: f64,
    /// Batch size for mixing
    pub batch_size: usize,
    /// Stem length for Dandelion++
    pub stem_length: usize,
    /// Circuit lifetime in seconds
    pub circuit_lifetime_secs: u64,
    /// Enable cover traffic
    pub enable_cover_traffic: bool,
    /// Mix node configuration
    pub mix_node_config: MixNodeConfig,
}

impl Default for MixnetConfig {
    fn default() -> Self {
        Self {
            num_hops: 5,
            cover_traffic_rate: 10.0,
            batch_size: 32,
            stem_length: 3,
            circuit_lifetime_secs: 600,
            enable_cover_traffic: true,
            mix_node_config: MixNodeConfig::default(),
        }
    }
}

/// Main mixnet client
pub struct MixnetClient {
    /// Configuration
    config: MixnetConfig,
    /// Our node identity (if acting as mix node)
    node_id: Option<[u8; 32]>,
    /// Private key for decryption
    private_key: Option<[u8; 32]>,
    /// Circuit manager
    circuit_manager: Arc<RwLock<CircuitManager>>,
    /// Dandelion router
    dandelion_router: Arc<RwLock<DandelionRouter>>,
    /// Packet processor (if acting as mix node)
    processor: Option<Arc<MixNodeProcessor>>,
    /// Running state
    running: Arc<RwLock<bool>>,
}

impl MixnetClient {
    /// Create a new mixnet client
    pub fn new(config: MixnetConfig, directory: MixDirectory) -> Self {
        let circuit_config = CircuitConfig {
            num_hops: config.num_hops,
            stem_length: config.stem_length,
            max_lifetime_secs: config.circuit_lifetime_secs,
            ..Default::default()
        };

        Self {
            config: config.clone(),
            node_id: None,
            private_key: None,
            circuit_manager: Arc::new(RwLock::new(
                CircuitManager::new(circuit_config, directory)
            )),
            dandelion_router: Arc::new(RwLock::new(
                DandelionRouter::new(config.stem_length)
            )),
            processor: None,
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Initialize as a mix node
    pub fn init_as_mix_node(&mut self, node_id: [u8; 32], private_key: [u8; 32]) {
        self.node_id = Some(node_id);
        self.private_key = Some(private_key);

        self.processor = Some(Arc::new(MixNodeProcessor::new(
            node_id,
            private_key,
            self.config.mix_node_config.clone(),
        )));
    }

    /// Send a message through the mixnet
    pub async fn send(&self, payload: &[u8], destination: [u8; 32]) -> MixnetResult<()> {
        let circuit_manager = self.circuit_manager.read().await;

        // Get or build a circuit
        let circuit = circuit_manager.get_random_circuit()
            .ok_or_else(|| MixnetError::NoRoute)?;

        // Create Sphinx packet
        let packet = circuit.send(payload, &destination)?;

        // Route through Dandelion++
        let mut router = self.dandelion_router.write().await;
        let decision = router.route_new(packet, destination);

        match decision {
            RouteDecision::StemForward { packet, next_hop } => {
                // In production, would send to next_hop
                Ok(())
            }
            RouteDecision::Broadcast { packet, exclude } => {
                // In production, would broadcast to network
                Ok(())
            }
            RouteDecision::Drop => {
                Err(MixnetError::InvalidPacket("Message dropped".into()))
            }
        }
    }

    /// Send a message with a reply SURB
    pub async fn send_with_reply(
        &self,
        payload: &[u8],
        destination: [u8; 32],
    ) -> MixnetResult<SURB> {
        let circuit_manager = self.circuit_manager.read().await;

        // Get or build a circuit
        let circuit = circuit_manager.get_random_circuit()
            .ok_or_else(|| MixnetError::NoRoute)?;

        // Create SURB for reply path
        let surb = SURB::create(&circuit.path, &self.private_key.unwrap_or([0u8; 32]))?;

        // Append SURB info to payload
        let mut full_payload = payload.to_vec();
        let surb_bytes = serde_json::to_vec(&surb)
            .map_err(|e| MixnetError::InvalidPacket(e.to_string()))?;
        full_payload.extend_from_slice(&surb_bytes);

        // Create and send packet
        let packet = circuit.send(&full_payload, &destination)?;

        let mut router = self.dandelion_router.write().await;
        router.route_new(packet, destination);

        Ok(surb)
    }

    /// Process an incoming packet (as mix node)
    pub async fn process_packet(&self, packet: SphinxPacket) -> MixnetResult<ProcessingAction> {
        let processor = self.processor.as_ref()
            .ok_or_else(|| MixnetError::InvalidPacket("Not a mix node".into()))?;

        let result = processor.process_packet(packet).await?;

        match result {
            mix_node::ProcessingResult::Queued { next_hop } => {
                Ok(ProcessingAction::Forward { next_hop })
            }
            mix_node::ProcessingResult::Delivered { destination, payload } => {
                Ok(ProcessingAction::Deliver { destination, payload })
            }
        }
    }

    /// Build a new circuit
    pub async fn build_circuit(&self) -> MixnetResult<[u8; 32]> {
        let mut manager = self.circuit_manager.write().await;
        let id = manager.build_circuit()?;
        manager.mark_ready(&id);
        Ok(id)
    }

    /// Get circuit count
    pub async fn circuit_count(&self) -> usize {
        self.circuit_manager.read().await.circuit_count()
    }

    /// Get usable circuit count
    pub async fn usable_circuit_count(&self) -> usize {
        self.circuit_manager.read().await.usable_count()
    }

    /// Cleanup expired circuits
    pub async fn cleanup(&self) -> usize {
        let mut manager = self.circuit_manager.write().await;
        manager.cleanup_expired()
    }

    /// Get processor statistics (if mix node)
    pub async fn stats(&self) -> Option<mix_node::ProcessorStats> {
        if let Some(ref processor) = self.processor {
            Some(processor.stats().await)
        } else {
            None
        }
    }

    /// Start background tasks (cover traffic, cleanup)
    pub async fn start(&self) {
        let mut running = self.running.write().await;
        *running = true;
    }

    /// Stop background tasks
    pub async fn stop(&self) {
        let mut running = self.running.write().await;
        *running = false;
    }

    /// Check if running
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }
}

/// Action to take after processing a packet
#[derive(Clone, Debug)]
pub enum ProcessingAction {
    /// Forward to next hop
    Forward { next_hop: [u8; 32] },
    /// Deliver to local recipient
    Deliver { destination: [u8; 32], payload: Vec<u8> },
}

/// Cover traffic generator
pub struct CoverTrafficGenerator {
    /// Rate in messages per second
    rate: f64,
    /// Directory for routing
    directory: Arc<RwLock<MixDirectory>>,
    /// Running flag
    running: Arc<RwLock<bool>>,
}

impl CoverTrafficGenerator {
    /// Create a new generator
    pub fn new(rate: f64, directory: Arc<RwLock<MixDirectory>>) -> Self {
        Self {
            rate,
            directory,
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Generate a cover traffic packet
    pub async fn generate(&self) -> MixnetResult<SphinxPacket> {
        let dir = self.directory.read().await;
        let route = dir.select_route(5)?;

        // Random dummy payload
        let mut payload = vec![0u8; 256];
        getrandom::getrandom(&mut payload)
            .map_err(|e| MixnetError::CryptoError(e.to_string()))?;

        // Random destination
        let mut destination = [0u8; 32];
        getrandom::getrandom(&mut destination)
            .map_err(|e| MixnetError::CryptoError(e.to_string()))?;

        SphinxPacket::create(&payload, &route, &destination)
    }

    /// Start generating cover traffic
    pub async fn start(&self) {
        let mut running = self.running.write().await;
        *running = true;
    }

    /// Stop generating cover traffic
    pub async fn stop(&self) {
        let mut running = self.running.write().await;
        *running = false;
    }

    /// Check if running
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    /// Get interval between cover messages in milliseconds
    pub fn interval_ms(&self) -> u64 {
        if self.rate <= 0.0 {
            return u64::MAX;
        }
        (1000.0 / self.rate) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_directory() -> MixDirectory {
        let mut dir = MixDirectory::new(3);

        for layer in 0..3 {
            for i in 0..10 {
                let mut id = [0u8; 32];
                id[0] = layer;
                id[1] = i;

                let mut public_key = [0u8; 32];
                public_key[0] = layer;
                public_key[1] = i;

                dir.add_node(MixNode::new(
                    id,
                    public_key,
                    format!("127.0.0.1:{}", 10000 + (layer as u16) * 100 + (i as u16)),
                    layer,
                ));
            }
        }

        dir
    }

    #[tokio::test]
    async fn test_client_creation() {
        let config = MixnetConfig::default();
        let directory = create_test_directory();
        let client = MixnetClient::new(config, directory);

        assert_eq!(client.circuit_count().await, 0);
    }

    #[tokio::test]
    async fn test_circuit_building() {
        let config = MixnetConfig::default();
        let directory = create_test_directory();
        let client = MixnetClient::new(config, directory);

        let circuit_id = client.build_circuit().await.unwrap();
        assert_eq!(client.circuit_count().await, 1);
        assert_eq!(client.usable_circuit_count().await, 1);
    }

    #[tokio::test]
    async fn test_cover_traffic_generator() {
        let directory = Arc::new(RwLock::new(create_test_directory()));
        let generator = CoverTrafficGenerator::new(10.0, directory);

        let packet = generator.generate().await.unwrap();
        assert_eq!(packet.version, SphinxPacket::VERSION);
    }
}
