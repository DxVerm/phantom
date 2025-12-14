//! Mix node implementation
//!
//! Mix nodes form the backbone of the mixnet:
//! - Process Sphinx packets (peel encryption layer)
//! - Add random delays to break timing correlation
//! - Batch and shuffle messages before forwarding
//! - Generate cover traffic to mask real messages

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use serde::{Deserialize, Serialize};

use crate::errors::{MixnetError, MixnetResult};
use crate::sphinx::{SphinxPacket, ProcessedPacket, MixNodeInfo};

/// Mix node configuration
#[derive(Clone, Debug)]
pub struct MixNodeConfig {
    /// Minimum batch size before processing
    pub min_batch_size: usize,
    /// Maximum batch size
    pub max_batch_size: usize,
    /// Maximum delay in milliseconds
    pub max_delay_ms: u64,
    /// Cover traffic rate (messages per second)
    pub cover_traffic_rate: f64,
    /// Enable replay detection
    pub replay_detection: bool,
    /// Tag cache TTL in seconds
    pub tag_cache_ttl_secs: u64,
}

impl Default for MixNodeConfig {
    fn default() -> Self {
        Self {
            min_batch_size: 8,
            max_batch_size: 64,
            max_delay_ms: 2000,
            cover_traffic_rate: 10.0,
            replay_detection: true,
            tag_cache_ttl_secs: 3600,
        }
    }
}

/// A mix node in the network
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MixNode {
    /// Node identifier
    pub id: [u8; 32],
    /// Node public key for packet encryption
    pub public_key: [u8; 32],
    /// Network address (IP:port)
    pub address: String,
    /// Layer in the mixnet (0 = entry, higher = closer to exit)
    pub layer: u8,
    /// Node reputation score
    pub reputation: f64,
    /// Whether node is currently online
    pub online: bool,
    /// Total messages processed
    pub messages_processed: u64,
}

impl MixNode {
    /// Create a new mix node
    pub fn new(id: [u8; 32], public_key: [u8; 32], address: String, layer: u8) -> Self {
        Self {
            id,
            public_key,
            address,
            layer,
            reputation: 100.0,
            online: true,
            messages_processed: 0,
        }
    }

    /// Convert to MixNodeInfo for route construction
    pub fn to_info(&self) -> MixNodeInfo {
        MixNodeInfo {
            id: self.id,
            public_key: self.public_key,
        }
    }

    /// Update reputation based on performance
    pub fn update_reputation(&mut self, success: bool) {
        if success {
            self.reputation = (self.reputation + 0.1).min(100.0);
        } else {
            self.reputation = (self.reputation - 1.0).max(0.0);
        }
    }
}

/// A message waiting to be processed
#[derive(Clone, Debug)]
struct PendingMessage {
    /// The packet to forward
    packet: SphinxPacket,
    /// Destination (next hop or final)
    destination: [u8; 32],
    /// When to release (unix timestamp ms)
    release_at: u64,
    /// Is this cover traffic?
    is_cover: bool,
}

/// Mix node processor handles packet processing and batching
pub struct MixNodeProcessor {
    /// Node identity
    node_id: [u8; 32],
    /// Private key for decryption
    private_key: [u8; 32],
    /// Configuration
    config: MixNodeConfig,
    /// Pending messages queue
    pending: Arc<Mutex<VecDeque<PendingMessage>>>,
    /// Seen tags for replay detection
    seen_tags: Arc<RwLock<HashMap<[u8; 16], u64>>>,
    /// Statistics
    stats: Arc<RwLock<ProcessorStats>>,
}

/// Processing statistics
#[derive(Clone, Debug, Default)]
pub struct ProcessorStats {
    pub packets_received: u64,
    pub packets_forwarded: u64,
    pub packets_delivered: u64,
    pub replay_attempts: u64,
    pub invalid_packets: u64,
    pub cover_traffic_sent: u64,
}

impl MixNodeProcessor {
    /// Create a new processor
    pub fn new(node_id: [u8; 32], private_key: [u8; 32], config: MixNodeConfig) -> Self {
        Self {
            node_id,
            private_key,
            config,
            pending: Arc::new(Mutex::new(VecDeque::new())),
            seen_tags: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(ProcessorStats::default())),
        }
    }

    /// Process an incoming packet
    pub async fn process_packet(&self, packet: SphinxPacket) -> MixnetResult<ProcessingResult> {
        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.packets_received += 1;
        }

        // Check for replay attack
        if self.config.replay_detection {
            let seen = self.seen_tags.read().await;
            if seen.contains_key(&packet.tag) {
                let mut stats = self.stats.write().await;
                stats.replay_attempts += 1;
                return Err(MixnetError::ReplayDetected);
            }
        }

        // Process the packet
        let result = packet.process(&self.private_key)?;

        // Record tag for replay detection
        if self.config.replay_detection {
            let now = now_millis();
            let mut seen = self.seen_tags.write().await;
            seen.insert(packet.tag, now);
        }

        match result {
            ProcessedPacket::Forward { next_hop, delay_ms, packet } => {
                // Calculate release time with added random delay
                let additional_delay = random_delay(self.config.max_delay_ms);
                let release_at = now_millis() + delay_ms as u64 + additional_delay;

                let pending_msg = PendingMessage {
                    packet,
                    destination: next_hop,
                    release_at,
                    is_cover: false,
                };

                {
                    let mut queue = self.pending.lock().await;
                    queue.push_back(pending_msg);
                }

                Ok(ProcessingResult::Queued { next_hop })
            }
            ProcessedPacket::Final { destination, payload } => {
                let mut stats = self.stats.write().await;
                stats.packets_delivered += 1;

                Ok(ProcessingResult::Delivered { destination, payload })
            }
        }
    }

    /// Get messages ready to be sent (called periodically)
    pub async fn get_ready_messages(&self) -> Vec<(SphinxPacket, [u8; 32])> {
        let now = now_millis();
        let mut ready = Vec::new();

        let mut queue = self.pending.lock().await;

        // Collect ready messages
        while let Some(msg) = queue.front() {
            if msg.release_at <= now {
                let msg = queue.pop_front().unwrap();
                ready.push((msg.packet, msg.destination));
            } else {
                break;
            }
        }

        // Sort by release time for better batching
        queue.make_contiguous().sort_by_key(|m| m.release_at);

        // Update stats
        if !ready.is_empty() {
            let mut stats = self.stats.write().await;
            stats.packets_forwarded += ready.len() as u64;
        }

        // Shuffle ready messages for anonymity
        shuffle_messages(&mut ready);

        ready
    }

    /// Generate cover traffic
    pub async fn generate_cover_traffic(&self, destinations: &[MixNodeInfo]) -> Option<SphinxPacket> {
        if destinations.is_empty() {
            return None;
        }

        // Create dummy payload
        let mut payload = vec![0u8; 256];
        let _ = getrandom::getrandom(&mut payload);

        // Select random route
        let route: Vec<MixNodeInfo> = destinations.iter()
            .take(3)
            .cloned()
            .collect();

        if route.is_empty() {
            return None;
        }

        let mut destination = [0u8; 32];
        let _ = getrandom::getrandom(&mut destination);

        match SphinxPacket::create(&payload, &route, &destination) {
            Ok(packet) => {
                let mut stats = self.stats.write().await;
                stats.cover_traffic_sent += 1;
                Some(packet)
            }
            Err(_) => None,
        }
    }

    /// Clean up expired replay tags
    pub async fn cleanup_tags(&self) {
        let now = now_millis();
        let ttl_ms = self.config.tag_cache_ttl_secs * 1000;

        let mut seen = self.seen_tags.write().await;
        seen.retain(|_, &mut timestamp| now - timestamp < ttl_ms);
    }

    /// Get current statistics
    pub async fn stats(&self) -> ProcessorStats {
        self.stats.read().await.clone()
    }

    /// Get pending message count
    pub async fn pending_count(&self) -> usize {
        self.pending.lock().await.len()
    }
}

/// Result of packet processing
#[derive(Clone, Debug)]
pub enum ProcessingResult {
    /// Message queued for forwarding
    Queued { next_hop: [u8; 32] },
    /// Message delivered to final destination
    Delivered { destination: [u8; 32], payload: Vec<u8> },
}

/// Network directory of mix nodes
#[derive(Clone, Debug, Default)]
pub struct MixDirectory {
    /// All known nodes by ID
    nodes: HashMap<[u8; 32], MixNode>,
    /// Nodes organized by layer
    layers: Vec<Vec<[u8; 32]>>,
    /// Number of layers
    num_layers: usize,
}

impl MixDirectory {
    /// Create a new directory with specified layers
    pub fn new(num_layers: usize) -> Self {
        Self {
            nodes: HashMap::new(),
            layers: vec![Vec::new(); num_layers],
            num_layers,
        }
    }

    /// Add a node to the directory
    pub fn add_node(&mut self, node: MixNode) {
        let layer = node.layer as usize;
        if layer < self.num_layers {
            self.layers[layer].push(node.id);
        }
        self.nodes.insert(node.id, node);
    }

    /// Remove a node from the directory
    pub fn remove_node(&mut self, id: &[u8; 32]) -> Option<MixNode> {
        if let Some(node) = self.nodes.remove(id) {
            let layer = node.layer as usize;
            if layer < self.layers.len() {
                self.layers[layer].retain(|&n| &n != id);
            }
            Some(node)
        } else {
            None
        }
    }

    /// Get a node by ID
    pub fn get(&self, id: &[u8; 32]) -> Option<&MixNode> {
        self.nodes.get(id)
    }

    /// Get all nodes in a layer
    pub fn get_layer(&self, layer: usize) -> Vec<&MixNode> {
        if layer >= self.layers.len() {
            return Vec::new();
        }

        self.layers[layer]
            .iter()
            .filter_map(|id| self.nodes.get(id))
            .filter(|n| n.online)
            .collect()
    }

    /// Get online nodes
    pub fn online_nodes(&self) -> Vec<&MixNode> {
        self.nodes.values().filter(|n| n.online).collect()
    }

    /// Get number of layers
    pub fn num_layers(&self) -> usize {
        self.num_layers
    }

    /// Select a random route through the mixnet
    pub fn select_route(&self, num_hops: usize) -> MixnetResult<Vec<MixNodeInfo>> {
        if num_hops == 0 {
            return Err(MixnetError::InvalidRouting("Zero hops requested".into()));
        }

        let mut route = Vec::with_capacity(num_hops);

        // If we have layers, select one node from each layer
        if self.num_layers > 0 {
            let hops_per_layer = (num_hops + self.num_layers - 1) / self.num_layers;

            for layer in 0..self.num_layers {
                let layer_nodes = self.get_layer(layer);
                if layer_nodes.is_empty() {
                    continue;
                }

                // Select random nodes from this layer (weighted by reputation)
                let selected = weighted_select(&layer_nodes, hops_per_layer.min(num_hops - route.len()));
                for node in selected {
                    route.push(node.to_info());
                    if route.len() >= num_hops {
                        break;
                    }
                }
            }
        } else {
            // No layer structure - random selection
            let online: Vec<_> = self.online_nodes();
            if online.len() < num_hops {
                return Err(MixnetError::NoRoute);
            }

            let selected = weighted_select(&online, num_hops);
            for node in selected {
                route.push(node.to_info());
            }
        }

        if route.is_empty() {
            return Err(MixnetError::NoRoute);
        }

        Ok(route)
    }

    /// Update node status
    pub fn set_online(&mut self, id: &[u8; 32], online: bool) {
        if let Some(node) = self.nodes.get_mut(id) {
            node.online = online;
        }
    }

    /// Get total node count
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Get online node count
    pub fn online_count(&self) -> usize {
        self.nodes.values().filter(|n| n.online).count()
    }
}

// Helper functions

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn random_delay(max_ms: u64) -> u64 {
    let mut bytes = [0u8; 8];
    let _ = getrandom::getrandom(&mut bytes);
    u64::from_le_bytes(bytes) % max_ms
}

fn shuffle_messages(messages: &mut Vec<(SphinxPacket, [u8; 32])>) {
    // Fisher-Yates shuffle
    for i in (1..messages.len()).rev() {
        let mut bytes = [0u8; 8];
        let _ = getrandom::getrandom(&mut bytes);
        let j = (u64::from_le_bytes(bytes) as usize) % (i + 1);
        messages.swap(i, j);
    }
}

fn weighted_select<'a>(nodes: &[&'a MixNode], count: usize) -> Vec<&'a MixNode> {
    if nodes.is_empty() || count == 0 {
        return Vec::new();
    }

    let total_weight: f64 = nodes.iter().map(|n| n.reputation).sum();
    if total_weight <= 0.0 {
        // Fallback to uniform selection
        return nodes.iter().take(count).cloned().collect();
    }

    let mut selected = Vec::with_capacity(count);
    let mut used = vec![false; nodes.len()];

    for _ in 0..count {
        // Recompute available weight for remaining nodes
        let available_weight: f64 = nodes.iter()
            .enumerate()
            .filter(|(i, _)| !used[*i])
            .map(|(_, n)| n.reputation)
            .sum();

        if available_weight <= 0.0 {
            break;
        }

        let mut bytes = [0u8; 8];
        let _ = getrandom::getrandom(&mut bytes);
        let rand = (u64::from_le_bytes(bytes) as f64) / (u64::MAX as f64) * available_weight;

        let mut cumulative = 0.0;
        for (i, node) in nodes.iter().enumerate() {
            if used[i] {
                continue;
            }
            cumulative += node.reputation;
            if rand < cumulative {
                selected.push(*node);
                used[i] = true;
                break;
            }
        }

        if selected.len() >= count {
            break;
        }
    }

    selected
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_node(id: u8, layer: u8) -> MixNode {
        let mut node_id = [0u8; 32];
        node_id[0] = id;
        let mut public_key = [0u8; 32];
        public_key[0] = id;

        MixNode::new(
            node_id,
            public_key,
            format!("127.0.0.1:{}", 10000 + id as u16),
            layer,
        )
    }

    #[test]
    fn test_mix_node_creation() {
        let node = create_test_node(1, 0);
        assert!(node.online);
        assert_eq!(node.reputation, 100.0);
        assert_eq!(node.layer, 0);
    }

    #[test]
    fn test_directory_routing() {
        let mut dir = MixDirectory::new(3);

        // Add nodes to each layer
        for layer in 0..3 {
            for i in 0..5 {
                dir.add_node(create_test_node(layer * 10 + i, layer));
            }
        }

        assert_eq!(dir.node_count(), 15);

        let route = dir.select_route(5).unwrap();
        assert_eq!(route.len(), 5);
    }

    #[test]
    fn test_node_reputation() {
        let mut node = create_test_node(1, 0);
        assert_eq!(node.reputation, 100.0);

        node.update_reputation(false);
        assert!(node.reputation < 100.0);

        node.update_reputation(true);
        // Should recover slightly
    }

    #[tokio::test]
    async fn test_processor_stats() {
        let config = MixNodeConfig::default();
        let processor = MixNodeProcessor::new([1u8; 32], [2u8; 32], config);

        let stats = processor.stats().await;
        assert_eq!(stats.packets_received, 0);
        assert_eq!(stats.packets_forwarded, 0);
    }
}
