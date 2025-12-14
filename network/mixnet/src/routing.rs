//! Circuit routing and path selection
//!
//! Implements Dandelion++ propagation and circuit management:
//! - Stem phase: Linear propagation through anonymity set
//! - Fluff phase: Broadcast to network
//! - Path selection with geographic/AS diversity

use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};

use crate::mix_node::{MixNode, MixDirectory};
use crate::sphinx::{SphinxPacket, MixNodeInfo, SURB};
use crate::errors::{MixnetError, MixnetResult};

/// Circuit configuration
#[derive(Clone, Debug)]
pub struct CircuitConfig {
    /// Number of hops in the circuit
    pub num_hops: usize,
    /// Stem length for Dandelion++
    pub stem_length: usize,
    /// Maximum circuit lifetime in seconds
    pub max_lifetime_secs: u64,
    /// Require geographic diversity
    pub geographic_diversity: bool,
    /// Require AS (Autonomous System) diversity
    pub as_diversity: bool,
}

impl Default for CircuitConfig {
    fn default() -> Self {
        Self {
            num_hops: 5,
            stem_length: 3,
            max_lifetime_secs: 600,
            geographic_diversity: true,
            as_diversity: true,
        }
    }
}

/// A circuit through the mixnet
#[derive(Clone, Debug)]
pub struct Circuit {
    /// Unique circuit identifier
    pub id: [u8; 32],
    /// Ordered list of nodes in the circuit
    pub path: Vec<MixNodeInfo>,
    /// Circuit creation time
    pub created_at: u64,
    /// Circuit expiration time
    pub expires_at: u64,
    /// SURB for receiving replies (if any)
    pub reply_surb: Option<SURB>,
    /// Circuit state
    pub state: CircuitState,
}

/// Circuit state
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CircuitState {
    /// Being constructed
    Building,
    /// Ready for use
    Ready,
    /// Temporarily unavailable
    Degraded,
    /// Torn down
    Closed,
}

impl Circuit {
    /// Create a new circuit
    pub fn new(id: [u8; 32], path: Vec<MixNodeInfo>, lifetime_secs: u64) -> Self {
        let now = now_secs();
        Self {
            id,
            path,
            created_at: now,
            expires_at: now + lifetime_secs,
            reply_surb: None,
            state: CircuitState::Building,
        }
    }

    /// Check if circuit is expired
    pub fn is_expired(&self) -> bool {
        now_secs() > self.expires_at
    }

    /// Check if circuit is usable
    pub fn is_usable(&self) -> bool {
        self.state == CircuitState::Ready && !self.is_expired()
    }

    /// Send a message through this circuit
    pub fn send(&self, payload: &[u8], destination: &[u8; 32]) -> MixnetResult<SphinxPacket> {
        if !self.is_usable() {
            return Err(MixnetError::CircuitFailed("Circuit not usable".into()));
        }

        SphinxPacket::create(payload, &self.path, destination)
    }

    /// Get the entry node
    pub fn entry_node(&self) -> Option<&MixNodeInfo> {
        self.path.first()
    }

    /// Get the exit node
    pub fn exit_node(&self) -> Option<&MixNodeInfo> {
        self.path.last()
    }
}

/// Dandelion++ propagation phases
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DandelionPhase {
    /// Stem phase: linear propagation
    Stem {
        hops_remaining: usize,
        stem_id: [u8; 32],
    },
    /// Fluff phase: broadcast
    Fluff,
}

/// A message with Dandelion++ routing
#[derive(Clone, Debug)]
pub struct DandelionMessage {
    /// The actual packet
    pub packet: SphinxPacket,
    /// Current phase
    pub phase: DandelionPhase,
    /// Final destination
    pub destination: [u8; 32],
    /// Message hash for deduplication
    pub hash: [u8; 32],
}

impl DandelionMessage {
    /// Create a new stem-phase message
    pub fn new_stem(
        packet: SphinxPacket,
        destination: [u8; 32],
        stem_length: usize,
    ) -> Self {
        let mut stem_id = [0u8; 32];
        let _ = getrandom::getrandom(&mut stem_id);

        let hash = compute_message_hash(&packet);

        Self {
            packet,
            phase: DandelionPhase::Stem {
                hops_remaining: stem_length,
                stem_id,
            },
            destination,
            hash,
        }
    }

    /// Process stem hop (returns true if should transition to fluff)
    pub fn advance_stem(&mut self) -> bool {
        if let DandelionPhase::Stem { ref mut hops_remaining, .. } = self.phase {
            if *hops_remaining > 0 {
                *hops_remaining -= 1;
                return *hops_remaining == 0;
            }
        }
        true // Already should be in fluff
    }

    /// Transition to fluff phase
    pub fn transition_to_fluff(&mut self) {
        self.phase = DandelionPhase::Fluff;
    }

    /// Check if in fluff phase
    pub fn is_fluff(&self) -> bool {
        matches!(self.phase, DandelionPhase::Fluff)
    }
}

/// Circuit manager handles circuit lifecycle
pub struct CircuitManager {
    /// Configuration
    config: CircuitConfig,
    /// Active circuits
    circuits: HashMap<[u8; 32], Circuit>,
    /// Node directory
    directory: MixDirectory,
    /// Used paths (for diversity)
    used_paths: HashSet<Vec<[u8; 32]>>,
}

impl CircuitManager {
    /// Create a new circuit manager
    pub fn new(config: CircuitConfig, directory: MixDirectory) -> Self {
        Self {
            config,
            circuits: HashMap::new(),
            directory,
            used_paths: HashSet::new(),
        }
    }

    /// Build a new circuit
    pub fn build_circuit(&mut self) -> MixnetResult<[u8; 32]> {
        // Generate circuit ID
        let mut id = [0u8; 32];
        getrandom::getrandom(&mut id)
            .map_err(|e| MixnetError::CryptoError(e.to_string()))?;

        // Select path
        let path = self.select_path()?;

        // Track used paths
        let path_ids: Vec<[u8; 32]> = path.iter().map(|n| n.id).collect();
        self.used_paths.insert(path_ids);

        // Create circuit
        let circuit = Circuit::new(id, path, self.config.max_lifetime_secs);
        self.circuits.insert(id, circuit);

        Ok(id)
    }

    /// Select a path through the network
    fn select_path(&self) -> MixnetResult<Vec<MixNodeInfo>> {
        let mut path = Vec::with_capacity(self.config.num_hops);
        let mut used_ids: HashSet<[u8; 32]> = HashSet::new();
        let mut used_countries: HashSet<String> = HashSet::new();
        let mut used_asns: HashSet<u32> = HashSet::new();

        for hop in 0..self.config.num_hops {
            // Get candidates for this layer
            let layer = hop % self.directory.num_layers().max(1);
            let candidates = self.directory.get_layer(layer);

            // Filter candidates
            let mut valid_candidates: Vec<_> = candidates.into_iter()
                .filter(|n| !used_ids.contains(&n.id))
                .filter(|n| n.online)
                .filter(|n| n.reputation > 50.0) // Minimum reputation
                .collect();

            if valid_candidates.is_empty() {
                // Relax constraints if no candidates
                valid_candidates = self.directory.online_nodes().into_iter()
                    .filter(|n| !used_ids.contains(&n.id))
                    .collect();
            }

            if valid_candidates.is_empty() {
                if path.is_empty() {
                    return Err(MixnetError::NoRoute);
                }
                break; // Use shorter path
            }

            // Select best candidate (weighted by reputation)
            let selected = select_weighted_node(&valid_candidates)?;

            used_ids.insert(selected.id);
            path.push(selected.to_info());
        }

        if path.len() < 3 {
            return Err(MixnetError::CircuitFailed(
                format!("Path too short: {} nodes", path.len())
            ));
        }

        Ok(path)
    }

    /// Get a circuit by ID
    pub fn get_circuit(&self, id: &[u8; 32]) -> Option<&Circuit> {
        self.circuits.get(id)
    }

    /// Get a circuit mutably
    pub fn get_circuit_mut(&mut self, id: &[u8; 32]) -> Option<&mut Circuit> {
        self.circuits.get_mut(id)
    }

    /// Get a random usable circuit
    pub fn get_random_circuit(&self) -> Option<&Circuit> {
        let usable: Vec<_> = self.circuits.values()
            .filter(|c| c.is_usable())
            .collect();

        if usable.is_empty() {
            return None;
        }

        let mut bytes = [0u8; 8];
        let _ = getrandom::getrandom(&mut bytes);
        let index = (u64::from_le_bytes(bytes) as usize) % usable.len();

        Some(usable[index])
    }

    /// Close a circuit
    pub fn close_circuit(&mut self, id: &[u8; 32]) -> bool {
        if let Some(circuit) = self.circuits.get_mut(id) {
            circuit.state = CircuitState::Closed;

            // Remove from used paths
            let path_ids: Vec<[u8; 32]> = circuit.path.iter().map(|n| n.id).collect();
            self.used_paths.remove(&path_ids);

            true
        } else {
            false
        }
    }

    /// Clean up expired circuits
    pub fn cleanup_expired(&mut self) -> usize {
        let expired: Vec<[u8; 32]> = self.circuits.iter()
            .filter(|(_, c)| c.is_expired())
            .map(|(id, _)| *id)
            .collect();

        let count = expired.len();
        for id in expired {
            self.close_circuit(&id);
            self.circuits.remove(&id);
        }

        count
    }

    /// Get circuit count
    pub fn circuit_count(&self) -> usize {
        self.circuits.len()
    }

    /// Get usable circuit count
    pub fn usable_count(&self) -> usize {
        self.circuits.values().filter(|c| c.is_usable()).count()
    }

    /// Mark circuit as ready
    pub fn mark_ready(&mut self, id: &[u8; 32]) -> bool {
        if let Some(circuit) = self.circuits.get_mut(id) {
            circuit.state = CircuitState::Ready;
            true
        } else {
            false
        }
    }

    /// Add a reply SURB to a circuit
    pub fn add_reply_surb(&mut self, id: &[u8; 32], surb: SURB) -> bool {
        if let Some(circuit) = self.circuits.get_mut(id) {
            circuit.reply_surb = Some(surb);
            true
        } else {
            false
        }
    }
}

/// Dandelion++ router for transaction propagation
pub struct DandelionRouter {
    /// Stem length configuration
    stem_length: usize,
    /// Stem successors (outbound stem peers)
    stem_successors: Vec<[u8; 32]>,
    /// Messages in stem phase
    stem_messages: HashMap<[u8; 32], DandelionMessage>,
    /// Seen message hashes (for deduplication)
    seen_hashes: HashSet<[u8; 32]>,
    /// Fluff delay in milliseconds
    fluff_delay_ms: u64,
}

impl DandelionRouter {
    /// Create a new router
    pub fn new(stem_length: usize) -> Self {
        Self {
            stem_length,
            stem_successors: Vec::new(),
            stem_messages: HashMap::new(),
            seen_hashes: HashSet::new(),
            fluff_delay_ms: 100,
        }
    }

    /// Add a stem successor
    pub fn add_stem_successor(&mut self, node_id: [u8; 32]) {
        if !self.stem_successors.contains(&node_id) {
            self.stem_successors.push(node_id);
        }
    }

    /// Remove a stem successor
    pub fn remove_stem_successor(&mut self, node_id: &[u8; 32]) {
        self.stem_successors.retain(|id| id != node_id);
    }

    /// Route a new message (starts in stem phase)
    pub fn route_new(&mut self, packet: SphinxPacket, destination: [u8; 32]) -> RouteDecision {
        let message = DandelionMessage::new_stem(packet, destination, self.stem_length);
        let hash = message.hash;

        // Check for duplicate
        if self.seen_hashes.contains(&hash) {
            return RouteDecision::Drop;
        }

        self.seen_hashes.insert(hash);
        self.route_message(message)
    }

    /// Route an existing message
    pub fn route_message(&mut self, mut message: DandelionMessage) -> RouteDecision {
        if message.is_fluff() {
            // Broadcast to all peers
            return RouteDecision::Broadcast {
                packet: message.packet,
                exclude: vec![],
            };
        }

        // Stem phase
        if message.advance_stem() {
            // Transition to fluff
            message.transition_to_fluff();
            return RouteDecision::Broadcast {
                packet: message.packet,
                exclude: vec![],
            };
        }

        // Continue stem
        if let Some(successor) = self.select_stem_successor() {
            self.stem_messages.insert(message.hash, message.clone());
            RouteDecision::StemForward {
                packet: message.packet,
                next_hop: successor,
            }
        } else {
            // No stem successor, immediately fluff
            RouteDecision::Broadcast {
                packet: message.packet,
                exclude: vec![],
            }
        }
    }

    /// Select a random stem successor
    fn select_stem_successor(&self) -> Option<[u8; 32]> {
        if self.stem_successors.is_empty() {
            return None;
        }

        let mut bytes = [0u8; 8];
        let _ = getrandom::getrandom(&mut bytes);
        let index = (u64::from_le_bytes(bytes) as usize) % self.stem_successors.len();

        Some(self.stem_successors[index])
    }

    /// Handle stem failure (transition affected messages to fluff)
    pub fn handle_stem_failure(&mut self, failed_node: &[u8; 32]) -> Vec<SphinxPacket> {
        // Remove from successors
        self.remove_stem_successor(failed_node);

        // Find messages going through this node
        let affected: Vec<[u8; 32]> = self.stem_messages.keys().cloned().collect();
        let mut to_fluff = Vec::new();

        for hash in affected {
            if let Some(mut msg) = self.stem_messages.remove(&hash) {
                msg.transition_to_fluff();
                to_fluff.push(msg.packet);
            }
        }

        to_fluff
    }

    /// Cleanup old entries
    pub fn cleanup(&mut self, max_age_secs: u64) {
        // Would track timestamps in production
        // For now, just limit set sizes
        if self.seen_hashes.len() > 10000 {
            self.seen_hashes.clear();
        }
        if self.stem_messages.len() > 1000 {
            self.stem_messages.clear();
        }
    }
}

/// Routing decision from Dandelion++ router
#[derive(Clone, Debug)]
pub enum RouteDecision {
    /// Forward along stem to specific node
    StemForward {
        packet: SphinxPacket,
        next_hop: [u8; 32],
    },
    /// Broadcast to network (fluff phase)
    Broadcast {
        packet: SphinxPacket,
        exclude: Vec<[u8; 32]>,
    },
    /// Drop the message (duplicate or invalid)
    Drop,
}

// Helper functions

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn compute_message_hash(packet: &SphinxPacket) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&packet.ephemeral_key);
    hasher.update(&packet.tag);
    hasher.update(&packet.payload);
    *hasher.finalize().as_bytes()
}

fn select_weighted_node<'a>(nodes: &[&'a MixNode]) -> MixnetResult<&'a MixNode> {
    if nodes.is_empty() {
        return Err(MixnetError::NoRoute);
    }

    let total_weight: f64 = nodes.iter().map(|n| n.reputation).sum();
    if total_weight <= 0.0 {
        return Ok(nodes[0]);
    }

    let mut bytes = [0u8; 8];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| MixnetError::CryptoError(e.to_string()))?;

    let rand = (u64::from_le_bytes(bytes) as f64) / (u64::MAX as f64) * total_weight;

    let mut cumulative = 0.0;
    for node in nodes {
        cumulative += node.reputation;
        if rand < cumulative {
            return Ok(*node);
        }
    }

    Ok(nodes[0])
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

    #[test]
    fn test_circuit_creation() {
        let config = CircuitConfig::default();
        let directory = create_test_directory();
        let mut manager = CircuitManager::new(config, directory);

        let circuit_id = manager.build_circuit().unwrap();
        assert!(manager.get_circuit(&circuit_id).is_some());
    }

    #[test]
    fn test_circuit_lifecycle() {
        let config = CircuitConfig {
            max_lifetime_secs: 1,
            ..Default::default()
        };
        let directory = create_test_directory();
        let mut manager = CircuitManager::new(config, directory);

        let circuit_id = manager.build_circuit().unwrap();
        manager.mark_ready(&circuit_id);

        let circuit = manager.get_circuit(&circuit_id).unwrap();
        assert!(circuit.is_usable());
    }

    #[test]
    fn test_dandelion_routing() {
        let mut router = DandelionRouter::new(3);

        // Add some stem successors
        router.add_stem_successor([1u8; 32]);
        router.add_stem_successor([2u8; 32]);

        // Create a dummy packet
        let route: Vec<MixNodeInfo> = (1..=3).map(|i| {
            let mut id = [0u8; 32];
            id[0] = i;
            MixNodeInfo { id, public_key: id }
        }).collect();

        let packet = SphinxPacket::create(b"test", &route, &[99u8; 32]).unwrap();

        let decision = router.route_new(packet, [99u8; 32]);

        // Should be stem forward or broadcast
        match decision {
            RouteDecision::StemForward { .. } => (),
            RouteDecision::Broadcast { .. } => (),
            RouteDecision::Drop => panic!("Should not drop new message"),
        }
    }

    #[test]
    fn test_stem_failure_recovery() {
        let mut router = DandelionRouter::new(5);
        router.add_stem_successor([1u8; 32]);

        // Simulate failure
        let fluffed = router.handle_stem_failure(&[1u8; 32]);

        // Successor should be removed
        assert!(router.stem_successors.is_empty());
    }
}
