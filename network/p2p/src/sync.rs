//! Encrypted State Synchronization Protocol
//!
//! Provides secure state synchronization over the P2P network while
//! preserving privacy of encrypted state fragments.
//!
//! # Features
//! - Full state sync for new nodes
//! - Incremental sync for catching up
//! - Merkle proof verification
//! - Encrypted fragment transfer
//! - Snapshot-based checkpoints

use crate::errors::{P2PError, P2PResult};
use crate::messages::{NetworkMessage, StateUpdateMessage, StateFragmentType, Attestation};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Unique identifier for a sync session
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SyncSessionId([u8; 32]);

impl SyncSessionId {
    /// Create a new random session ID
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
        Self(bytes)
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the underlying bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// State sync request types
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SyncRequest {
    /// Request current state snapshot (lightweight)
    GetSnapshot,
    /// Request specific fragment by ID
    GetFragment {
        fragment_id: [u8; 32],
    },
    /// Request fragments in an epoch range
    GetFragmentsByEpoch {
        start_epoch: u64,
        end_epoch: u64,
        max_count: u32,
    },
    /// Request commitment tree proof
    GetCommitmentProof {
        commitment: [u8; 32],
    },
    /// Request nullifier existence proof
    GetNullifierProof {
        nullifier: [u8; 32],
    },
    /// Request state updates since epoch
    GetUpdatesSince {
        epoch: u64,
        max_count: u32,
    },
    /// Request full state sync (for new nodes)
    InitiateFullSync {
        session_id: SyncSessionId,
    },
    /// Request next batch in full sync
    GetSyncBatch {
        session_id: SyncSessionId,
        batch_index: u64,
    },
}

/// State sync response types
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SyncResponse {
    /// State snapshot response
    Snapshot(StateSnapshot),
    /// Single fragment response
    Fragment(Option<EncryptedFragment>),
    /// Multiple fragments response
    Fragments {
        fragments: Vec<EncryptedFragment>,
        has_more: bool,
        next_epoch: Option<u64>,
    },
    /// Commitment proof response
    CommitmentProof {
        exists: bool,
        proof: Option<MerkleProof>,
    },
    /// Nullifier proof response
    NullifierProof {
        exists: bool,
        proof: Option<MerkleProof>,
    },
    /// State updates response
    Updates {
        updates: Vec<StateUpdateMessage>,
        has_more: bool,
    },
    /// Full sync initiated
    SyncInitiated {
        session_id: SyncSessionId,
        total_batches: u64,
        estimated_fragments: u64,
    },
    /// Sync batch response
    SyncBatch {
        session_id: SyncSessionId,
        batch_index: u64,
        fragments: Vec<EncryptedFragment>,
        is_last: bool,
    },
    /// Error response
    Error {
        code: SyncErrorCode,
        message: String,
    },
}

/// Sync error codes
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SyncErrorCode {
    /// Fragment not found
    FragmentNotFound,
    /// Invalid epoch range
    InvalidEpochRange,
    /// Session not found
    SessionNotFound,
    /// Too many requests (rate limited)
    RateLimited,
    /// Internal error
    InternalError,
    /// Peer is syncing (can't serve requests)
    PeerSyncing,
}

/// Lightweight state snapshot
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateSnapshot {
    /// State root hash
    pub state_root: [u8; 32],
    /// Commitment tree root
    pub commitment_root: [u8; 32],
    /// Nullifier tree root
    pub nullifier_root: [u8; 32],
    /// Current epoch
    pub epoch: u64,
    /// Total commitments
    pub num_commitments: u64,
    /// Total nullifiers
    pub num_nullifiers: u64,
    /// Snapshot timestamp
    pub timestamp: u64,
    /// Attestations from validators
    pub attestations: Vec<Attestation>,
}

impl StateSnapshot {
    /// Compute snapshot hash for verification
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"phantom_snapshot");
        hasher.update(&self.state_root);
        hasher.update(&self.commitment_root);
        hasher.update(&self.nullifier_root);
        hasher.update(&self.epoch.to_le_bytes());
        hasher.update(&self.num_commitments.to_le_bytes());
        hasher.update(&self.num_nullifiers.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Verify the snapshot has sufficient attestations
    pub fn verify_attestations(&self, threshold: usize) -> bool {
        self.attestations.len() >= threshold
    }
}

/// An encrypted state fragment for network transfer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedFragment {
    /// Fragment unique identifier
    pub id: [u8; 32],
    /// Fragment type
    pub fragment_type: StateFragmentType,
    /// Encrypted balance data (FHE ciphertext)
    pub encrypted_data: Vec<u8>,
    /// Commitment to the plaintext state
    pub commitment: [u8; 32],
    /// Owner's public key hash (stealth address)
    pub owner_hash: [u8; 32],
    /// Fragment epoch
    pub epoch: u64,
    /// Merkle proof of inclusion in commitment tree
    pub merkle_proof: Option<MerkleProof>,
    /// Witness attestation signatures
    pub attestations: Vec<Attestation>,
}

impl EncryptedFragment {
    /// Compute fragment hash
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"phantom_fragment");
        hasher.update(&self.id);
        hasher.update(&self.commitment);
        hasher.update(&self.owner_hash);
        hasher.update(&self.epoch.to_le_bytes());
        hasher.update(&self.encrypted_data);
        *hasher.finalize().as_bytes()
    }

    /// Verify the fragment has valid structure
    pub fn verify_structure(&self) -> P2PResult<()> {
        if self.commitment == [0u8; 32] {
            return Err(P2PError::MessageError("Zero commitment".into()));
        }
        if self.owner_hash == [0u8; 32] {
            return Err(P2PError::MessageError("Zero owner hash".into()));
        }
        if self.encrypted_data.is_empty() {
            return Err(P2PError::MessageError("Empty encrypted data".into()));
        }
        Ok(())
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> P2PResult<Self> {
        bincode::deserialize(bytes)
            .map_err(|e| P2PError::MessageError(e.to_string()))
    }
}

/// Merkle proof for state verification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Path from leaf to root
    pub path: Vec<MerkleNode>,
    /// Leaf index
    pub leaf_index: u64,
    /// Leaf hash
    pub leaf_hash: [u8; 32],
    /// Root hash (for verification)
    pub root: [u8; 32],
}

/// Node in a Merkle proof path
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleNode {
    /// Hash of the sibling node
    pub hash: [u8; 32],
    /// Position (left or right)
    pub position: MerklePosition,
}

/// Position of sibling in Merkle tree
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MerklePosition {
    Left,
    Right,
}

impl MerkleProof {
    /// Verify the proof against an expected root
    pub fn verify(&self) -> bool {
        let mut current_hash = self.leaf_hash;

        for node in &self.path {
            let mut hasher = blake3::Hasher::new();
            match node.position {
                MerklePosition::Left => {
                    hasher.update(&node.hash);
                    hasher.update(&current_hash);
                }
                MerklePosition::Right => {
                    hasher.update(&current_hash);
                    hasher.update(&node.hash);
                }
            }
            current_hash = *hasher.finalize().as_bytes();
        }

        current_hash == self.root
    }
}

/// State sync session for tracking full sync progress
#[derive(Clone, Debug)]
pub struct SyncSession {
    /// Session identifier
    pub id: SyncSessionId,
    /// Peer we're syncing with
    pub peer_id: PeerId,
    /// Target state snapshot
    pub target_snapshot: StateSnapshot,
    /// Current batch index
    pub current_batch: u64,
    /// Total batches expected
    pub total_batches: u64,
    /// Fragments received so far
    pub fragments_received: u64,
    /// Session start time
    pub started_at: u64,
    /// Last activity timestamp
    pub last_activity: u64,
    /// Session state
    pub state: SyncSessionState,
}

/// State of a sync session
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncSessionState {
    /// Waiting for initiation response
    Initiating,
    /// Actively receiving batches
    InProgress,
    /// Verifying received data
    Verifying,
    /// Sync completed successfully
    Completed,
    /// Sync failed
    Failed(String),
}

/// Configuration for state sync
#[derive(Clone, Debug)]
pub struct SyncConfig {
    /// Maximum fragments per batch
    pub batch_size: u32,
    /// Maximum concurrent sync sessions
    pub max_sessions: usize,
    /// Session timeout in seconds
    pub session_timeout: u64,
    /// Minimum attestations required for verification
    pub min_attestations: usize,
    /// Rate limit: max requests per minute per peer
    pub rate_limit_rpm: u32,
    /// Enable parallel fragment fetching
    pub parallel_fetch: bool,
    /// Number of parallel fetch workers
    pub parallel_workers: usize,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            batch_size: 100,
            max_sessions: 4,
            session_timeout: 300, // 5 minutes
            min_attestations: 3,
            rate_limit_rpm: 60,
            parallel_fetch: true,
            parallel_workers: 4,
        }
    }
}

/// State synchronization manager
pub struct StateSyncManager {
    /// Configuration
    config: SyncConfig,
    /// Active sync sessions (as receiver)
    incoming_sessions: Arc<RwLock<HashMap<SyncSessionId, SyncSession>>>,
    /// Active sync sessions (as requester)
    outgoing_sessions: Arc<RwLock<HashMap<SyncSessionId, SyncSession>>>,
    /// Pending requests awaiting response (for future request tracking)
    #[allow(dead_code)]
    pending_requests: Arc<RwLock<HashMap<u64, PendingRequest>>>,
    /// Request counter for IDs (for future request tracking)
    #[allow(dead_code)]
    request_counter: Arc<RwLock<u64>>,
    /// Rate limiting: peer -> (timestamp, count)
    rate_limits: Arc<RwLock<HashMap<PeerId, (u64, u32)>>>,
    /// Local state snapshot (for serving requests)
    local_snapshot: Arc<RwLock<Option<StateSnapshot>>>,
    /// Local fragments index
    local_fragments: Arc<RwLock<HashMap<[u8; 32], EncryptedFragment>>>,
    /// Fragments pending verification
    pending_fragments: Arc<RwLock<VecDeque<EncryptedFragment>>>,
    /// Known valid fragment IDs
    verified_fragments: Arc<RwLock<HashSet<[u8; 32]>>>,
}

/// A pending request awaiting response
#[derive(Clone, Debug)]
pub struct PendingRequest {
    /// Request ID
    pub id: u64,
    /// Target peer
    pub peer_id: PeerId,
    /// Request type
    pub request: SyncRequest,
    /// Timestamp when sent
    pub sent_at: u64,
    /// Session ID if part of a sync
    pub session_id: Option<SyncSessionId>,
}

impl StateSyncManager {
    /// Create a new state sync manager
    pub fn new(config: SyncConfig) -> Self {
        Self {
            config,
            incoming_sessions: Arc::new(RwLock::new(HashMap::new())),
            outgoing_sessions: Arc::new(RwLock::new(HashMap::new())),
            pending_requests: Arc::new(RwLock::new(HashMap::new())),
            request_counter: Arc::new(RwLock::new(0)),
            rate_limits: Arc::new(RwLock::new(HashMap::new())),
            local_snapshot: Arc::new(RwLock::new(None)),
            local_fragments: Arc::new(RwLock::new(HashMap::new())),
            pending_fragments: Arc::new(RwLock::new(VecDeque::new())),
            verified_fragments: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Update local state snapshot (called when state changes)
    pub async fn update_local_snapshot(&self, snapshot: StateSnapshot) {
        let mut local = self.local_snapshot.write().await;
        *local = Some(snapshot);
    }

    /// Add a local fragment (for serving to peers)
    pub async fn add_local_fragment(&self, fragment: EncryptedFragment) {
        let mut fragments = self.local_fragments.write().await;
        fragments.insert(fragment.id, fragment);
    }

    /// Get current local snapshot
    pub async fn get_local_snapshot(&self) -> Option<StateSnapshot> {
        self.local_snapshot.read().await.clone()
    }

    /// Handle an incoming sync request
    pub async fn handle_request(
        &self,
        peer_id: &PeerId,
        request: SyncRequest,
    ) -> P2PResult<SyncResponse> {
        // Check rate limit
        if !self.check_rate_limit(peer_id).await {
            return Ok(SyncResponse::Error {
                code: SyncErrorCode::RateLimited,
                message: "Rate limit exceeded".into(),
            });
        }

        match request {
            SyncRequest::GetSnapshot => {
                let snapshot = self.local_snapshot.read().await;
                match &*snapshot {
                    Some(s) => Ok(SyncResponse::Snapshot(s.clone())),
                    None => Ok(SyncResponse::Error {
                        code: SyncErrorCode::InternalError,
                        message: "No snapshot available".into(),
                    }),
                }
            }

            SyncRequest::GetFragment { fragment_id } => {
                let fragments = self.local_fragments.read().await;
                let fragment = fragments.get(&fragment_id).cloned();
                Ok(SyncResponse::Fragment(fragment))
            }

            SyncRequest::GetFragmentsByEpoch { start_epoch, end_epoch, max_count } => {
                if end_epoch < start_epoch {
                    return Ok(SyncResponse::Error {
                        code: SyncErrorCode::InvalidEpochRange,
                        message: "Invalid epoch range".into(),
                    });
                }

                let fragments = self.local_fragments.read().await;
                let matching: Vec<_> = fragments
                    .values()
                    .filter(|f| f.epoch >= start_epoch && f.epoch <= end_epoch)
                    .take(max_count as usize)
                    .cloned()
                    .collect();

                let has_more = fragments
                    .values()
                    .filter(|f| f.epoch >= start_epoch && f.epoch <= end_epoch)
                    .count() > max_count as usize;

                let next_epoch = if has_more {
                    matching.last().map(|f| f.epoch)
                } else {
                    None
                };

                Ok(SyncResponse::Fragments {
                    fragments: matching,
                    has_more,
                    next_epoch,
                })
            }

            SyncRequest::InitiateFullSync { session_id } => {
                let sessions = self.incoming_sessions.read().await;
                if sessions.len() >= self.config.max_sessions {
                    return Ok(SyncResponse::Error {
                        code: SyncErrorCode::RateLimited,
                        message: "Too many active sessions".into(),
                    });
                }
                drop(sessions);

                let snapshot = match self.local_snapshot.read().await.clone() {
                    Some(s) => s,
                    None => {
                        return Ok(SyncResponse::Error {
                            code: SyncErrorCode::PeerSyncing,
                            message: "Node is still syncing".into(),
                        });
                    }
                };

                let fragments = self.local_fragments.read().await;
                let total_fragments = fragments.len() as u64;
                let total_batches = (total_fragments + self.config.batch_size as u64 - 1)
                    / self.config.batch_size as u64;

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let session = SyncSession {
                    id: session_id,
                    peer_id: *peer_id,
                    target_snapshot: snapshot,
                    current_batch: 0,
                    total_batches,
                    fragments_received: 0,
                    started_at: now,
                    last_activity: now,
                    state: SyncSessionState::InProgress,
                };

                let mut sessions = self.incoming_sessions.write().await;
                sessions.insert(session_id, session);

                Ok(SyncResponse::SyncInitiated {
                    session_id,
                    total_batches,
                    estimated_fragments: total_fragments,
                })
            }

            SyncRequest::GetSyncBatch { session_id, batch_index } => {
                let mut sessions = self.incoming_sessions.write().await;
                let session = match sessions.get_mut(&session_id) {
                    Some(s) => s,
                    None => {
                        return Ok(SyncResponse::Error {
                            code: SyncErrorCode::SessionNotFound,
                            message: "Session not found".into(),
                        });
                    }
                };

                session.last_activity = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let fragments = self.local_fragments.read().await;
                let batch_start = (batch_index * self.config.batch_size as u64) as usize;
                let batch_end = batch_start + self.config.batch_size as usize;

                let batch_fragments: Vec<_> = fragments
                    .values()
                    .skip(batch_start)
                    .take(self.config.batch_size as usize)
                    .cloned()
                    .collect();

                let is_last = batch_end >= fragments.len();

                if is_last {
                    session.state = SyncSessionState::Completed;
                }

                Ok(SyncResponse::SyncBatch {
                    session_id,
                    batch_index,
                    fragments: batch_fragments,
                    is_last,
                })
            }

            _ => Ok(SyncResponse::Error {
                code: SyncErrorCode::InternalError,
                message: "Request type not yet implemented".into(),
            }),
        }
    }

    /// Handle an incoming sync response
    pub async fn handle_response(
        &self,
        peer_id: &PeerId,
        response: SyncResponse,
    ) -> P2PResult<SyncEvent> {
        match response {
            SyncResponse::Snapshot(snapshot) => {
                Ok(SyncEvent::SnapshotReceived {
                    peer_id: *peer_id,
                    snapshot,
                })
            }

            SyncResponse::Fragment(fragment) => {
                match fragment {
                    Some(f) => {
                        f.verify_structure()?;
                        self.pending_fragments.write().await.push_back(f.clone());
                        Ok(SyncEvent::FragmentReceived {
                            peer_id: *peer_id,
                            fragment: f,
                        })
                    }
                    None => Ok(SyncEvent::FragmentNotFound { peer_id: *peer_id }),
                }
            }

            SyncResponse::SyncBatch { session_id, batch_index, fragments, is_last } => {
                let mut sessions = self.outgoing_sessions.write().await;
                let session = match sessions.get_mut(&session_id) {
                    Some(s) => s,
                    None => return Err(P2PError::SyncFailed("Session not found".into())),
                };

                session.current_batch = batch_index + 1;
                session.fragments_received += fragments.len() as u64;
                session.last_activity = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                // Queue fragments for verification
                let mut pending = self.pending_fragments.write().await;
                for fragment in &fragments {
                    if fragment.verify_structure().is_ok() {
                        pending.push_back(fragment.clone());
                    }
                }

                if is_last {
                    session.state = SyncSessionState::Verifying;
                    Ok(SyncEvent::SyncCompleted {
                        session_id,
                        fragments_received: session.fragments_received,
                    })
                } else {
                    Ok(SyncEvent::BatchReceived {
                        session_id,
                        batch_index,
                        fragment_count: fragments.len(),
                        remaining_batches: session.total_batches - session.current_batch,
                    })
                }
            }

            SyncResponse::SyncInitiated { session_id, total_batches, estimated_fragments } => {
                let mut sessions = self.outgoing_sessions.write().await;
                if let Some(session) = sessions.get_mut(&session_id) {
                    session.total_batches = total_batches;
                    session.state = SyncSessionState::InProgress;
                }

                Ok(SyncEvent::SyncStarted {
                    session_id,
                    total_batches,
                    estimated_fragments,
                })
            }

            SyncResponse::Error { code, message } => {
                Ok(SyncEvent::SyncError { code, message })
            }

            _ => Ok(SyncEvent::Unknown),
        }
    }

    /// Start a new full sync with a peer
    pub async fn start_full_sync(&self, peer_id: PeerId, target_snapshot: StateSnapshot) -> SyncSessionId {
        let session_id = SyncSessionId::random();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let session = SyncSession {
            id: session_id,
            peer_id,
            target_snapshot,
            current_batch: 0,
            total_batches: 0, // Will be updated when sync starts
            fragments_received: 0,
            started_at: now,
            last_activity: now,
            state: SyncSessionState::Initiating,
        };

        let mut sessions = self.outgoing_sessions.write().await;
        sessions.insert(session_id, session);

        session_id
    }

    /// Get the next batch request for an outgoing sync session
    pub async fn get_next_batch_request(&self, session_id: &SyncSessionId) -> Option<SyncRequest> {
        let sessions = self.outgoing_sessions.read().await;
        let session = sessions.get(session_id)?;

        if session.state != SyncSessionState::InProgress {
            return None;
        }

        if session.current_batch >= session.total_batches {
            return None;
        }

        Some(SyncRequest::GetSyncBatch {
            session_id: *session_id,
            batch_index: session.current_batch,
        })
    }

    /// Get sync session status
    pub async fn get_session_status(&self, session_id: &SyncSessionId) -> Option<SyncSession> {
        // Check outgoing first
        let outgoing = self.outgoing_sessions.read().await;
        if let Some(session) = outgoing.get(session_id) {
            return Some(session.clone());
        }
        drop(outgoing);

        // Check incoming
        let incoming = self.incoming_sessions.read().await;
        incoming.get(session_id).cloned()
    }

    /// Clean up timed out sessions
    pub async fn cleanup_timed_out_sessions(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let timeout = self.config.session_timeout;

        let mut outgoing = self.outgoing_sessions.write().await;
        outgoing.retain(|_, session| {
            now - session.last_activity < timeout
        });

        let mut incoming = self.incoming_sessions.write().await;
        incoming.retain(|_, session| {
            now - session.last_activity < timeout
        });
    }

    /// Process pending fragments (verify and store)
    pub async fn process_pending_fragments(&self) -> Vec<EncryptedFragment> {
        let mut verified = Vec::new();
        let mut pending = self.pending_fragments.write().await;

        while let Some(fragment) = pending.pop_front() {
            // Verify merkle proof if present
            if let Some(ref proof) = fragment.merkle_proof {
                if !proof.verify() {
                    continue; // Skip invalid proof
                }
            }

            // Verify structure
            if fragment.verify_structure().is_err() {
                continue;
            }

            // Check attestations
            if fragment.attestations.len() >= self.config.min_attestations {
                self.verified_fragments.write().await.insert(fragment.id);
                verified.push(fragment);
            }
        }

        verified
    }

    /// Check rate limit for a peer
    async fn check_rate_limit(&self, peer_id: &PeerId) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut limits = self.rate_limits.write().await;
        let entry = limits.entry(*peer_id).or_insert((now, 0));

        // Reset if minute has passed
        if now - entry.0 >= 60 {
            *entry = (now, 0);
        }

        if entry.1 >= self.config.rate_limit_rpm {
            return false;
        }

        entry.1 += 1;
        true
    }

    /// Get sync statistics
    pub async fn get_stats(&self) -> SyncStats {
        let outgoing = self.outgoing_sessions.read().await;
        let incoming = self.incoming_sessions.read().await;
        let pending = self.pending_fragments.read().await;
        let verified = self.verified_fragments.read().await;
        let local = self.local_fragments.read().await;

        SyncStats {
            outgoing_sessions: outgoing.len(),
            incoming_sessions: incoming.len(),
            pending_fragments: pending.len(),
            verified_fragments: verified.len(),
            local_fragments: local.len(),
        }
    }
}

/// Events emitted by state sync
#[derive(Clone, Debug)]
pub enum SyncEvent {
    /// Snapshot received from peer
    SnapshotReceived {
        peer_id: PeerId,
        snapshot: StateSnapshot,
    },
    /// Single fragment received
    FragmentReceived {
        peer_id: PeerId,
        fragment: EncryptedFragment,
    },
    /// Fragment not found
    FragmentNotFound {
        peer_id: PeerId,
    },
    /// Full sync started
    SyncStarted {
        session_id: SyncSessionId,
        total_batches: u64,
        estimated_fragments: u64,
    },
    /// Batch received during sync
    BatchReceived {
        session_id: SyncSessionId,
        batch_index: u64,
        fragment_count: usize,
        remaining_batches: u64,
    },
    /// Full sync completed
    SyncCompleted {
        session_id: SyncSessionId,
        fragments_received: u64,
    },
    /// Sync error
    SyncError {
        code: SyncErrorCode,
        message: String,
    },
    /// Unknown event
    Unknown,
}

/// Sync statistics
#[derive(Clone, Debug)]
pub struct SyncStats {
    /// Number of outgoing sync sessions
    pub outgoing_sessions: usize,
    /// Number of incoming sync sessions
    pub incoming_sessions: usize,
    /// Pending fragments awaiting verification
    pub pending_fragments: usize,
    /// Verified fragment count
    pub verified_fragments: usize,
    /// Local fragments available for serving
    pub local_fragments: usize,
}

/// Convert sync messages to network messages
impl SyncRequest {
    /// Convert to network message for transmission
    pub fn to_network_message(&self) -> NetworkMessage {
        let data = bincode::serialize(self).unwrap_or_default();
        NetworkMessage::StateUpdate(StateUpdateMessage {
            fragment_id: [0u8; 32], // Marker for sync request
            fragment_type: StateFragmentType::StateRoot,
            encrypted_data: data,
            version: 0,
            merkle_proof: None,
            attestations: Vec::new(),
        })
    }

    /// Parse from network message
    pub fn from_bytes(data: &[u8]) -> P2PResult<Self> {
        bincode::deserialize(data)
            .map_err(|e| P2PError::MessageError(e.to_string()))
    }
}

impl SyncResponse {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Parse from bytes
    pub fn from_bytes(data: &[u8]) -> P2PResult<Self> {
        bincode::deserialize(data)
            .map_err(|e| P2PError::MessageError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_session_id() {
        let id1 = SyncSessionId::random();
        let id2 = SyncSessionId::random();
        assert_ne!(id1.as_bytes(), id2.as_bytes());
    }

    #[test]
    fn test_state_snapshot_hash() {
        let snapshot = StateSnapshot {
            state_root: [1u8; 32],
            commitment_root: [2u8; 32],
            nullifier_root: [3u8; 32],
            epoch: 100,
            num_commitments: 1000,
            num_nullifiers: 500,
            timestamp: 12345,
            attestations: Vec::new(),
        };

        let hash1 = snapshot.hash();
        let hash2 = snapshot.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_encrypted_fragment_verify() {
        let fragment = EncryptedFragment {
            id: [1u8; 32],
            fragment_type: StateFragmentType::Balance,
            encrypted_data: vec![0u8; 64],
            commitment: [2u8; 32],
            owner_hash: [3u8; 32],
            epoch: 1,
            merkle_proof: None,
            attestations: Vec::new(),
        };

        assert!(fragment.verify_structure().is_ok());
    }

    #[test]
    fn test_encrypted_fragment_invalid() {
        let fragment = EncryptedFragment {
            id: [1u8; 32],
            fragment_type: StateFragmentType::Balance,
            encrypted_data: vec![], // Empty = invalid
            commitment: [2u8; 32],
            owner_hash: [3u8; 32],
            epoch: 1,
            merkle_proof: None,
            attestations: Vec::new(),
        };

        assert!(fragment.verify_structure().is_err());
    }

    #[test]
    fn test_merkle_proof_verification() {
        // Create a simple valid proof
        let leaf_hash = [1u8; 32];
        let sibling1 = [2u8; 32];

        // Compute root manually
        let mut hasher = blake3::Hasher::new();
        hasher.update(&leaf_hash);
        hasher.update(&sibling1);
        let root = *hasher.finalize().as_bytes();

        let proof = MerkleProof {
            path: vec![MerkleNode {
                hash: sibling1,
                position: MerklePosition::Right,
            }],
            leaf_index: 0,
            leaf_hash,
            root,
        };

        assert!(proof.verify());
    }

    #[test]
    fn test_sync_config_default() {
        let config = SyncConfig::default();
        assert_eq!(config.batch_size, 100);
        assert_eq!(config.max_sessions, 4);
        assert!(config.parallel_fetch);
    }

    #[tokio::test]
    async fn test_sync_manager_creation() {
        let manager = StateSyncManager::new(SyncConfig::default());
        let stats = manager.get_stats().await;
        assert_eq!(stats.outgoing_sessions, 0);
        assert_eq!(stats.incoming_sessions, 0);
    }

    #[tokio::test]
    async fn test_sync_manager_local_snapshot() {
        let manager = StateSyncManager::new(SyncConfig::default());

        let snapshot = StateSnapshot {
            state_root: [1u8; 32],
            commitment_root: [2u8; 32],
            nullifier_root: [3u8; 32],
            epoch: 100,
            num_commitments: 1000,
            num_nullifiers: 500,
            timestamp: 12345,
            attestations: Vec::new(),
        };

        manager.update_local_snapshot(snapshot.clone()).await;
        let retrieved = manager.get_local_snapshot().await;

        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().epoch, 100);
    }

    #[tokio::test]
    async fn test_sync_manager_add_fragment() {
        let manager = StateSyncManager::new(SyncConfig::default());

        let fragment = EncryptedFragment {
            id: [1u8; 32],
            fragment_type: StateFragmentType::Balance,
            encrypted_data: vec![0u8; 64],
            commitment: [2u8; 32],
            owner_hash: [3u8; 32],
            epoch: 1,
            merkle_proof: None,
            attestations: Vec::new(),
        };

        manager.add_local_fragment(fragment).await;
        let stats = manager.get_stats().await;
        assert_eq!(stats.local_fragments, 1);
    }

    #[test]
    fn test_sync_request_serialization() {
        let request = SyncRequest::GetSnapshot;
        let bytes = bincode::serialize(&request).unwrap();
        let restored: SyncRequest = bincode::deserialize(&bytes).unwrap();

        match restored {
            SyncRequest::GetSnapshot => {}
            _ => panic!("Wrong request type"),
        }
    }

    #[test]
    fn test_sync_response_serialization() {
        let response = SyncResponse::Error {
            code: SyncErrorCode::FragmentNotFound,
            message: "Test error".into(),
        };

        let bytes = response.to_bytes();
        let restored = SyncResponse::from_bytes(&bytes).unwrap();

        match restored {
            SyncResponse::Error { code, message } => {
                assert!(matches!(code, SyncErrorCode::FragmentNotFound));
                assert_eq!(message, "Test error");
            }
            _ => panic!("Wrong response type"),
        }
    }
}
