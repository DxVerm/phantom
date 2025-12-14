//! Prometheus Metrics System
//!
//! Provides comprehensive monitoring for PHANTOM nodes:
//! - Consensus metrics (attestations, finality, rounds)
//! - Transaction metrics (throughput, latency, pool size)
//! - Network metrics (peers, bandwidth, messages)
//! - Storage metrics (blocks, state size, cache hits)
//! - System metrics (CPU, memory, disk)

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::io::AsyncWriteExt;

/// Metrics errors
#[derive(Error, Debug)]
pub enum MetricsError {
    #[error("Server error: {0}")]
    Server(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Already running")]
    AlreadyRunning,
}

pub type MetricsResult<T> = Result<T, MetricsError>;

/// Metrics server configuration
#[derive(Clone, Debug)]
pub struct MetricsConfig {
    /// Address to bind metrics server
    pub bind_addr: SocketAddr,
    /// Metrics collection interval
    pub collection_interval: Duration,
    /// Enable detailed histograms
    pub enable_histograms: bool,
    /// Namespace prefix for all metrics
    pub namespace: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:9090".parse().unwrap(),
            collection_interval: Duration::from_secs(10),
            enable_histograms: true,
            namespace: "phantom".to_string(),
        }
    }
}

/// Atomic counter metric
#[derive(Debug, Default)]
pub struct Counter {
    value: AtomicU64,
}

impl Counter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_by(&self, n: u64) {
        self.value.fetch_add(n, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }

    pub fn reset(&self) {
        self.value.store(0, Ordering::Relaxed);
    }
}

/// Atomic gauge metric
#[derive(Debug, Default)]
pub struct Gauge {
    value: AtomicU64,
}

impl Gauge {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, v: u64) {
        self.value.store(v, Ordering::Relaxed);
    }

    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec(&self) {
        self.value.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

/// Simple histogram for latency tracking
#[derive(Debug)]
pub struct Histogram {
    buckets: Vec<AtomicU64>,
    bucket_bounds: Vec<f64>,
    sum: AtomicU64,
    count: AtomicU64,
}

impl Histogram {
    /// Create histogram with default latency buckets (ms)
    pub fn new() -> Self {
        Self::with_buckets(vec![
            1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0, 10000.0,
        ])
    }

    /// Create histogram with custom buckets
    pub fn with_buckets(bounds: Vec<f64>) -> Self {
        let buckets = (0..=bounds.len())
            .map(|_| AtomicU64::new(0))
            .collect();

        Self {
            buckets,
            bucket_bounds: bounds,
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// Observe a value
    pub fn observe(&self, value: f64) {
        let value_bits = (value * 1000.0) as u64;
        self.sum.fetch_add(value_bits, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);

        for (i, bound) in self.bucket_bounds.iter().enumerate() {
            if value <= *bound {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        // Overflow bucket
        self.buckets.last().unwrap().fetch_add(1, Ordering::Relaxed);
    }

    /// Get bucket counts
    pub fn get_buckets(&self) -> Vec<(f64, u64)> {
        let mut result = Vec::new();
        let mut cumulative = 0u64;

        for (i, bound) in self.bucket_bounds.iter().enumerate() {
            cumulative += self.buckets[i].load(Ordering::Relaxed);
            result.push((*bound, cumulative));
        }

        // +Inf bucket
        cumulative += self.buckets.last().unwrap().load(Ordering::Relaxed);
        result.push((f64::INFINITY, cumulative));

        result
    }

    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    pub fn sum(&self) -> f64 {
        self.sum.load(Ordering::Relaxed) as f64 / 1000.0
    }
}

impl Default for Histogram {
    fn default() -> Self {
        Self::new()
    }
}

/// Timer for measuring duration
pub struct Timer {
    start: Instant,
    histogram: Arc<Histogram>,
}

impl Timer {
    pub fn new(histogram: Arc<Histogram>) -> Self {
        Self {
            start: Instant::now(),
            histogram,
        }
    }

    pub fn observe_duration(self) -> f64 {
        let duration = self.start.elapsed().as_secs_f64() * 1000.0;
        self.histogram.observe(duration);
        duration
    }
}

/// Node metrics collection
#[derive(Default)]
pub struct NodeMetrics {
    // Consensus metrics
    pub consensus_rounds_total: Counter,
    pub consensus_attestations_total: Counter,
    pub consensus_attestations_successful: Counter,
    pub consensus_finalized_blocks: Counter,
    pub consensus_current_round: Gauge,
    pub consensus_validators_active: Gauge,
    pub consensus_attestation_latency: Histogram,

    // Transaction metrics
    pub tx_received_total: Counter,
    pub tx_processed_total: Counter,
    pub tx_failed_total: Counter,
    pub tx_mempool_size: Gauge,
    pub tx_gas_used_total: Counter,
    pub tx_processing_latency: Histogram,

    // Block metrics
    pub blocks_produced_total: Counter,
    pub blocks_imported_total: Counter,
    pub blocks_rejected_total: Counter,
    pub block_height: Gauge,
    pub block_size_bytes: Histogram,
    pub block_tx_count: Histogram,
    pub block_production_latency: Histogram,

    // Network metrics
    pub peers_connected: Gauge,
    pub peers_discovered_total: Counter,
    pub peers_disconnected_total: Counter,
    pub messages_received_total: Counter,
    pub messages_sent_total: Counter,
    pub bytes_received_total: Counter,
    pub bytes_sent_total: Counter,
    pub message_latency: Histogram,

    // Sync metrics
    pub sync_status: Gauge, // 0=synced, 1=syncing, 2=stalled
    pub sync_blocks_downloaded: Counter,
    pub sync_blocks_remaining: Gauge,
    pub sync_peers: Gauge,

    // Storage metrics
    pub storage_blocks_total: Gauge,
    pub storage_state_size_bytes: Gauge,
    pub storage_cache_hits: Counter,
    pub storage_cache_misses: Counter,
    pub storage_read_latency: Histogram,
    pub storage_write_latency: Histogram,

    // ESL (Encrypted State Ledger) metrics
    pub esl_accounts_total: Gauge,
    pub esl_proof_generation_latency: Histogram,
    pub esl_proof_verification_latency: Histogram,
    pub esl_tree_depth: Gauge,

    // Validator metrics
    pub validator_stake_total: Gauge,
    pub validator_rewards_total: Counter,
    pub validator_slashing_events: Counter,
    pub validator_unbonding_queue: Gauge,

    // System metrics
    pub process_cpu_seconds_total: Counter,
    pub process_memory_bytes: Gauge,
    pub process_open_fds: Gauge,
    pub process_start_time_seconds: Gauge,

    // Custom labels
    labels: RwLock<Vec<(String, String)>>,
}

impl NodeMetrics {
    /// Create new metrics collection
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a label to all metrics
    pub fn add_label(&self, key: impl Into<String>, value: impl Into<String>) {
        self.labels.write().push((key.into(), value.into()));
    }

    /// Start a timer for a histogram
    pub fn start_timer(&self, histogram: &Histogram) -> Timer {
        Timer::new(Arc::new(Histogram::new()))
    }

    /// Record transaction received
    pub fn record_tx_received(&self) {
        self.tx_received_total.inc();
    }

    /// Record transaction processed
    pub fn record_tx_processed(&self, success: bool, gas_used: u64, latency_ms: f64) {
        self.tx_processed_total.inc();
        if !success {
            self.tx_failed_total.inc();
        }
        self.tx_gas_used_total.inc_by(gas_used);
        self.tx_processing_latency.observe(latency_ms);
    }

    /// Record block produced
    pub fn record_block_produced(&self, height: u64, size_bytes: u64, tx_count: u64, latency_ms: f64) {
        self.blocks_produced_total.inc();
        self.block_height.set(height);
        self.block_size_bytes.observe(size_bytes as f64);
        self.block_tx_count.observe(tx_count as f64);
        self.block_production_latency.observe(latency_ms);
    }

    /// Record block imported
    pub fn record_block_imported(&self, height: u64) {
        self.blocks_imported_total.inc();
        self.block_height.set(height);
    }

    /// Record attestation
    pub fn record_attestation(&self, successful: bool, latency_ms: f64) {
        self.consensus_attestations_total.inc();
        if successful {
            self.consensus_attestations_successful.inc();
        }
        self.consensus_attestation_latency.observe(latency_ms);
    }

    /// Update mempool size
    pub fn update_mempool_size(&self, size: u64) {
        self.tx_mempool_size.set(size);
    }

    /// Update peer count
    pub fn update_peers(&self, connected: u64) {
        self.peers_connected.set(connected);
    }

    /// Record network message
    pub fn record_network_message(&self, sent: bool, bytes: u64) {
        if sent {
            self.messages_sent_total.inc();
            self.bytes_sent_total.inc_by(bytes);
        } else {
            self.messages_received_total.inc();
            self.bytes_received_total.inc_by(bytes);
        }
    }

    /// Update sync status
    pub fn update_sync_status(&self, syncing: bool, remaining: u64) {
        self.sync_status.set(if syncing { 1 } else { 0 });
        self.sync_blocks_remaining.set(remaining);
    }

    /// Record storage operation
    pub fn record_storage_read(&self, cache_hit: bool, latency_ms: f64) {
        if cache_hit {
            self.storage_cache_hits.inc();
        } else {
            self.storage_cache_misses.inc();
        }
        self.storage_read_latency.observe(latency_ms);
    }

    /// Update validator metrics
    pub fn update_validator_metrics(&self, active: u64, total_stake: u64, unbonding: u64) {
        self.consensus_validators_active.set(active);
        self.validator_stake_total.set(total_stake);
        self.validator_unbonding_queue.set(unbonding);
    }

    /// Export metrics in Prometheus format
    pub fn export(&self) -> String {
        let labels = self.labels.read();
        let label_str = if labels.is_empty() {
            String::new()
        } else {
            let pairs: Vec<String> = labels
                .iter()
                .map(|(k, v)| format!("{}=\"{}\"", k, v))
                .collect();
            format!("{{{}}}", pairs.join(","))
        };

        let mut output = String::new();

        // Helper macro for metrics
        macro_rules! export_counter {
            ($name:expr, $help:expr, $value:expr) => {
                output.push_str(&format!(
                    "# HELP phantom_{} {}\n# TYPE phantom_{} counter\nphantom_{}{} {}\n",
                    $name, $help, $name, $name, label_str, $value
                ));
            };
        }

        macro_rules! export_gauge {
            ($name:expr, $help:expr, $value:expr) => {
                output.push_str(&format!(
                    "# HELP phantom_{} {}\n# TYPE phantom_{} gauge\nphantom_{}{} {}\n",
                    $name, $help, $name, $name, label_str, $value
                ));
            };
        }

        macro_rules! export_histogram {
            ($name:expr, $help:expr, $hist:expr) => {
                output.push_str(&format!(
                    "# HELP phantom_{} {}\n# TYPE phantom_{} histogram\n",
                    $name, $help, $name
                ));
                for (bound, count) in $hist.get_buckets() {
                    let le = if bound.is_infinite() {
                        "+Inf".to_string()
                    } else {
                        bound.to_string()
                    };
                    output.push_str(&format!(
                        "phantom_{}_bucket{{le=\"{}\"}}{} {}\n",
                        $name, le, label_str, count
                    ));
                }
                output.push_str(&format!(
                    "phantom_{}_sum{} {}\nphantom_{}_count{} {}\n",
                    $name, label_str, $hist.sum(),
                    $name, label_str, $hist.count()
                ));
            };
        }

        // Consensus metrics
        export_counter!("consensus_rounds_total", "Total consensus rounds", self.consensus_rounds_total.get());
        export_counter!("consensus_attestations_total", "Total attestations made", self.consensus_attestations_total.get());
        export_counter!("consensus_attestations_successful", "Successful attestations", self.consensus_attestations_successful.get());
        export_counter!("consensus_finalized_blocks", "Finalized blocks", self.consensus_finalized_blocks.get());
        export_gauge!("consensus_current_round", "Current consensus round", self.consensus_current_round.get());
        export_gauge!("consensus_validators_active", "Active validators", self.consensus_validators_active.get());
        export_histogram!("consensus_attestation_latency_ms", "Attestation latency in ms", self.consensus_attestation_latency);

        // Transaction metrics
        export_counter!("tx_received_total", "Total transactions received", self.tx_received_total.get());
        export_counter!("tx_processed_total", "Total transactions processed", self.tx_processed_total.get());
        export_counter!("tx_failed_total", "Failed transactions", self.tx_failed_total.get());
        export_gauge!("tx_mempool_size", "Current mempool size", self.tx_mempool_size.get());
        export_counter!("tx_gas_used_total", "Total gas used", self.tx_gas_used_total.get());
        export_histogram!("tx_processing_latency_ms", "Transaction processing latency in ms", self.tx_processing_latency);

        // Block metrics
        export_counter!("blocks_produced_total", "Total blocks produced", self.blocks_produced_total.get());
        export_counter!("blocks_imported_total", "Total blocks imported", self.blocks_imported_total.get());
        export_counter!("blocks_rejected_total", "Rejected blocks", self.blocks_rejected_total.get());
        export_gauge!("block_height", "Current block height", self.block_height.get());
        export_histogram!("block_size_bytes", "Block size in bytes", self.block_size_bytes);
        export_histogram!("block_tx_count", "Transactions per block", self.block_tx_count);
        export_histogram!("block_production_latency_ms", "Block production latency in ms", self.block_production_latency);

        // Network metrics
        export_gauge!("peers_connected", "Connected peers", self.peers_connected.get());
        export_counter!("peers_discovered_total", "Total peers discovered", self.peers_discovered_total.get());
        export_counter!("peers_disconnected_total", "Total peer disconnections", self.peers_disconnected_total.get());
        export_counter!("messages_received_total", "Total messages received", self.messages_received_total.get());
        export_counter!("messages_sent_total", "Total messages sent", self.messages_sent_total.get());
        export_counter!("bytes_received_total", "Total bytes received", self.bytes_received_total.get());
        export_counter!("bytes_sent_total", "Total bytes sent", self.bytes_sent_total.get());
        export_histogram!("message_latency_ms", "Message latency in ms", self.message_latency);

        // Sync metrics
        export_gauge!("sync_status", "Sync status (0=synced, 1=syncing)", self.sync_status.get());
        export_counter!("sync_blocks_downloaded", "Blocks downloaded during sync", self.sync_blocks_downloaded.get());
        export_gauge!("sync_blocks_remaining", "Blocks remaining to sync", self.sync_blocks_remaining.get());
        export_gauge!("sync_peers", "Sync peers", self.sync_peers.get());

        // Storage metrics
        export_gauge!("storage_blocks_total", "Total stored blocks", self.storage_blocks_total.get());
        export_gauge!("storage_state_size_bytes", "State storage size in bytes", self.storage_state_size_bytes.get());
        export_counter!("storage_cache_hits", "Storage cache hits", self.storage_cache_hits.get());
        export_counter!("storage_cache_misses", "Storage cache misses", self.storage_cache_misses.get());
        export_histogram!("storage_read_latency_ms", "Storage read latency in ms", self.storage_read_latency);
        export_histogram!("storage_write_latency_ms", "Storage write latency in ms", self.storage_write_latency);

        // ESL metrics
        export_gauge!("esl_accounts_total", "Total ESL accounts", self.esl_accounts_total.get());
        export_histogram!("esl_proof_generation_latency_ms", "ESL proof generation latency in ms", self.esl_proof_generation_latency);
        export_histogram!("esl_proof_verification_latency_ms", "ESL proof verification latency in ms", self.esl_proof_verification_latency);
        export_gauge!("esl_tree_depth", "ESL tree depth", self.esl_tree_depth.get());

        // Validator metrics
        export_gauge!("validator_stake_total", "Total validator stake", self.validator_stake_total.get());
        export_counter!("validator_rewards_total", "Total validator rewards", self.validator_rewards_total.get());
        export_counter!("validator_slashing_events", "Total slashing events", self.validator_slashing_events.get());
        export_gauge!("validator_unbonding_queue", "Unbonding queue size", self.validator_unbonding_queue.get());

        // System metrics
        export_counter!("process_cpu_seconds_total", "Total CPU seconds", self.process_cpu_seconds_total.get());
        export_gauge!("process_memory_bytes", "Process memory usage", self.process_memory_bytes.get());
        export_gauge!("process_open_fds", "Open file descriptors", self.process_open_fds.get());
        export_gauge!("process_start_time_seconds", "Process start time", self.process_start_time_seconds.get());

        output
    }
}

/// Shared metrics instance
pub struct SharedMetrics(Arc<NodeMetrics>);

impl SharedMetrics {
    pub fn new() -> Self {
        Self(Arc::new(NodeMetrics::new()))
    }

    pub fn get(&self) -> &NodeMetrics {
        &self.0
    }

    pub fn inner(&self) -> Arc<NodeMetrics> {
        Arc::clone(&self.0)
    }
}

impl Clone for SharedMetrics {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl Default for SharedMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Prometheus metrics HTTP server
pub struct MetricsServer {
    config: MetricsConfig,
    metrics: SharedMetrics,
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl MetricsServer {
    /// Create new metrics server
    pub fn new(config: MetricsConfig, metrics: SharedMetrics) -> Self {
        Self {
            config,
            metrics,
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Start the metrics server
    pub async fn start(&self) -> MetricsResult<()> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Err(MetricsError::AlreadyRunning);
        }

        let listener = TcpListener::bind(self.config.bind_addr).await?;
        let metrics = self.metrics.clone();
        let running = Arc::clone(&self.running);

        tokio::spawn(async move {
            while running.load(Ordering::SeqCst) {
                match listener.accept().await {
                    Ok((mut socket, _)) => {
                        let metrics_data = metrics.get().export();

                        let response = format!(
                            "HTTP/1.1 200 OK\r\n\
                            Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
                            Content-Length: {}\r\n\
                            \r\n\
                            {}",
                            metrics_data.len(),
                            metrics_data
                        );

                        let _ = socket.write_all(response.as_bytes()).await;
                    }
                    Err(e) => {
                        eprintln!("Metrics server error: {}", e);
                    }
                }
            }
        });

        Ok(())
    }

    /// Stop the metrics server
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Check if running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get metrics reference
    pub fn metrics(&self) -> &SharedMetrics {
        &self.metrics
    }
}

/// Convenience macro for timing operations
#[macro_export]
macro_rules! time_operation {
    ($histogram:expr, $operation:expr) => {{
        let start = std::time::Instant::now();
        let result = $operation;
        let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
        $histogram.observe(duration_ms);
        result
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter() {
        let counter = Counter::new();
        assert_eq!(counter.get(), 0);

        counter.inc();
        assert_eq!(counter.get(), 1);

        counter.inc_by(5);
        assert_eq!(counter.get(), 6);

        counter.reset();
        assert_eq!(counter.get(), 0);
    }

    #[test]
    fn test_gauge() {
        let gauge = Gauge::new();
        assert_eq!(gauge.get(), 0);

        gauge.set(100);
        assert_eq!(gauge.get(), 100);

        gauge.inc();
        assert_eq!(gauge.get(), 101);

        gauge.dec();
        assert_eq!(gauge.get(), 100);
    }

    #[test]
    fn test_histogram() {
        let histogram = Histogram::new();

        histogram.observe(5.0);
        histogram.observe(50.0);
        histogram.observe(500.0);
        histogram.observe(5000.0);

        assert_eq!(histogram.count(), 4);
        assert!((histogram.sum() - 5555.0).abs() < 0.01);

        let buckets = histogram.get_buckets();
        assert!(!buckets.is_empty());
    }

    #[test]
    fn test_metrics_export() {
        let metrics = NodeMetrics::new();

        metrics.consensus_rounds_total.inc_by(100);
        metrics.block_height.set(12345);
        metrics.peers_connected.set(25);
        metrics.tx_processing_latency.observe(10.0);
        metrics.tx_processing_latency.observe(20.0);

        let output = metrics.export();

        assert!(output.contains("phantom_consensus_rounds_total"));
        assert!(output.contains("100"));
        assert!(output.contains("phantom_block_height"));
        assert!(output.contains("12345"));
        assert!(output.contains("phantom_peers_connected"));
        assert!(output.contains("phantom_tx_processing_latency_ms"));
    }

    #[test]
    fn test_record_methods() {
        let metrics = NodeMetrics::new();

        metrics.record_tx_received();
        assert_eq!(metrics.tx_received_total.get(), 1);

        metrics.record_tx_processed(true, 21000, 5.0);
        assert_eq!(metrics.tx_processed_total.get(), 1);
        assert_eq!(metrics.tx_gas_used_total.get(), 21000);

        metrics.record_tx_processed(false, 10000, 10.0);
        assert_eq!(metrics.tx_failed_total.get(), 1);

        metrics.record_block_produced(100, 5000, 50, 100.0);
        assert_eq!(metrics.blocks_produced_total.get(), 1);
        assert_eq!(metrics.block_height.get(), 100);

        metrics.record_attestation(true, 15.0);
        assert_eq!(metrics.consensus_attestations_total.get(), 1);
        assert_eq!(metrics.consensus_attestations_successful.get(), 1);
    }

    #[test]
    fn test_shared_metrics() {
        let shared = SharedMetrics::new();
        let cloned = shared.clone();

        shared.get().tx_received_total.inc();

        assert_eq!(cloned.get().tx_received_total.get(), 1);
    }

    #[test]
    fn test_metrics_with_labels() {
        let metrics = NodeMetrics::new();
        metrics.add_label("node_id", "node-1");
        metrics.add_label("network", "testnet");

        let output = metrics.export();

        assert!(output.contains("node_id=\"node-1\""));
        assert!(output.contains("network=\"testnet\""));
    }

    #[test]
    fn test_histogram_buckets() {
        let histogram = Histogram::with_buckets(vec![10.0, 50.0, 100.0]);

        histogram.observe(5.0);   // <= 10
        histogram.observe(25.0);  // <= 50
        histogram.observe(75.0);  // <= 100
        histogram.observe(200.0); // > 100 (overflow)

        let buckets = histogram.get_buckets();

        assert_eq!(buckets[0], (10.0, 1));   // 1 value <= 10
        assert_eq!(buckets[1], (50.0, 2));   // 2 values <= 50 (cumulative)
        assert_eq!(buckets[2], (100.0, 3));  // 3 values <= 100 (cumulative)
        assert_eq!(buckets[3].1, 4);         // 4 total (cumulative +Inf)
    }

    #[test]
    fn test_sync_status_update() {
        let metrics = NodeMetrics::new();

        metrics.update_sync_status(true, 1000);
        assert_eq!(metrics.sync_status.get(), 1);
        assert_eq!(metrics.sync_blocks_remaining.get(), 1000);

        metrics.update_sync_status(false, 0);
        assert_eq!(metrics.sync_status.get(), 0);
        assert_eq!(metrics.sync_blocks_remaining.get(), 0);
    }

    #[test]
    fn test_validator_metrics_update() {
        let metrics = NodeMetrics::new();

        metrics.update_validator_metrics(50, 1_000_000_000, 10);

        assert_eq!(metrics.consensus_validators_active.get(), 50);
        assert_eq!(metrics.validator_stake_total.get(), 1_000_000_000);
        assert_eq!(metrics.validator_unbonding_queue.get(), 10);
    }

    #[tokio::test]
    async fn test_metrics_server_creation() {
        let config = MetricsConfig::default();
        let metrics = SharedMetrics::new();
        let server = MetricsServer::new(config, metrics);

        assert!(!server.is_running());
    }
}
