//! State storage for ESL snapshots

use std::sync::Arc;
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use crate::{StorageError, StorageResult};

/// Table for state snapshots by epoch
const STATE_SNAPSHOTS: TableDefinition<u64, &[u8]> = TableDefinition::new("state_snapshots");

/// Table for latest state root
const LATEST_STATE: TableDefinition<&str, &[u8]> = TableDefinition::new("latest_state");

/// Table for spent nullifiers
const NULLIFIERS: TableDefinition<&[u8], u64> = TableDefinition::new("nullifiers");

/// Stored state snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    /// Epoch number
    pub epoch: u64,
    /// Block height at snapshot
    pub height: u64,
    /// ESL state root
    pub state_root: [u8; 32],
    /// Total accounts
    pub account_count: u64,
    /// Validator set hash
    pub validator_set_hash: [u8; 32],
    /// Timestamp
    pub timestamp: u64,
    /// Serialized ESL tree (compressed)
    pub tree_data: Vec<u8>,
}

/// State storage interface
pub struct StateStore {
    db: Arc<Database>,
}

impl StateStore {
    /// Create new state store
    pub fn new(db: Arc<Database>) -> StorageResult<Self> {
        let write_txn = db.begin_write()?;
        {
            let _ = write_txn.open_table(STATE_SNAPSHOTS)?;
            let _ = write_txn.open_table(LATEST_STATE)?;
            let _ = write_txn.open_table(NULLIFIERS)?;
        }
        write_txn.commit()?;

        Ok(Self { db })
    }

    /// Save a state snapshot
    pub fn save_snapshot(&self, snapshot: &StateSnapshot) -> StorageResult<()> {
        let encoded = bincode::serialize(snapshot)?;

        let write_txn = self.db.begin_write()?;
        {
            let mut snapshots = write_txn.open_table(STATE_SNAPSHOTS)?;
            let mut latest = write_txn.open_table(LATEST_STATE)?;

            snapshots.insert(snapshot.epoch, encoded.as_slice())?;
            latest.insert("root", snapshot.state_root.as_slice())?;
            latest.insert("epoch", &snapshot.epoch.to_le_bytes()[..])?;
        }
        write_txn.commit()?;

        Ok(())
    }

    /// Get snapshot by epoch
    pub fn get_snapshot(&self, epoch: u64) -> StorageResult<Option<StateSnapshot>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(STATE_SNAPSHOTS)?;

        let result = match table.get(epoch)? {
            Some(data) => {
                let bytes = data.value().to_vec();
                Some(bincode::deserialize(&bytes)?)
            }
            None => None,
        };

        Ok(result)
    }

    /// Get latest state root
    pub fn get_latest_root(&self) -> StorageResult<Option<[u8; 32]>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(LATEST_STATE)?;

        let result = match table.get("root")? {
            Some(data) => {
                let bytes = data.value();
                let mut root = [0u8; 32];
                root.copy_from_slice(bytes);
                Some(root)
            }
            None => None,
        };

        Ok(result)
    }

    /// Get latest epoch with snapshot
    pub fn get_latest_epoch(&self) -> StorageResult<Option<u64>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(LATEST_STATE)?;

        let result = match table.get("epoch")? {
            Some(data) => {
                let bytes = data.value().to_vec();
                let arr: [u8; 8] = bytes.try_into().map_err(|_| {
                    StorageError::InvalidData("Invalid epoch bytes".into())
                })?;
                Some(u64::from_le_bytes(arr))
            }
            None => None,
        };

        Ok(result)
    }

    /// Get snapshot count
    pub fn snapshot_count(&self) -> StorageResult<u64> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(STATE_SNAPSHOTS)?;
        let len = table.len()?;
        Ok(len)
    }

    /// Get nearest snapshot at or before given epoch
    pub fn get_nearest_snapshot(&self, epoch: u64) -> StorageResult<Option<StateSnapshot>> {
        let result_bytes: Option<Vec<u8>> = {
            let read_txn = self.db.begin_read()?;
            let table = read_txn.open_table(STATE_SNAPSHOTS)?;
            let range = table.range(..=epoch)?;

            // Find the last one (highest epoch <= requested)
            let mut found = None;
            for item in range.rev() {
                if let Ok((_, data)) = item {
                    found = Some(data.value().to_vec());
                    break;
                }
            }
            found
        };

        match result_bytes {
            Some(bytes) => {
                let snapshot: StateSnapshot = bincode::deserialize(&bytes)?;
                Ok(Some(snapshot))
            }
            None => Ok(None),
        }
    }

    /// Delete old snapshots (keep last N epochs)
    pub fn prune_snapshots(&self, keep_epochs: u64) -> StorageResult<usize> {
        // Collect all epochs in a scoped read transaction
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(STATE_SNAPSHOTS)?;
        let all_epochs: Vec<u64> = table.iter()?
            .filter_map(|r| r.ok().map(|(k, _)| k.value()))
            .collect();
        drop(table);
        drop(read_txn);

        if all_epochs.len() as u64 <= keep_epochs {
            return Ok(0);
        }

        let delete_count = all_epochs.len() - keep_epochs as usize;
        let epochs_to_delete: Vec<_> = all_epochs.into_iter().take(delete_count).collect();

        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(STATE_SNAPSHOTS)?;
            for epoch in &epochs_to_delete {
                table.remove(*epoch)?;
            }
        }
        write_txn.commit()?;

        Ok(delete_count)
    }

    /// Get all nullifiers (spent note identifiers)
    pub fn get_nullifier_set(&self) -> StorageResult<Option<Vec<[u8; 32]>>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(NULLIFIERS)?;

        let nullifiers: Vec<[u8; 32]> = table.iter()?
            .filter_map(|r| r.ok())
            .filter_map(|(k, _)| {
                let bytes = k.value();
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(bytes);
                    Some(arr)
                } else {
                    None
                }
            })
            .collect();

        if nullifiers.is_empty() {
            Ok(None)
        } else {
            Ok(Some(nullifiers))
        }
    }

    /// Add a nullifier (mark note as spent)
    pub fn add_nullifier(&self, nullifier: &[u8; 32], block_height: u64) -> StorageResult<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(NULLIFIERS)?;
            table.insert(nullifier.as_slice(), block_height)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Check if a nullifier exists (note is spent)
    pub fn has_nullifier(&self, nullifier: &[u8; 32]) -> StorageResult<bool> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(NULLIFIERS)?;
        let exists = table.get(nullifier.as_slice())?.is_some();
        Ok(exists)
    }

    /// Add multiple nullifiers in a batch
    pub fn add_nullifiers(&self, nullifiers: &[[u8; 32]], block_height: u64) -> StorageResult<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(NULLIFIERS)?;
            for nullifier in nullifiers {
                table.insert(nullifier.as_slice(), block_height)?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn create_test_snapshot(epoch: u64) -> StateSnapshot {
        StateSnapshot {
            epoch,
            height: epoch * 100,
            state_root: [epoch as u8; 32],
            account_count: 1000 + epoch,
            validator_set_hash: [0u8; 32],
            timestamp: 1000000 + epoch * 600,
            tree_data: vec![0u8; 100],
        }
    }

    #[test]
    fn test_state_store() {
        let dir = tempdir().unwrap();
        let db = Database::create(dir.path().join("test.db")).unwrap();
        let store = StateStore::new(Arc::new(db)).unwrap();

        let snapshot = create_test_snapshot(5);
        store.save_snapshot(&snapshot).unwrap();

        let retrieved = store.get_snapshot(5).unwrap().unwrap();
        assert_eq!(retrieved.epoch, 5);
        assert_eq!(retrieved.height, 500);

        let root = store.get_latest_root().unwrap().unwrap();
        assert_eq!(root, [5u8; 32]);

        let latest_epoch = store.get_latest_epoch().unwrap().unwrap();
        assert_eq!(latest_epoch, 5);
    }

    #[test]
    fn test_nearest_snapshot() {
        let dir = tempdir().unwrap();
        let db = Database::create(dir.path().join("test.db")).unwrap();
        let store = StateStore::new(Arc::new(db)).unwrap();

        for epoch in [1, 5, 10, 15] {
            store.save_snapshot(&create_test_snapshot(epoch)).unwrap();
        }

        let nearest = store.get_nearest_snapshot(7).unwrap().unwrap();
        assert_eq!(nearest.epoch, 5);

        let nearest = store.get_nearest_snapshot(15).unwrap().unwrap();
        assert_eq!(nearest.epoch, 15);
    }

    #[test]
    fn test_prune_snapshots() {
        let dir = tempdir().unwrap();
        let db = Database::create(dir.path().join("test.db")).unwrap();
        let store = StateStore::new(Arc::new(db)).unwrap();

        for epoch in 1..=10 {
            store.save_snapshot(&create_test_snapshot(epoch)).unwrap();
        }

        assert_eq!(store.snapshot_count().unwrap(), 10);

        let pruned = store.prune_snapshots(3).unwrap();
        assert_eq!(pruned, 7);
        assert_eq!(store.snapshot_count().unwrap(), 3);

        // Should have epochs 8, 9, 10
        assert!(store.get_snapshot(7).unwrap().is_none());
        assert!(store.get_snapshot(8).unwrap().is_some());
    }
}
