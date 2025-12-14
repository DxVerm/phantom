//! Chain metadata storage

use std::sync::Arc;
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use crate::{StorageError, StorageResult};

/// Table for chain metadata
const CHAIN_META: TableDefinition<&str, &[u8]> = TableDefinition::new("chain_meta");

/// Table for validator history by epoch
const VALIDATOR_SETS: TableDefinition<u64, &[u8]> = TableDefinition::new("validator_sets");

/// Table for consensus checkpoints
const CHECKPOINTS: TableDefinition<u64, &[u8]> = TableDefinition::new("checkpoints");

/// Chain metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainMeta {
    /// Genesis hash
    pub genesis_hash: [u8; 32],
    /// Network ID
    pub network_id: String,
    /// Chain ID
    pub chain_id: u64,
    /// Genesis timestamp
    pub genesis_timestamp: u64,
    /// Current epoch
    pub current_epoch: u64,
    /// Current round
    pub current_round: u64,
    /// Latest finalized height
    pub finalized_height: u64,
    /// Latest finalized hash
    pub finalized_hash: [u8; 32],
    /// Current height
    pub current_height: u64,
}

/// Validator set at an epoch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSet {
    pub epoch: u64,
    pub validators: Vec<ValidatorEntry>,
    pub total_stake: u64,
}

/// Validator entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorEntry {
    pub id: [u8; 32],
    pub public_key: Vec<u8>,
    pub stake: u64,
    pub commission: u16, // basis points
    pub active: bool,
}

/// Consensus checkpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub height: u64,
    pub epoch: u64,
    pub round: u64,
    pub block_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub validator_set_hash: [u8; 32],
    pub timestamp: u64,
}

/// Chain storage interface
pub struct ChainStore {
    db: Arc<Database>,
}

impl ChainStore {
    /// Create new chain store
    pub fn new(db: Arc<Database>) -> StorageResult<Self> {
        let write_txn = db.begin_write()?;
        {
            let _ = write_txn.open_table(CHAIN_META)?;
            let _ = write_txn.open_table(VALIDATOR_SETS)?;
            let _ = write_txn.open_table(CHECKPOINTS)?;
        }
        write_txn.commit()?;

        Ok(Self { db })
    }

    /// Save chain metadata
    pub fn save_meta(&self, meta: &ChainMeta) -> StorageResult<()> {
        let encoded = bincode::serialize(meta)?;

        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(CHAIN_META)?;
            table.insert("chain_meta", encoded.as_slice())?;
        }
        write_txn.commit()?;

        Ok(())
    }

    /// Get chain metadata
    pub fn get_meta(&self) -> StorageResult<Option<ChainMeta>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(CHAIN_META)?;

        let result = match table.get("chain_meta")? {
            Some(data) => {
                let bytes = data.value().to_vec();
                Some(bincode::deserialize(&bytes)?)
            }
            None => None,
        };

        Ok(result)
    }

    /// Update finalized block
    pub fn update_finalized(&self, height: u64, hash: [u8; 32]) -> StorageResult<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(CHAIN_META)?;
            table.insert("finalized_height", &height.to_le_bytes()[..])?;
            table.insert("finalized_hash", hash.as_slice())?;
        }
        write_txn.commit()?;

        Ok(())
    }

    /// Get finalized height
    pub fn get_finalized_height(&self) -> StorageResult<Option<u64>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(CHAIN_META)?;

        let result = match table.get("finalized_height")? {
            Some(data) => {
                let bytes = data.value().to_vec();
                let arr: [u8; 8] = bytes.try_into().map_err(|_| {
                    StorageError::InvalidData("Invalid height bytes".into())
                })?;
                Some(u64::from_le_bytes(arr))
            }
            None => None,
        };

        Ok(result)
    }

    /// Save validator set for epoch
    pub fn save_validator_set(&self, set: &ValidatorSet) -> StorageResult<()> {
        let encoded = bincode::serialize(set)?;

        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(VALIDATOR_SETS)?;
            table.insert(set.epoch, encoded.as_slice())?;
        }
        write_txn.commit()?;

        Ok(())
    }

    /// Get validator set for epoch
    pub fn get_validator_set(&self, epoch: u64) -> StorageResult<Option<ValidatorSet>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(VALIDATOR_SETS)?;

        let result = match table.get(epoch)? {
            Some(data) => {
                let bytes = data.value().to_vec();
                Some(bincode::deserialize(&bytes)?)
            }
            None => None,
        };

        Ok(result)
    }

    /// Get latest validator set
    pub fn get_latest_validator_set(&self) -> StorageResult<Option<ValidatorSet>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(VALIDATOR_SETS)?;
        let mut iter = table.iter()?;
        let last = iter.next_back();

        let result = match last.transpose()? {
            Some((_, data)) => {
                let bytes = data.value().to_vec();
                Some(bincode::deserialize(&bytes)?)
            }
            None => None,
        };

        Ok(result)
    }

    /// Save checkpoint
    pub fn save_checkpoint(&self, checkpoint: &Checkpoint) -> StorageResult<()> {
        let encoded = bincode::serialize(checkpoint)?;

        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(CHECKPOINTS)?;
            table.insert(checkpoint.height, encoded.as_slice())?;
        }
        write_txn.commit()?;

        Ok(())
    }

    /// Get checkpoint by height
    pub fn get_checkpoint(&self, height: u64) -> StorageResult<Option<Checkpoint>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(CHECKPOINTS)?;

        let result = match table.get(height)? {
            Some(data) => {
                let bytes = data.value().to_vec();
                Some(bincode::deserialize(&bytes)?)
            }
            None => None,
        };

        Ok(result)
    }

    /// Get latest checkpoint
    pub fn get_latest_checkpoint(&self) -> StorageResult<Option<Checkpoint>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(CHECKPOINTS)?;
        let mut iter = table.iter()?;
        let last = iter.next_back();

        let result = match last.transpose()? {
            Some((_, data)) => {
                let bytes = data.value().to_vec();
                Some(bincode::deserialize(&bytes)?)
            }
            None => None,
        };

        Ok(result)
    }

    /// Get checkpoints in range
    pub fn get_checkpoints_range(
        &self,
        start_height: u64,
        end_height: u64,
    ) -> StorageResult<Vec<Checkpoint>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(CHECKPOINTS)?;
        let bytes_list: Vec<Vec<u8>> = table.range(start_height..=end_height)?
            .filter_map(|r| r.ok())
            .map(|(_, data)| data.value().to_vec())
            .collect();
        drop(table);
        drop(read_txn);

        let mut checkpoints = Vec::new();
        for bytes in bytes_list {
            let cp: Checkpoint = bincode::deserialize(&bytes)?;
            checkpoints.push(cp);
        }

        Ok(checkpoints)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_chain_meta() {
        let dir = tempdir().unwrap();
        let db = Database::create(dir.path().join("test.db")).unwrap();
        let store = ChainStore::new(Arc::new(db)).unwrap();

        let meta = ChainMeta {
            genesis_hash: [1u8; 32],
            network_id: "testnet".to_string(),
            chain_id: 1337,
            genesis_timestamp: 1000000,
            current_epoch: 5,
            current_round: 42,
            finalized_height: 500,
            finalized_hash: [2u8; 32],
            current_height: 510,
        };

        store.save_meta(&meta).unwrap();

        let retrieved = store.get_meta().unwrap().unwrap();
        assert_eq!(retrieved.chain_id, 1337);
        assert_eq!(retrieved.network_id, "testnet");
    }

    #[test]
    fn test_validator_sets() {
        let dir = tempdir().unwrap();
        let db = Database::create(dir.path().join("test.db")).unwrap();
        let store = ChainStore::new(Arc::new(db)).unwrap();

        let set = ValidatorSet {
            epoch: 1,
            validators: vec![ValidatorEntry {
                id: [1u8; 32],
                public_key: vec![2u8; 64],
                stake: 10000,
                commission: 500, // 5%
                active: true,
            }],
            total_stake: 10000,
        };

        store.save_validator_set(&set).unwrap();

        let retrieved = store.get_validator_set(1).unwrap().unwrap();
        assert_eq!(retrieved.validators.len(), 1);
        assert_eq!(retrieved.total_stake, 10000);
    }

    #[test]
    fn test_checkpoints() {
        let dir = tempdir().unwrap();
        let db = Database::create(dir.path().join("test.db")).unwrap();
        let store = ChainStore::new(Arc::new(db)).unwrap();

        for height in [100, 200, 300] {
            let cp = Checkpoint {
                height,
                epoch: height / 100,
                round: 0,
                block_hash: [height as u8; 32],
                state_root: [0u8; 32],
                validator_set_hash: [0u8; 32],
                timestamp: 1000000 + height,
            };
            store.save_checkpoint(&cp).unwrap();
        }

        let latest = store.get_latest_checkpoint().unwrap().unwrap();
        assert_eq!(latest.height, 300);

        let range = store.get_checkpoints_range(100, 200).unwrap();
        assert_eq!(range.len(), 2);
    }

    #[test]
    fn test_finalized_updates() {
        let dir = tempdir().unwrap();
        let db = Database::create(dir.path().join("test.db")).unwrap();
        let store = ChainStore::new(Arc::new(db)).unwrap();

        store.update_finalized(100, [1u8; 32]).unwrap();
        assert_eq!(store.get_finalized_height().unwrap(), Some(100));

        store.update_finalized(200, [2u8; 32]).unwrap();
        assert_eq!(store.get_finalized_height().unwrap(), Some(200));
    }
}
