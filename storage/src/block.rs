//! Block storage

use std::sync::Arc;
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use crate::StorageResult;

/// Table for blocks by height
const BLOCKS_BY_HEIGHT: TableDefinition<u64, &[u8]> = TableDefinition::new("blocks_by_height");

/// Table for block hashes by height
const BLOCK_HASHES: TableDefinition<u64, &[u8]> = TableDefinition::new("block_hashes");

/// Table for height by block hash
const HEIGHT_BY_HASH: TableDefinition<&[u8], u64> = TableDefinition::new("height_by_hash");

/// Stored block header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredBlockHeader {
    /// Block height
    pub height: u64,
    /// Block hash
    pub hash: [u8; 32],
    /// Previous block hash
    pub prev_hash: [u8; 32],
    /// State root after this block
    pub state_root: [u8; 32],
    /// Transactions root
    pub tx_root: [u8; 32],
    /// Block timestamp
    pub timestamp: u64,
    /// Block producer
    pub producer: [u8; 32],
    /// Attestation count
    pub attestation_count: u32,
}

/// Stored block body
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredBlockBody {
    /// Transactions (encrypted bytes)
    pub transactions: Vec<StoredTransaction>,
}

/// Stored transaction (minimal for block body)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredTransaction {
    /// Transaction hash
    pub hash: [u8; 32],
    /// Transaction type
    pub tx_type: TransactionType,
    /// Encrypted sender
    pub encrypted_sender: Vec<u8>,
    /// Encrypted receiver
    pub encrypted_receiver: Vec<u8>,
    /// Encrypted amount
    pub encrypted_amount: Vec<u8>,
    /// Encrypted memo
    pub encrypted_memo: Option<Vec<u8>>,
    /// Fee
    pub fee: u64,
    /// Nonce
    pub nonce: u64,
    /// Zero-knowledge proof
    pub proof: Vec<u8>,
    /// Signature
    pub signature: Vec<u8>,
    /// Timestamp
    pub timestamp: u64,
    /// Block height (if included)
    pub block_height: Option<u64>,
}

/// Transaction type
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransactionType {
    /// Value transfer
    Transfer,
    /// Contract deployment
    Deploy,
    /// Contract call
    Call,
    /// Stake delegation
    Stake,
    /// Stake withdrawal
    Unstake,
    /// Validator registration
    RegisterValidator,
}

/// Full stored block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredBlock {
    pub header: StoredBlockHeader,
    pub body: StoredBlockBody,
}

impl StoredBlock {
    /// Compute block hash
    pub fn hash(&self) -> [u8; 32] {
        let data = bincode::serialize(&self.header).unwrap_or_default();
        blake3::hash(&data).into()
    }
}

/// Block storage interface
pub struct BlockStore {
    db: Arc<Database>,
}

impl BlockStore {
    /// Create new block store
    pub fn new(db: Arc<Database>) -> StorageResult<Self> {
        // Initialize tables
        let write_txn = db.begin_write()?;
        {
            let _ = write_txn.open_table(BLOCKS_BY_HEIGHT)?;
            let _ = write_txn.open_table(BLOCK_HASHES)?;
            let _ = write_txn.open_table(HEIGHT_BY_HASH)?;
        }
        write_txn.commit()?;

        Ok(Self { db })
    }

    /// Store a block
    pub fn put(&self, block: &StoredBlock) -> StorageResult<()> {
        let height = block.header.height;
        let hash = block.hash();
        let encoded = bincode::serialize(block)?;

        let write_txn = self.db.begin_write()?;
        {
            let mut blocks = write_txn.open_table(BLOCKS_BY_HEIGHT)?;
            let mut hashes = write_txn.open_table(BLOCK_HASHES)?;
            let mut heights = write_txn.open_table(HEIGHT_BY_HASH)?;

            blocks.insert(height, encoded.as_slice())?;
            hashes.insert(height, hash.as_slice())?;
            heights.insert(hash.as_slice(), height)?;
        }
        write_txn.commit()?;

        Ok(())
    }

    /// Get block by height
    pub fn get(&self, height: u64) -> StorageResult<Option<StoredBlock>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(BLOCKS_BY_HEIGHT)?;

        let result = match table.get(height)? {
            Some(data) => {
                let bytes = data.value().to_vec();
                Some(bincode::deserialize(&bytes)?)
            }
            None => None,
        };

        Ok(result)
    }

    /// Get block by hash
    pub fn get_by_hash(&self, hash: &[u8; 32]) -> StorageResult<Option<StoredBlock>> {
        let read_txn = self.db.begin_read()?;
        let heights = read_txn.open_table(HEIGHT_BY_HASH)?;

        let height_opt = match heights.get(hash.as_slice())? {
            Some(h) => Some(h.value()),
            None => None,
        };
        drop(heights);
        drop(read_txn);

        match height_opt {
            Some(h) => self.get(h),
            None => Ok(None),
        }
    }

    /// Get block hash by height
    pub fn get_hash(&self, height: u64) -> StorageResult<Option<[u8; 32]>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(BLOCK_HASHES)?;

        let result = match table.get(height)? {
            Some(data) => {
                let bytes = data.value();
                let mut hash = [0u8; 32];
                hash.copy_from_slice(bytes);
                Some(hash)
            }
            None => None,
        };

        Ok(result)
    }

    /// Get latest block height
    pub fn latest_height(&self) -> StorageResult<Option<u64>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(BLOCKS_BY_HEIGHT)?;
        let mut iter = table.iter()?;
        let last = iter.next_back();
        let height_opt = last.transpose()?.map(|(key, _)| key.value());
        Ok(height_opt)
    }

    /// Get total block count
    pub fn count(&self) -> StorageResult<u64> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(BLOCKS_BY_HEIGHT)?;
        let len = table.len()?;
        Ok(len)
    }

    /// Get blocks in height range
    pub fn get_range(&self, start: u64, end: u64) -> StorageResult<Vec<StoredBlock>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(BLOCKS_BY_HEIGHT)?;
        let bytes_list: Vec<Vec<u8>> = table.range(start..=end)?
            .filter_map(|r| r.ok())
            .map(|(_, data)| data.value().to_vec())
            .collect();
        drop(table);
        drop(read_txn);

        let mut blocks = Vec::new();
        for bytes in bytes_list {
            let block: StoredBlock = bincode::deserialize(&bytes)?;
            blocks.push(block);
        }

        Ok(blocks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn create_test_block(height: u64) -> StoredBlock {
        StoredBlock {
            header: StoredBlockHeader {
                height,
                hash: [height as u8; 32],
                prev_hash: [0u8; 32],
                state_root: [1u8; 32],
                tx_root: [2u8; 32],
                timestamp: 1000 + height,
                producer: [3u8; 32],
                attestation_count: 3,
            },
            body: StoredBlockBody {
                transactions: vec![],
            },
        }
    }

    #[test]
    fn test_block_store() {
        let dir = tempdir().unwrap();
        let db = Database::create(dir.path().join("test.db")).unwrap();
        let store = BlockStore::new(Arc::new(db)).unwrap();

        let block = create_test_block(1);
        store.put(&block).unwrap();

        let retrieved = store.get(1).unwrap().unwrap();
        assert_eq!(retrieved.header.height, 1);

        assert_eq!(store.count().unwrap(), 1);
        assert_eq!(store.latest_height().unwrap(), Some(1));
    }

    #[test]
    fn test_block_by_hash() {
        let dir = tempdir().unwrap();
        let db = Database::create(dir.path().join("test.db")).unwrap();
        let store = BlockStore::new(Arc::new(db)).unwrap();

        let block = create_test_block(1);
        let hash = block.hash();
        store.put(&block).unwrap();

        let retrieved = store.get_by_hash(&hash).unwrap().unwrap();
        assert_eq!(retrieved.header.height, 1);
    }

    #[test]
    fn test_block_range() {
        let dir = tempdir().unwrap();
        let db = Database::create(dir.path().join("test.db")).unwrap();
        let store = BlockStore::new(Arc::new(db)).unwrap();

        for i in 1..=10 {
            store.put(&create_test_block(i)).unwrap();
        }

        let range = store.get_range(3, 7).unwrap();
        assert_eq!(range.len(), 5);
        assert_eq!(range[0].header.height, 3);
        assert_eq!(range[4].header.height, 7);
    }
}
