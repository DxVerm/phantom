//! Transaction storage

use std::sync::Arc;
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use crate::StorageResult;

/// Table for transactions by hash
const TRANSACTIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("transactions");

/// Table for transaction index (hash -> block height, index)
const TX_INDEX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("tx_index");

/// Table for transactions by sender
const TX_BY_SENDER: TableDefinition<&[u8], &[u8]> = TableDefinition::new("tx_by_sender");

/// Stored transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredTransaction {
    /// Transaction hash
    pub hash: [u8; 32],
    /// Sender address (encrypted)
    pub sender: Vec<u8>,
    /// Recipient address (encrypted)
    pub recipient: Vec<u8>,
    /// Amount (encrypted)
    pub amount_encrypted: Vec<u8>,
    /// Fee
    pub fee: u64,
    /// Nonce
    pub nonce: u64,
    /// Timestamp
    pub timestamp: u64,
    /// Zero-knowledge proof
    pub proof: Vec<u8>,
    /// PQ signature
    pub signature: Vec<u8>,
    /// Transaction type
    pub tx_type: TransactionType,
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

/// Transaction location in a block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionLocation {
    pub block_height: u64,
    pub tx_index: u32,
}

/// Transaction receipt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionReceipt {
    pub tx_hash: [u8; 32],
    pub block_height: u64,
    pub tx_index: u32,
    pub success: bool,
    pub gas_used: u64,
    pub logs: Vec<TransactionLog>,
}

/// Transaction log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionLog {
    pub contract: [u8; 32],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

/// Transaction storage interface
pub struct TransactionStore {
    db: Arc<Database>,
}

impl TransactionStore {
    /// Create new transaction store
    pub fn new(db: Arc<Database>) -> StorageResult<Self> {
        let write_txn = db.begin_write()?;
        {
            let _ = write_txn.open_table(TRANSACTIONS)?;
            let _ = write_txn.open_table(TX_INDEX)?;
            let _ = write_txn.open_table(TX_BY_SENDER)?;
        }
        write_txn.commit()?;

        Ok(Self { db })
    }

    /// Store a transaction
    pub fn put(&self, tx: &StoredTransaction, location: &TransactionLocation) -> StorageResult<()> {
        let tx_encoded = bincode::serialize(tx)?;
        let loc_encoded = bincode::serialize(location)?;

        // First read existing sender txs
        let read_txn = self.db.begin_read()?;
        let by_sender_table = read_txn.open_table(TX_BY_SENDER)?;
        let sender_key = &tx.sender[..];
        let existing_sender_txs: Vec<[u8; 32]> = match by_sender_table.get(sender_key)? {
            Some(data) => {
                let bytes = data.value().to_vec();
                bincode::deserialize(&bytes).unwrap_or_default()
            }
            None => Vec::new(),
        };
        drop(by_sender_table);
        drop(read_txn);

        let write_txn = self.db.begin_write()?;
        {
            let mut txs = write_txn.open_table(TRANSACTIONS)?;
            let mut index = write_txn.open_table(TX_INDEX)?;
            let mut by_sender = write_txn.open_table(TX_BY_SENDER)?;

            txs.insert(tx.hash.as_slice(), tx_encoded.as_slice())?;
            index.insert(tx.hash.as_slice(), loc_encoded.as_slice())?;

            // Index by sender (store list of tx hashes)
            let sender_key = &tx.sender[..];
            let mut sender_txs = existing_sender_txs;
            sender_txs.push(tx.hash);
            let sender_txs_encoded = bincode::serialize(&sender_txs)?;
            by_sender.insert(sender_key, sender_txs_encoded.as_slice())?;
        }
        write_txn.commit()?;

        Ok(())
    }

    /// Store multiple transactions in a batch
    pub fn put_batch(
        &self,
        transactions: &[(StoredTransaction, TransactionLocation)],
    ) -> StorageResult<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut txs = write_txn.open_table(TRANSACTIONS)?;
            let mut index = write_txn.open_table(TX_INDEX)?;

            for (tx, location) in transactions {
                let tx_encoded = bincode::serialize(tx)?;
                let loc_encoded = bincode::serialize(location)?;

                txs.insert(tx.hash.as_slice(), tx_encoded.as_slice())?;
                index.insert(tx.hash.as_slice(), loc_encoded.as_slice())?;
            }
        }
        write_txn.commit()?;

        Ok(())
    }

    /// Get transaction by hash
    pub fn get(&self, hash: &[u8; 32]) -> StorageResult<Option<StoredTransaction>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(TRANSACTIONS)?;

        let result = match table.get(hash.as_slice())? {
            Some(data) => {
                let bytes = data.value().to_vec();
                Some(bincode::deserialize(&bytes)?)
            }
            None => None,
        };

        Ok(result)
    }

    /// Get transaction location
    pub fn get_location(&self, hash: &[u8; 32]) -> StorageResult<Option<TransactionLocation>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(TX_INDEX)?;

        let result = match table.get(hash.as_slice())? {
            Some(data) => {
                let bytes = data.value().to_vec();
                Some(bincode::deserialize(&bytes)?)
            }
            None => None,
        };

        Ok(result)
    }

    /// Get transactions by sender
    pub fn get_by_sender(&self, sender: &[u8]) -> StorageResult<Vec<StoredTransaction>> {
        // First get the list of hashes for this sender
        let read_txn = self.db.begin_read()?;
        let by_sender = read_txn.open_table(TX_BY_SENDER)?;
        let hashes: Vec<[u8; 32]> = match by_sender.get(sender)? {
            Some(data) => {
                let bytes = data.value().to_vec();
                bincode::deserialize(&bytes).unwrap_or_default()
            }
            None => return Ok(Vec::new()),
        };
        drop(by_sender);
        drop(read_txn);

        // Then fetch each transaction
        let mut result = Vec::new();
        for hash in hashes {
            let read_txn = self.db.begin_read()?;
            let txs_table = read_txn.open_table(TRANSACTIONS)?;
            let tx_opt = match txs_table.get(hash.as_slice())? {
                Some(data) => {
                    let bytes = data.value().to_vec();
                    Some(bincode::deserialize::<StoredTransaction>(&bytes)?)
                }
                None => None,
            };
            drop(txs_table);
            drop(read_txn);

            if let Some(tx) = tx_opt {
                result.push(tx);
            }
        }

        Ok(result)
    }

    /// Check if transaction exists
    pub fn exists(&self, hash: &[u8; 32]) -> StorageResult<bool> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(TRANSACTIONS)?;
        let exists = table.get(hash.as_slice())?.is_some();
        Ok(exists)
    }

    /// Get total transaction count
    pub fn count(&self) -> StorageResult<u64> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(TRANSACTIONS)?;
        let len = table.len()?;
        Ok(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn create_test_tx(nonce: u64) -> StoredTransaction {
        let mut hash = [0u8; 32];
        hash[0..8].copy_from_slice(&nonce.to_le_bytes());

        StoredTransaction {
            hash,
            sender: vec![1u8; 32],
            recipient: vec![2u8; 32],
            amount_encrypted: vec![3u8; 64],
            fee: 100,
            nonce,
            timestamp: 1000000 + nonce,
            proof: vec![4u8; 128],
            signature: vec![5u8; 64],
            tx_type: TransactionType::Transfer,
        }
    }

    #[test]
    fn test_transaction_store() {
        let dir = tempdir().unwrap();
        let db = Database::create(dir.path().join("test.db")).unwrap();
        let store = TransactionStore::new(Arc::new(db)).unwrap();

        let tx = create_test_tx(1);
        let location = TransactionLocation {
            block_height: 100,
            tx_index: 0,
        };

        store.put(&tx, &location).unwrap();

        let retrieved = store.get(&tx.hash).unwrap().unwrap();
        assert_eq!(retrieved.nonce, 1);

        let loc = store.get_location(&tx.hash).unwrap().unwrap();
        assert_eq!(loc.block_height, 100);

        assert!(store.exists(&tx.hash).unwrap());
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn test_batch_insert() {
        let dir = tempdir().unwrap();
        let db = Database::create(dir.path().join("test.db")).unwrap();
        let store = TransactionStore::new(Arc::new(db)).unwrap();

        let batch: Vec<_> = (0..100)
            .map(|i| {
                let tx = create_test_tx(i);
                let loc = TransactionLocation {
                    block_height: 1,
                    tx_index: i as u32,
                };
                (tx, loc)
            })
            .collect();

        store.put_batch(&batch).unwrap();
        assert_eq!(store.count().unwrap(), 100);
    }

    #[test]
    fn test_get_by_sender() {
        let dir = tempdir().unwrap();
        let db = Database::create(dir.path().join("test.db")).unwrap();
        let store = TransactionStore::new(Arc::new(db)).unwrap();

        for i in 0..5 {
            let tx = create_test_tx(i);
            let location = TransactionLocation {
                block_height: 1,
                tx_index: i as u32,
            };
            store.put(&tx, &location).unwrap();
        }

        let sender = vec![1u8; 32];
        let txs = store.get_by_sender(&sender).unwrap();
        assert_eq!(txs.len(), 5);
    }
}
