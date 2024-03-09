//! This module implements a key-value storage system called LedgerKV.
//!
//! The LedgerKV struct provides methods for inserting, deleting, and retrieving key-value entries.
//! It journals the entries in a binary file. Each entry is appended to the file along with its
//! length, allowing efficient retrieval and updates.
//!
//! The LedgerKV struct maintains an in-memory index of the entries for quick lookups. It uses a HashMap
//! to store the entries, where the key is an enum value representing the label of the entry, and the value
//! is an IndexMap of key-value pairs.
//!
//! The LedgerKV struct also maintains a metadata file that keeps track of the number of entries, the last offset,
//! and the parent hash of the entries. The parent hash is used to compute the cumulative hash of each entry,
//! ensuring data integrity.
//!
//! The LedgerKV struct provides methods for inserting and deleting entries, as well as iterating over the entries
//! by label or in raw form. It also supports re-reading the in-memory index and metadata from the binary file.
//!
//! Entries of LedgerKV are stored in blocks. Each block contains a vector of entries, and the block is committed
//! to the binary file when the user calls the commit_block method. A block also contains metadata such as the
//! offset of block in the persistent storage, the timestamp, and the parent hash.
//!
//! Example usage:
//!
//! ```rust
//! use std::path::PathBuf;
//! use ledger_kv::{platform_specific, LedgerKV, Operation};
//! use borsh::{BorshDeserialize, BorshSerialize};
//!
//! // Optional: Override the backing file path
//! // let ledger_path = PathBuf::from("/tmp/ledger_kv/test_data.bin");
//! // platform_specific::override_backing_file(Some(ledger_path));
//!
//! // Create a new LedgerKV instance
//! let mut ledger_kv = LedgerKV::new().expect("Failed to create LedgerKV");
//!
//! // Insert a few new entries, each with a separate label
//! ledger_kv.upsert("Label1", b"key1".to_vec(), b"value1".to_vec()).unwrap();
//! ledger_kv.upsert("Label2", b"key2".to_vec(), b"value2".to_vec()).unwrap();
//! ledger_kv.commit_block().unwrap();
//!
//! // Retrieve all entries
//! let entries = ledger_kv.iter(None).collect::<Vec<_>>();
//! println!("All entries: {:?}", entries);
//! // Only entries with the Label1 label
//! let entries = ledger_kv.iter(Some("Label1")).collect::<Vec<_>>();
//! println!("Label1 entries: {:?}", entries);
//! // Only entries with the Label2 label
//! let entries = ledger_kv.iter(Some("Label2")).collect::<Vec<_>>();
//! println!("Label2 entries: {:?}", entries);
//!
//! // Delete an entry
//! ledger_kv.delete("Label1", b"key1".to_vec()).unwrap();
//! ledger_kv.commit_block().unwrap();
//! // Label1 entries are now empty
//! assert_eq!(ledger_kv.iter(Some("Label1")).count(), 0);
//! // Label2 entries still exist
//! assert_eq!(ledger_kv.iter(Some("Label2")).count(), 1);
//! ```

#[cfg(target_arch = "wasm32")]
pub mod platform_specific_wasm32;
#[cfg(target_arch = "wasm32")]
use ic_cdk::println;
#[cfg(target_arch = "wasm32")]
pub use platform_specific_wasm32 as platform_specific;

#[cfg(target_arch = "x86_64")]
pub mod platform_specific_x86_64;
#[cfg(target_arch = "x86_64")]
pub use platform_specific::{debug, error, info, warn};
#[cfg(target_arch = "x86_64")]
pub use platform_specific_x86_64 as platform_specific;

pub mod ledger_entry;
pub mod partition_table;

use crate::platform_specific::{
    persistent_storage_read64, persistent_storage_size_bytes, persistent_storage_write64,
};
#[cfg(target_arch = "x86_64")]
pub use platform_specific::override_backing_file;
pub use platform_specific::{export_debug, export_error, export_info, export_warn};

use borsh::{to_vec, BorshDeserialize, BorshSerialize};
use indexmap::IndexMap;
pub use ledger_entry::{EntryKey, EntryValue, LedgerBlock, LedgerEntry, Operation};
use sha2::{Digest, Sha256};
use std::{cell::RefCell, fmt::Debug};

/// Struct representing the metadata of the ledger.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub(crate) struct Metadata {
    /// The number of blocks in the ledger so far.
    pub(crate) num_blocks: usize,
    /// The chain hash of the entire ledger, to be used as the initial hash of the next block.
    pub(crate) last_block_chain_hash: Vec<u8>,
    /// The offset in the persistent storage where the next block will be written.
    pub(crate) next_block_write_position: u64,
}

impl Default for Metadata {
    fn default() -> Self {
        debug!(
            "next_write_position: 0x{:0x}",
            partition_table::get_data_partition().start_lba
        );
        Metadata {
            num_blocks: 0,
            last_block_chain_hash: Vec::new(),
            next_block_write_position: partition_table::get_data_partition().start_lba,
        }
    }
}

impl Metadata {
    pub fn new() -> Self {
        Metadata::default()
    }

    pub fn clear(&mut self) {
        self.num_blocks = 0;
        self.last_block_chain_hash = Vec::new();
        self.next_block_write_position = partition_table::get_data_partition().start_lba;
    }

    pub fn append_block(
        &mut self,
        parent_hash: &[u8],
        next_block_write_position: u64,
    ) -> anyhow::Result<()> {
        self.num_blocks += 1;
        self.last_block_chain_hash = parent_hash.to_vec();
        self.next_block_write_position = next_block_write_position;
        Ok(())
    }

    fn get_last_block_chain_hash(&self) -> &[u8] {
        self.last_block_chain_hash.as_slice()
    }
}

#[derive(Debug)]
pub struct LedgerKV {
    metadata: RefCell<Metadata>,
    entries: IndexMap<String, IndexMap<EntryKey, LedgerEntry>>,
    next_block_entries: IndexMap<String, IndexMap<EntryKey, LedgerEntry>>,
    current_timestamp_nanos: fn() -> u64,
}

enum ErrorBlockRead {
    Empty,
    Corrupted(anyhow::Error),
}

impl LedgerKV {
    pub fn new() -> anyhow::Result<Self> {
        LedgerKV {
            metadata: RefCell::new(Metadata::new()),
            entries: IndexMap::new(),
            next_block_entries: IndexMap::new(),
            current_timestamp_nanos: platform_specific::get_timestamp_nanos,
        }
        .refresh_ledger()
    }

    #[cfg(test)]
    fn with_timestamp_fn(self, get_timestamp_nanos: fn() -> u64) -> Self {
        LedgerKV {
            current_timestamp_nanos: get_timestamp_nanos,
            ..self
        }
    }

    fn _compute_block_chain_hash(
        last_block_chain_hash: &[u8],
        block_entries: &[LedgerEntry],
        block_timestamp: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let mut hasher = Sha256::new();
        hasher.update(last_block_chain_hash);
        for entry in block_entries.iter() {
            hasher.update(to_vec(entry)?);
        }
        hasher.update(block_timestamp.to_le_bytes());
        Ok(hasher.finalize().to_vec())
    }

    fn _journal_append_block(&self, ledger_block: LedgerBlock) -> anyhow::Result<()> {
        // Prepare entry as serialized bytes
        let serialized_data = to_vec(&ledger_block)?;
        info!(
            "Appending block @timestamp {} with {} bytes: {}",
            ledger_block.timestamp,
            serialized_data.len(),
            ledger_block,
        );
        // Prepare entry len, as bytes
        let block_len_bytes: u32 = serialized_data.len() as u32;
        let serialized_data_len = block_len_bytes.to_le_bytes();

        info!(
            "entry_len_bytes {} serialized_data_len: {:?} serialized_data: {:?}",
            block_len_bytes, serialized_data_len, serialized_data
        );
        persistent_storage_write64(
            self.metadata.borrow().next_block_write_position as u64,
            &serialized_data_len,
        );
        persistent_storage_write64(
            self.metadata.borrow().next_block_write_position as u64
                + serialized_data_len.len() as u64,
            &serialized_data,
        );

        let next_write_position = self.metadata.borrow().next_block_write_position
            + serialized_data_len.len() as u64
            + serialized_data.len() as u64;
        self.metadata
            .borrow_mut()
            .append_block(&ledger_block.hash, next_write_position)
    }

    fn _journal_read_block(&self, offset: u64) -> Result<LedgerBlock, ErrorBlockRead> {
        // Find out how many bytes we need to read ==> block len in bytes
        let mut buf = [0u8; std::mem::size_of::<u32>()];
        persistent_storage_read64(offset, &mut buf)
            .map_err(|err| ErrorBlockRead::Corrupted(err))?;
        let block_len: u32 = u32::from_le_bytes(buf);
        debug!("read bytes: {:?}", buf);
        debug!("block_len: {}", block_len);

        if block_len == 0 {
            return Err(ErrorBlockRead::Empty);
        }

        debug!(
            "Reading journal block of {} bytes at offset 0x{:0x}",
            block_len, offset
        );

        // Read the block as raw bytes
        let mut buf = vec![0u8; block_len as usize];
        persistent_storage_read64(offset + std::mem::size_of::<u32>() as u64, &mut buf)
            .map_err(|err| ErrorBlockRead::Corrupted(err))?;
        match LedgerBlock::deserialize(&mut buf.as_ref())
            .map_err(|err| ErrorBlockRead::Corrupted(err.into()))
        {
            Ok(mut block) => {
                block.offset_next =
                    Some(offset + std::mem::size_of::<u32>() as u64 + block_len as u64);
                Ok(block)
            }
            Err(err) => Err(err),
        }
    }

    pub fn begin_block(&mut self) -> anyhow::Result<()> {
        if !&self.next_block_entries.is_empty() {
            return Err(anyhow::format_err!("There is already an open transaction."));
        } else {
            self.next_block_entries.clear();
        }
        Ok(())
    }

    pub fn commit_block(&mut self) -> anyhow::Result<()> {
        if self.next_block_entries.is_empty() {
            debug!("Commit of empty block invoked, skipping");
        } else {
            info!(
                "Commit non-empty block, with {} entries",
                self.next_block_entries.len()
            );
            let mut block_entries = Vec::new();
            for (label, values) in self.next_block_entries.iter() {
                self.entries
                    .entry(label.clone())
                    .or_default()
                    .extend(values.clone());
                for (_key, entry) in values.iter() {
                    block_entries.push(entry.clone());
                }
            }
            let block_timestamp = (self.current_timestamp_nanos)();
            let hash = Self::_compute_block_chain_hash(
                self.metadata.borrow().get_last_block_chain_hash(),
                &block_entries,
                block_timestamp,
            )?;
            let block = LedgerBlock::new(
                block_entries,
                self.metadata.borrow().next_block_write_position,
                None,
                block_timestamp,
                hash,
            );
            self._journal_append_block(block)?;
            self.next_block_entries.clear();
        }
        Ok(())
    }

    pub fn get<S: AsRef<str>>(&self, label: S, key: &EntryKey) -> anyhow::Result<EntryValue> {
        fn lookup<'a>(
            map: &'a IndexMap<String, IndexMap<EntryKey, LedgerEntry>>,
            label: &String,
            key: &EntryKey,
        ) -> Option<&'a LedgerEntry> {
            match map.get(label) {
                Some(entries) => entries.get(key),
                None => None,
            }
        }

        let label = label.as_ref().to_string();
        for map in [&self.next_block_entries, &self.entries] {
            if let Some(entry) = lookup(map, &label, key) {
                match entry.operation {
                    Operation::Upsert => {
                        return Ok(entry.value.clone());
                    }
                    Operation::Delete => {
                        return Err(anyhow::format_err!("Entry not found"));
                    }
                }
            }
        }

        Err(anyhow::format_err!("Entry not found"))
    }

    fn _insert_entry_into_next_block(
        &mut self,
        label: String,
        key: EntryKey,
        value: EntryValue,
        operation: Operation,
    ) -> anyhow::Result<()> {
        let entry = LedgerEntry::new(label.clone(), key, value, operation);
        match self.next_block_entries.get_mut(&entry.label) {
            Some(entries) => {
                entries.insert(entry.key.clone(), entry);
            }
            None => {
                let mut new_map = IndexMap::new();
                new_map.insert(entry.key.clone(), entry);
                self.next_block_entries.insert(label, new_map);
            }
        };

        Ok(())
    }

    pub fn upsert<S: AsRef<str>>(
        &mut self,
        label: S,
        key: EntryKey,
        value: EntryValue,
    ) -> anyhow::Result<()> {
        self._insert_entry_into_next_block(
            label.as_ref().to_string(),
            key,
            value,
            Operation::Upsert,
        )
    }

    pub fn delete<S: AsRef<str>>(&mut self, label: S, key: EntryKey) -> anyhow::Result<()> {
        self._insert_entry_into_next_block(
            label.as_ref().to_string(),
            key,
            Vec::new(),
            Operation::Delete,
        )
    }

    pub fn refresh_ledger(mut self) -> anyhow::Result<LedgerKV> {
        self.metadata.borrow_mut().clear();
        self.entries.clear();
        self.next_block_entries.clear();

        // If the backend is empty or non-existing, just return
        if persistent_storage_size_bytes() == 0 {
            warn!("Persistent storage is empty");
            return Ok(self);
        }

        let data_part_entry = partition_table::get_data_partition();
        if persistent_storage_size_bytes() < data_part_entry.start_lba {
            warn!("No data found in persistent storage");
            return Ok(self);
        }

        let mut parent_hash = Vec::new();
        let mut updates = Vec::new();
        // Step 1: Read all Ledger Blocks
        for ledger_block in self.iter_raw() {
            let ledger_block = ledger_block?;

            let expected_hash = Self::_compute_block_chain_hash(
                &parent_hash,
                &ledger_block.entries,
                ledger_block.timestamp,
            )?;
            if ledger_block.hash != expected_hash {
                return Err(anyhow::format_err!(
                    "Hash mismatch: expected {:?}, got {:?}",
                    expected_hash,
                    ledger_block.hash
                ));
            };

            parent_hash.clear();
            parent_hash.extend_from_slice(&ledger_block.hash);

            self.metadata.borrow_mut().append_block(
                parent_hash.as_slice(),
                ledger_block.offset_next.expect("offset must be set"),
            )?;

            updates.push(ledger_block);
        }

        // Step 2: Processing the collected data
        for ledger_block in updates.into_iter() {
            for ledger_entry in ledger_block.entries.iter() {
                let entries = match self.entries.get_mut(ledger_entry.label.as_str()) {
                    Some(entries) => entries,
                    None => {
                        let new_map = IndexMap::new();
                        self.entries.insert(ledger_entry.label.clone(), new_map);
                        self.entries
                            .get_mut(&ledger_entry.label)
                            .ok_or(anyhow::format_err!(
                                "Entry label {:?} not found",
                                ledger_entry.label
                            ))?
                    }
                };

                match &ledger_entry.operation {
                    Operation::Upsert => {
                        entries.insert(ledger_entry.key.clone(), ledger_entry.clone());
                    }
                    Operation::Delete => {
                        entries.swap_remove(&ledger_entry.key);
                    }
                }
            }
        }

        Ok(self)
    }

    pub fn iter(&self, label: Option<&str>) -> impl Iterator<Item = &LedgerEntry> {
        match label {
            Some(label) => self
                .entries
                .get(label)
                .map(|entries| entries.values())
                .unwrap_or_default()
                .filter(|entry| entry.operation == Operation::Upsert)
                .collect::<Vec<_>>()
                .into_iter(),
            None => self
                .entries
                .values()
                .into_iter()
                .flat_map(|entries| entries.values())
                .filter(|entry| entry.operation == Operation::Upsert)
                .collect::<Vec<_>>()
                .into_iter(),
        }
    }

    pub fn iter_raw(&self) -> impl Iterator<Item = anyhow::Result<LedgerBlock>> + '_ {
        let data_start = partition_table::get_data_partition().start_lba;
        (0..).scan(data_start, |state, _| {
            let ledger_block = match self._journal_read_block(*state) {
                Ok(block) => block,
                Err(ErrorBlockRead::Empty) => return None,
                Err(ErrorBlockRead::Corrupted(err)) => {
                    return Some(Err(anyhow::format_err!(
                        "Failed to read Ledger block: {}",
                        err
                    )))
                }
            };
            *state = ledger_block.offset_next.expect("offset_next must be set");
            Some(Ok(ledger_block))
        })
    }

    pub fn num_blocks(&self) -> usize {
        self.metadata.borrow().num_blocks
    }

    pub fn get_latest_block_hash(&self) -> Vec<u8> {
        self.metadata.borrow().get_last_block_chain_hash().to_vec()
    }

    pub fn get_next_block_write_position(&self) -> u64 {
        self.metadata.borrow().next_block_write_position
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform_specific;
    fn log_init() {
        // Set log level to info by default
        if std::env::var("RUST_LOG").is_err() {
            std::env::set_var("RUST_LOG", "info");
        }
        let _ = env_logger::builder().is_test(true).try_init();
    }

    fn new_temp_ledger() -> LedgerKV {
        log_init();
        info!("Create temp ledger");
        // Create a temporary directory for the test
        let file_path = tempfile::tempdir()
            .unwrap()
            .into_path()
            .join("test_ledger_store.bin");
        platform_specific::override_backing_file(Some(file_path));
        partition_table::persist();

        fn mock_get_timestamp_nanos() -> u64 {
            0
        }

        LedgerKV::new()
            .expect("Failed to create a temp ledger for the test")
            .with_timestamp_fn(mock_get_timestamp_nanos)
    }

    #[test]
    fn test_compute_cumulative_hash() {
        let parent_hash = vec![0, 1, 2, 3];
        let key = vec![4, 5, 6, 7];
        let value = vec![8, 9, 10, 11];
        let ledger_block = LedgerBlock::new(
            vec![LedgerEntry::new(
                "Unspecified",
                key.clone(),
                value.clone(),
                Operation::Upsert,
            )],
            0,
            None,
            0,
            vec![],
        );
        let cumulative_hash = LedgerKV::_compute_block_chain_hash(
            &parent_hash,
            &ledger_block.entries,
            ledger_block.timestamp,
        )
        .unwrap();

        // Cumulative hash is a sha256 hash of the parent hash, key, and value
        // Obtained from a reference run
        assert_eq!(
            cumulative_hash,
            vec![
                40, 95, 206, 211, 182, 177, 181, 223, 8, 222, 58, 156, 47, 202, 110, 34, 8, 27, 73,
                51, 159, 2, 114, 103, 222, 45, 6, 14, 7, 186, 115, 42
            ]
        );
    }

    #[test]
    fn test_upsert() {
        let mut ledger_kv = new_temp_ledger();

        // Test upsert
        let key = b"test_key".to_vec();
        let value = b"test_value".to_vec();
        ledger_kv
            .upsert("Unspecified", key.clone(), value.clone())
            .unwrap();
        println!("partition table {}", partition_table::get_partition_table());
        assert_eq!(ledger_kv.get("Unspecified", &key).unwrap(), value);
        assert!(ledger_kv.commit_block().is_ok());
        assert_eq!(ledger_kv.get("Unspecified", &key).unwrap(), value);
        let entries = ledger_kv.entries.get("Unspecified").unwrap();
        assert_eq!(
            entries.get(&key),
            Some(&LedgerEntry::new(
                "Unspecified",
                key,
                value,
                Operation::Upsert,
            ))
        );
        assert_eq!(ledger_kv.metadata.borrow().num_blocks, 1);
        assert!(ledger_kv.next_block_entries.is_empty());
    }

    #[test]
    fn test_upsert_with_matching_entry_label() {
        let mut ledger_kv = new_temp_ledger();

        let key = b"test_key".to_vec();
        let value = b"test_value".to_vec();
        ledger_kv
            .upsert("NodeProvider", key.clone(), value.clone())
            .unwrap();
        assert_eq!(ledger_kv.entries.get("NodeProvider"), None); // value not committed yet
        assert_eq!(ledger_kv.get("NodeProvider", &key).unwrap(), value);
        ledger_kv.commit_block().unwrap();
        let entries = ledger_kv.entries.get("NodeProvider").unwrap();
        assert_eq!(
            entries.get(&key),
            Some(&LedgerEntry::new(
                "NodeProvider",
                key.clone(),
                value.clone(),
                Operation::Upsert,
            ))
        );
    }

    #[test]
    fn test_upsert_with_mismatched_entry_type() {
        let mut ledger_kv = new_temp_ledger();

        let key = b"test_key".to_vec();
        let value = b"test_value".to_vec();
        ledger_kv
            .upsert("Unspecified", key.clone(), value.clone())
            .unwrap();

        // Ensure that the entry is not added to the NodeProvider ledger since the entry_type doesn't match
        assert_eq!(ledger_kv.entries.get("NodeProvider"), None);
    }

    #[test]
    fn test_delete_with_matching_entry_type() {
        let mut ledger_kv = new_temp_ledger();

        let key = b"test_key".to_vec();
        let value = b"test_value".to_vec();
        ledger_kv
            .upsert("NodeProvider", key.clone(), value.clone())
            .unwrap();
        assert_eq!(ledger_kv.get("NodeProvider", &key).unwrap(), value); // Before delete: the value is there
        ledger_kv.delete("NodeProvider", key.clone()).unwrap();
        let expected_tombstone = Some(LedgerEntry {
            label: "NodeProvider".to_string(),
            key: key.clone(),
            value: vec![],
            operation: Operation::Delete,
        });
        assert_eq!(
            ledger_kv.get("NodeProvider", &key).unwrap_err().to_string(),
            "Entry not found"
        ); // After delete: the value is gone in the public interface
        assert_eq!(
            ledger_kv
                .next_block_entries
                .get("NodeProvider")
                .unwrap()
                .get(&key),
            expected_tombstone.as_ref()
        );
        assert_eq!(ledger_kv.entries.get("NodeProvider"), None); // (not yet committed)

        // Now commit the block
        assert!(ledger_kv.commit_block().is_ok());

        // And recheck: the value is gone in the public interface and deletion is in the ledger
        assert_eq!(
            ledger_kv.entries.get("NodeProvider").unwrap().get(&key),
            expected_tombstone.as_ref()
        );
        assert_eq!(ledger_kv.next_block_entries.get("NodeProvider"), None);
        assert_eq!(
            ledger_kv.get("NodeProvider", &key).unwrap_err().to_string(),
            "Entry not found"
        );
    }

    #[test]
    fn test_delete_with_mismatched_entry_type() {
        let mut ledger_kv = new_temp_ledger();

        let key = b"test_key".to_vec();
        let value = b"test_value".to_vec();
        ledger_kv
            .upsert("NodeProvider", key.clone(), value.clone())
            .unwrap();
        ledger_kv.get("NodeProvider", &key).unwrap();
        assert!(ledger_kv.entries.get("NodeProvider").is_none()); // the value is not yet committed
        ledger_kv.commit_block().unwrap();
        ledger_kv.entries.get("NodeProvider").unwrap();
        ledger_kv.delete("Unspecified", key.clone()).unwrap();

        // Ensure that the entry is not deleted from the ledger since the entry_type doesn't match
        let entries_np = ledger_kv.entries.get("NodeProvider").unwrap();
        assert_eq!(
            entries_np.get(&key),
            Some(&LedgerEntry::new(
                "NodeProvider",
                key.clone(),
                value.clone(),
                Operation::Upsert,
            ))
        );
        assert_eq!(ledger_kv.entries.get("Unspecified"), None);
    }

    #[test]
    fn test_delete() {
        let mut ledger_kv = new_temp_ledger();

        // Test delete
        let key = b"test_key".to_vec();
        let value = b"test_value".to_vec();
        ledger_kv
            .upsert("Unspecified", key.clone(), value.clone())
            .unwrap();
        ledger_kv.delete("Unspecified", key.clone()).unwrap();
        assert!(ledger_kv.commit_block().is_ok());
        let entries = ledger_kv.entries.get("Unspecified").unwrap();
        assert_eq!(
            entries.get(&key),
            Some(LedgerEntry {
                label: "Unspecified".to_string(),
                key: key.clone(),
                value: vec![],
                operation: Operation::Delete
            })
            .as_ref()
        );
        assert_eq!(ledger_kv.entries.get("NodeProvider"), None);
        assert_eq!(
            ledger_kv.get("Unspecified", &key).unwrap_err().to_string(),
            "Entry not found"
        );
    }

    #[test]
    fn test_refresh_ledger() {
        let mut ledger_kv = new_temp_ledger();

        info!("New temp ledger created");
        info!("ledger: {:?}", ledger_kv);

        // Test refresh_ledger
        let key = b"test_key".to_vec();
        let value = b"test_value".to_vec();
        ledger_kv
            .upsert("Unspecified", key.clone(), value.clone())
            .unwrap();
        assert!(ledger_kv.commit_block().is_ok());
        let expected_parent_hash = vec![
            44, 47, 227, 111, 170, 182, 247, 50, 62, 223, 196, 244, 223, 162, 138, 184, 243, 171,
            233, 153, 212, 151, 62, 60, 230, 242, 227, 39, 101, 178, 42, 141,
        ];
        ledger_kv = ledger_kv.refresh_ledger().unwrap();

        let entry = ledger_kv
            .entries
            .get("Unspecified")
            .unwrap()
            .values()
            .next()
            .unwrap()
            .clone();
        assert_eq!(
            entry,
            LedgerEntry {
                label: "Unspecified".to_string(),
                key,
                value,
                operation: Operation::Upsert,
            }
        );
        assert_eq!(
            ledger_kv.metadata.borrow().last_block_chain_hash,
            expected_parent_hash
        );

        // get_latest_hash should return the parent hash
        assert_eq!(ledger_kv.get_latest_block_hash(), expected_parent_hash);
    }
}
