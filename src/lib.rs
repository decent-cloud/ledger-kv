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
//! Example usage:
//!
//! ```rust
//! use std::path::PathBuf;
//! use ledger_kv::{platform_specific, LedgerKV, Operation};
//! use borsh::{BorshDeserialize, BorshSerialize};
//!
//! /// Enum defining the different labels for entries.
//! #[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug, Hash)]
//! pub enum EntryLabel {
//!     Unspecified,
//!     Label1,
//!     Label2,
//! }
//!
//! impl std::fmt::Display for EntryLabel {
//!     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//!         match self {
//!             EntryLabel::Unspecified => write!(f, "Unspecified"),
//!             EntryLabel::Label1 => write!(f, "Label1"),
//!             EntryLabel::Label2 => write!(f, "Label2"),
//!         }
//!     }
//! }
//!
//! // Optional: Override the backing file path
//! // let ledger_path = PathBuf::from("/tmp/ledger_kv/test_data.bin");
//! // platform_specific::override_backing_file(Some(ledger_path));
//!
//! // Create a new LedgerKV instance
//! let mut ledger_kv = LedgerKV::new().expect("Failed to create LedgerKV");
//!
//! // Insert a few new entries, each with a separate label
//! ledger_kv.upsert(EntryLabel::Label1, b"key1".to_vec(), b"value1".to_vec()).unwrap();
//! ledger_kv.upsert(EntryLabel::Label2, b"key2".to_vec(), b"value2".to_vec()).unwrap();
//! ledger_kv.commit_block().unwrap();
//!
//! // Retrieve all entries
//! let entries = ledger_kv.iter(None).collect::<Vec<_>>();
//! println!("All entries: {:?}", entries);
//! // Label1 entries
//! let entries = ledger_kv.iter(Some(EntryLabel::Label1)).collect::<Vec<_>>();
//! println!("Label1 entries: {:?}", entries);
//! // Label2 entries
//! let entries = ledger_kv.iter(Some(EntryLabel::Label2)).collect::<Vec<_>>();
//! println!("Label2 entries: {:?}", entries);
//!
//! // Delete an entry
//! ledger_kv.delete(EntryLabel::Label1, b"key1".to_vec()).unwrap();
//! ledger_kv.commit_block().unwrap();
//! // Label1 entries are now empty
//! assert_eq!(ledger_kv.iter(Some(EntryLabel::Label1)).count(), 0);
//! // Label2 entries still exist
//! assert_eq!(ledger_kv.iter(Some(EntryLabel::Label2)).count(), 1);
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
pub use ledger_entry::{Key, LedgerBlock, LedgerEntry, Operation, Value};
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
pub struct LedgerKV<TL> {
    metadata: RefCell<Metadata>,
    entries_next_block: IndexMap<Key, LedgerEntry<TL>>,
    entries: IndexMap<TL, IndexMap<Key, LedgerEntry<TL>>>,
    get_timestamp_nanos: fn() -> u64,
}

enum ErrorBlockRead {
    Empty,
    Corrupted(anyhow::Error),
}

impl<TL> LedgerKV<TL>
where
    TL: Debug
        + std::fmt::Display
        + BorshSerialize
        + BorshDeserialize
        + Clone
        + Eq
        + std::hash::Hash,
{
    pub fn new() -> anyhow::Result<Self> {
        LedgerKV {
            metadata: RefCell::new(Metadata::new()),
            entries_next_block: IndexMap::new(),
            entries: IndexMap::new(),
            get_timestamp_nanos: platform_specific::get_timestamp_nanos,
        }
        .refresh_ledger()
    }

    #[cfg(test)]
    fn with_timestamp_fn(self, get_timestamp_nanos: fn() -> u64) -> Self {
        LedgerKV {
            get_timestamp_nanos,
            ..self
        }
    }

    fn _compute_block_chain_hash(
        last_block_chain_hash: &[u8],
        block_entries: &[LedgerEntry<TL>],
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

    fn _journal_append_block(&self, ledger_block: LedgerBlock<TL>) -> anyhow::Result<()> {
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

    fn _journal_read_block(&self, offset: u64) -> Result<LedgerBlock<TL>, ErrorBlockRead> {
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
        if !&self.entries_next_block.is_empty() {
            return Err(anyhow::format_err!("There is already an open transaction."));
        } else {
            self.entries_next_block.clear();
        }
        Ok(())
    }

    pub fn commit_block(&mut self) -> anyhow::Result<()> {
        if self.entries_next_block.is_empty() {
            debug!("Commit of empty block invoked, skipping");
        } else {
            info!(
                "Commit non-empty block, with {} entries",
                self.entries_next_block.len()
            );
            let block_entries = Vec::from_iter(self.entries_next_block.values().cloned());
            let block_timestamp = (self.get_timestamp_nanos)();
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
            self.entries_next_block.clear();
        }
        Ok(())
    }

    pub fn get(&self, label: TL, key: &Key) -> anyhow::Result<Value> {
        match self.entries.get(&label) {
            Some(entries) => entries
                .get(key)
                .ok_or(anyhow::format_err!("Key not found"))
                .map(|e| e.value.clone()),
            None => Err(anyhow::format_err!("Entry label {:?} not found", label)),
        }
    }

    pub fn upsert(&mut self, label: TL, key: Key, value: Value) -> anyhow::Result<()> {
        let entry = LedgerEntry::new(label.clone(), key.clone(), value.clone(), Operation::Upsert);

        self.entries_next_block.insert(key.clone(), entry.clone());

        match self.entries.get_mut(&label) {
            Some(entries) => {
                entries.insert(key, entry);
            }
            None => {
                let mut new_map = IndexMap::new();
                new_map.insert(key, entry);
                self.entries.insert(label, new_map);
            }
        };

        Ok(())
    }

    pub fn delete(&mut self, label: TL, key: Key) -> anyhow::Result<()> {
        let entry = LedgerEntry::new(label.clone(), key.clone(), Vec::new(), Operation::Delete);

        self.entries_next_block.insert(key.clone(), entry);

        match self.entries.get_mut(&label) {
            Some(entries) => {
                entries.swap_remove(&key);
            }
            None => {
                warn!("Entry label {:?} not found", label);
            }
        };

        Ok(())
    }

    pub fn refresh_ledger(mut self) -> anyhow::Result<LedgerKV<TL>> {
        self.metadata.borrow_mut().clear();
        self.entries.clear();

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

            // Update the in-memory IndexMap of entries, used for quick lookups
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
                let entries = match self.entries.get_mut(&ledger_entry.label) {
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

    pub fn iter(&self, label: Option<TL>) -> impl Iterator<Item = &LedgerEntry<TL>> {
        self.entries
            .iter()
            .filter(|(entry_label, _entry)| match &label {
                Some(label) => entry_label == &label,
                None => true,
            })
            .map(|(_, entry)| entry)
            .flat_map(|entry| entry.values())
            .collect::<Vec<_>>()
            .into_iter()
    }

    pub fn iter_raw(&self) -> impl Iterator<Item = anyhow::Result<LedgerBlock<TL>>> + '_ {
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

    /// Enum defining the different labels for entries.
    #[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug, Hash)]
    pub enum EntryLabel {
        Unspecified,
        NodeProvider,
    }

    impl std::fmt::Display for EntryLabel {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                EntryLabel::Unspecified => write!(f, "Unspecified"),
                EntryLabel::NodeProvider => write!(f, "NodeProvider"),
            }
        }
    }

    fn new_temp_ledger<TL>() -> LedgerKV<TL>
    where
        TL: BorshSerialize
            + BorshDeserialize
            + Clone
            + PartialEq
            + Eq
            + Debug
            + std::hash::Hash
            + std::fmt::Display,
    {
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
                EntryLabel::Unspecified,
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
        assert_eq!(
            cumulative_hash,
            vec![
                225, 96, 89, 71, 148, 202, 180, 76, 246, 238, 241, 35, 75, 214, 40, 97, 72, 97,
                110, 128, 130, 94, 48, 103, 202, 14, 223, 86, 225, 194, 87, 174
            ]
        );
    }

    #[test]
    fn test_upsert() {
        let mut ledger_kv = new_temp_ledger();

        // Test upsert
        let key = vec![1, 2, 3];
        let value = vec![4, 5, 6];
        ledger_kv
            .upsert(EntryLabel::Unspecified, key.clone(), value.clone())
            .unwrap();
        println!("partition table {}", partition_table::get_partition_table());
        assert!(ledger_kv.commit_block().is_ok());
        let entries = ledger_kv.entries.get(&EntryLabel::Unspecified).unwrap();
        assert_eq!(
            entries.get(&key),
            Some(&LedgerEntry::new(
                EntryLabel::Unspecified,
                key,
                value,
                Operation::Upsert,
            ))
        );
        assert_eq!(ledger_kv.metadata.borrow().num_blocks, 1);
        assert!(ledger_kv.entries_next_block.is_empty());
    }

    #[test]
    fn test_upsert_with_matching_entry_label() {
        let mut ledger_kv = new_temp_ledger();

        let key = vec![1, 2, 3];
        let value = vec![4, 5, 6];
        ledger_kv
            .upsert(EntryLabel::NodeProvider, key.clone(), value.clone())
            .unwrap();
        let entries = ledger_kv.entries.get(&EntryLabel::NodeProvider).unwrap();
        assert_eq!(
            entries.get(&key),
            Some(&LedgerEntry::new(
                EntryLabel::NodeProvider,
                key.clone(),
                value.clone(),
                Operation::Upsert,
            ))
        );
    }

    #[test]
    fn test_upsert_with_mismatched_entry_type() {
        let mut ledger_kv = new_temp_ledger();

        let key = vec![1, 2, 3];
        let value = vec![4, 5, 6];
        ledger_kv
            .upsert(EntryLabel::Unspecified, key.clone(), value.clone())
            .unwrap();

        // Ensure that the entry is not added to the NodeProvider ledger since the entry_type doesn't match
        assert_eq!(ledger_kv.entries.get(&EntryLabel::NodeProvider), None);
    }

    #[test]
    fn test_delete_with_matching_entry_type() {
        let mut ledger_kv = new_temp_ledger();

        let key = vec![1, 2, 3];
        let value = vec![4, 5, 6];
        ledger_kv
            .upsert(EntryLabel::NodeProvider, key.clone(), value.clone())
            .unwrap();
        ledger_kv
            .delete(EntryLabel::NodeProvider, key.clone())
            .unwrap();

        // Ensure that the entry is deleted from the ledger since the entry_type matches
        let entries = ledger_kv.entries.get(&EntryLabel::NodeProvider).unwrap();
        assert_eq!(entries.get(&key), None);
    }

    #[test]
    fn test_delete_with_mismatched_entry_type() {
        let mut ledger_kv = new_temp_ledger();

        let key = vec![1, 2, 3];
        let value = vec![4, 5, 6];
        ledger_kv
            .upsert(EntryLabel::NodeProvider, key.clone(), value.clone())
            .unwrap();
        ledger_kv
            .delete(EntryLabel::Unspecified, key.clone())
            .unwrap();

        // Ensure that the entry is not deleted from the ledger since the entry_type doesn't match
        let entries_np = ledger_kv.entries.get(&EntryLabel::NodeProvider).unwrap();
        assert_eq!(
            entries_np.get(&key),
            Some(&LedgerEntry::new(
                EntryLabel::NodeProvider,
                key.clone(),
                value.clone(),
                Operation::Upsert,
            ))
        );
        assert_eq!(ledger_kv.entries.get(&EntryLabel::Unspecified), None);
    }

    #[test]
    fn test_delete() {
        let mut ledger_kv = new_temp_ledger();

        // Test delete
        let key = vec![1, 2, 3];
        let value = vec![4, 5, 6];
        ledger_kv
            .upsert(EntryLabel::Unspecified, key.clone(), value.clone())
            .unwrap();
        ledger_kv
            .delete(EntryLabel::Unspecified, key.clone())
            .unwrap();
        let entries = ledger_kv.entries.get(&EntryLabel::Unspecified).unwrap();
        assert_eq!(entries.get(&key), None);
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
            .upsert(EntryLabel::Unspecified, key.clone(), value.clone())
            .unwrap();
        assert!(ledger_kv.commit_block().is_ok());
        let expected_parent_hash = vec![
            47, 1, 209, 196, 44, 241, 73, 144, 71, 71, 188, 31, 174, 237, 64, 83, 220, 233, 6, 253,
            11, 244, 132, 66, 165, 27, 188, 187, 149, 13, 46, 245,
        ];
        ledger_kv = ledger_kv.refresh_ledger().unwrap();

        let entry = ledger_kv
            .entries
            .get(&EntryLabel::Unspecified)
            .unwrap()
            .values()
            .next()
            .unwrap()
            .clone();
        assert_eq!(
            entry,
            LedgerEntry {
                label: EntryLabel::Unspecified,
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
