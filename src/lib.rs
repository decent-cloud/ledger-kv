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
//! use ledger_kv::{LedgerKV, Operation};
//! use borsh::{BorshDeserialize, BorshSerialize};
//!
//! /// Enum defining the different labels for entries.
//! #[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug, Hash)]
//! pub enum EntryLabel {
//!     Unspecified,
//!     SomeLabel,
//! }
//!
//! let file_path = PathBuf::from("/tmp/ledger_kv/test_data.bin");
//!
//! // Create a new LedgerKV instance
//! let mut ledger_kv = LedgerKV::new().expect("Failed to create LedgerKV");
//!
//! // Insert a new entry
//! let label = EntryLabel::Unspecified;
//! let key = b"key".to_vec();
//! let value = b"value".to_vec();
//! ledger_kv.upsert(label.clone(), key.clone(), value.clone()).unwrap();
//! ledger_kv.upsert(label.clone(), b"key2".to_vec(), b"value2".to_vec()).unwrap();
//! ledger_kv.commit_block().unwrap();
//!
//! // Retrieve all entries
//! let entries = ledger_kv.iter(None).collect::<Vec<_>>();
//! println!("All entries: {:?}", entries);
//!
//! // Delete an entry
//! ledger_kv.delete(label, key).unwrap();
//! ledger_kv.commit_block().unwrap();
//! ```

#[cfg(target_arch = "wasm32")]
pub mod platform_specific_wasm32;
#[cfg(target_arch = "wasm32")]
pub use platform_specific_wasm32 as platform_specific;

#[cfg(target_arch = "x86_64")]
pub mod platform_specific_x86_64;
#[cfg(target_arch = "x86_64")]
pub use platform_specific_x86_64 as platform_specific;

pub mod ledger_entry;
pub mod partition_table;

use crate::platform_specific::{persistent_storage_read64, persistent_storage_write64};
use ahash::AHashMap;
use borsh::{to_vec, BorshDeserialize, BorshSerialize};
use indexmap::IndexMap;
pub use ledger_entry::{Key, LedgerBlock, LedgerEntry, Operation, Value};
use platform_specific::{info, persistent_storage_ready, warn};
use sha2::{Digest, Sha256};
use std::{cell::RefCell, fmt::Debug};

/// Struct representing the metadata of the ledger.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub(crate) struct Metadata {
    /// The number of entries in the ledger.
    pub(crate) num_blocks: usize,
    /// The last offset in the file.
    pub(crate) next_write_position: usize,
    /// The hash of the parent metadata.
    pub(crate) parent_hash: Vec<u8>,
}

impl Default for Metadata {
    fn default() -> Self {
        info!(
            "next_write_position: {}",
            partition_table::get_data_partition().start_lba
        );
        Metadata {
            num_blocks: 0,
            next_write_position: partition_table::get_data_partition().start_lba as usize,
            parent_hash: Vec::new(),
        }
    }
}

impl Metadata {
    pub fn new() -> Self {
        Metadata::default()
    }

    pub fn clear(&mut self) {
        self.num_blocks = 0;
        self.next_write_position = partition_table::get_data_partition().start_lba as usize;
        self.parent_hash = Vec::new();
    }

    /// Refreshes (re-reads) the metadata by reading from the persistent storage.
    fn update_from_persistent_storage(&mut self) -> anyhow::Result<()> {
        let metadata_bytes = self._read_raw_metadata_bytes()?;

        if metadata_bytes.is_empty() {
            self.num_blocks = 0;
            self.next_write_position = partition_table::get_data_partition().start_lba as usize;
            self.parent_hash = Vec::new();
        } else {
            let deserialized_metadata: Metadata =
                Metadata::deserialize(&mut metadata_bytes.as_ref()).unwrap();
            self.num_blocks = deserialized_metadata.num_blocks;
            self.next_write_position = deserialized_metadata.next_write_position;
            self.parent_hash = deserialized_metadata.parent_hash;
        }

        info!(
            "Read metadata of num_blocks {} next_write_position {}",
            self.num_blocks, self.next_write_position
        );
        Ok(())
    }

    fn append_entries(&mut self, parent_hash: &[u8], position: usize) -> anyhow::Result<()> {
        // let md: &mut Metadata = &mut *self.borrow_mut();
        self.num_blocks += 1;
        self.parent_hash = parent_hash.to_vec();
        self.next_write_position = position;
        let metadata_bytes = to_vec(self).expect("Failed to serialize metadata");
        self._save_raw_metadata_bytes(&metadata_bytes)?;
        self.update_from_persistent_storage()
    }

    fn get_parent_hash(&self) -> &[u8] {
        self.parent_hash.as_slice()
    }

    fn _read_raw_metadata_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let part_entry = partition_table::get_metadata_partition();
        let mut buf = [0u8; std::mem::size_of::<Metadata>() * 2];
        persistent_storage_read64(part_entry.start_lba, &mut buf)?;
        Ok(buf.to_vec())
    }

    fn _save_raw_metadata_bytes(&self, metadata_bytes: &[u8]) -> anyhow::Result<()> {
        let part_entry = partition_table::get_metadata_partition();
        info!(
            "Saving metadata to {} bytes at offset {}",
            metadata_bytes.len(),
            part_entry.start_lba
        );
        persistent_storage_write64(part_entry.start_lba, metadata_bytes);
        Ok(())
    }
}

#[derive(Debug)]
pub struct LedgerKV<TL> {
    metadata: RefCell<Metadata>,
    entries_next_block: IndexMap<Key, LedgerEntry<TL>>,
    entries: AHashMap<TL, IndexMap<Key, LedgerEntry<TL>>>,
    entry_hash2offset: IndexMap<Key, usize>,
}

impl<TL> LedgerKV<TL>
where
    TL: Debug + BorshSerialize + BorshDeserialize + Clone + Eq + std::hash::Hash,
{
    pub fn new() -> anyhow::Result<Self> {
        LedgerKV {
            metadata: RefCell::new(Metadata::new()),
            entries_next_block: IndexMap::new(),
            entries: AHashMap::new(),
            entry_hash2offset: IndexMap::new(),
        }
        .refresh_ledger()
    }

    fn _compute_cumulative_hash(
        parent_hash: &[u8],
        block_entries: &[LedgerEntry<TL>],
    ) -> anyhow::Result<Vec<u8>> {
        let mut hasher = Sha256::new();
        hasher.update(parent_hash);
        for entry in block_entries.iter() {
            hasher.update(to_vec(entry)?);
        }
        Ok(hasher.finalize().to_vec())
    }

    fn _journal_append_block(&self, ledger_block: LedgerBlock<TL>) -> anyhow::Result<()> {
        // Prepare entry as serialized bytes
        let serialized_data = to_vec(&ledger_block)?;
        info!(
            "Appending block with {} bytes: {}",
            serialized_data.len(),
            ledger_block,
        );
        // Prepare entry len, as bytes
        let block_len_bytes = serialized_data.len();
        let serialized_data_len = block_len_bytes.to_le_bytes();

        info!(
            "entry_len_bytes {} serialized_data_len: {:?} serialized_data: {:?}",
            block_len_bytes, serialized_data_len, serialized_data
        );
        persistent_storage_write64(
            self.metadata.borrow().next_write_position as u64,
            &serialized_data_len,
        );
        persistent_storage_write64(
            self.metadata.borrow().next_write_position as u64 + serialized_data_len.len() as u64,
            &serialized_data,
        );

        let next_write_position = self.metadata.borrow().next_write_position
            + serialized_data_len.len()
            + serialized_data.len();
        self.metadata
            .borrow_mut()
            .append_entries(&ledger_block.hash, next_write_position)
    }

    fn _journal_read_block(&self, offset: u64) -> anyhow::Result<(u64, LedgerBlock<TL>)> {
        info!("Reading journal block at offset {}", offset);

        // Find out how many bytes we need to read ==> block len in bytes
        let mut buf = [0u8; std::mem::size_of::<usize>()];
        persistent_storage_read64(offset, &mut buf)?;
        let block_len: usize = usize::from_le_bytes(buf);
        info!("read bytes: {:?}", buf);
        info!("block_len: {}", block_len);

        // Read the block as raw bytes
        let mut buf = vec![0u8; block_len];
        persistent_storage_read64(offset + std::mem::size_of::<usize>() as u64, &mut buf)?;
        match LedgerBlock::deserialize(&mut buf.as_ref()).map_err(|err| err.into()) {
            Ok(block) => Ok((
                offset + std::mem::size_of::<usize>() as u64 + block_len as u64,
                block,
            )),
            Err(err) => Err(err),
        }
    }

    pub fn ready(&self) -> bool {
        persistent_storage_ready()
    }

    pub fn begin_block(&mut self) -> anyhow::Result<()> {
        if !&self.entries_next_block.is_empty() {
            return Err(anyhow::format_err!("There is already an open transaction."));
        } else {
            self.entries_next_block.clear();
        }
        Ok(())
    }

    pub fn commit_block(&self) -> anyhow::Result<()> {
        if !self.entries_next_block.is_empty() {
            let block_entries = Vec::from_iter(self.entries_next_block.values().cloned());
            let hash = Self::_compute_cumulative_hash(
                self.metadata.borrow().get_parent_hash(),
                &block_entries,
            )?;
            let block = LedgerBlock::new(
                block_entries,
                self.metadata.borrow().next_write_position,
                hash,
            );
            self._journal_append_block(block)?;
        }
        Ok(())
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
                entries.remove(&key);
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
        self.entry_hash2offset.clear();

        // If the backend is not ready (e.g. the backing file does not exist), just return
        if !self.ready() {
            warn!("Backend not ready");
            return Ok(self);
        }

        let mut entries_hash2offset = IndexMap::new();

        self.metadata
            .borrow_mut()
            .update_from_persistent_storage()?;
        let num_blocks = self.metadata.borrow().num_blocks;
        info!("Num blocks: {}", self.metadata.borrow().num_blocks);

        let mut parent_hash = Vec::new();
        let mut updates = Vec::new();
        // Step 1: Read all Ledger Blocks
        for ledger_block in self.iter_raw(num_blocks) {
            // Update the in-memory IndexMap of entries, used for quick lookups
            let expected_hash =
                Self::_compute_cumulative_hash(&parent_hash, &ledger_block.entries)?;
            assert_eq!(expected_hash, ledger_block.hash);

            parent_hash.clear();
            parent_hash.extend_from_slice(&ledger_block.hash);

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
                        self.entries.get_mut(&ledger_entry.label).unwrap()
                    }
                };

                match &ledger_entry.operation {
                    Operation::Upsert => {
                        entries.insert(ledger_entry.key.clone(), ledger_entry.clone());
                        entries_hash2offset.insert(ledger_block.hash.to_vec(), ledger_block.offset);
                    }
                    Operation::Delete => {
                        entries.remove(&ledger_entry.key);
                    }
                }
            }
        }

        self.entry_hash2offset = entries_hash2offset;

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

    pub fn iter_raw(&self, num_blocks: usize) -> impl Iterator<Item = LedgerBlock<TL>> + '_ {
        let data_start = partition_table::get_data_partition().start_lba;
        (0..num_blocks).scan(data_start, |state, _| {
            let (offset_next, ledger_block) = self
                ._journal_read_block(*state)
                .expect("Failed to read Ledger block");
            *state = offset_next;
            Some(ledger_block)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        platform_specific, platform_specific_x86_64::persistent_storage_size_bytes, Metadata,
    };
    use borsh::to_vec;
    fn log_init() {
        // Set log level to info by default
        if std::env::var("RUST_LOG").is_err() {
            std::env::set_var("RUST_LOG", "info");
        }
        let _ = env_logger::builder().is_test(true).try_init();
    }

    fn create_temp_metadata() -> Metadata {
        log_init();
        info!("Create temp metadata");
        // Create a temporary directory for the test
        let file_path = tempfile::tempdir()
            .unwrap()
            .into_path()
            .join("test_ledger_store.bin");
        platform_specific::override_backing_file(Some(file_path));

        // Create a Metadata instance
        Metadata::new()
    }

    /// Enum defining the different labels for entries.
    #[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug, Hash)]
    pub enum EntryLabel {
        Unspecified,
        NodeProvider,
    }

    fn new_temp_ledger<TL>() -> LedgerKV<TL>
    where
        TL: BorshSerialize + BorshDeserialize + Clone + PartialEq + Eq + Debug + std::hash::Hash,
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
        LedgerKV::new().expect("Failed to create a temp ledger for the test")
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
            vec![],
        );
        let cumulative_hash =
            LedgerKV::_compute_cumulative_hash(&parent_hash, &ledger_block.entries).unwrap();

        // Cumulative hash is a sha256 hash of the parent hash, key, and value
        assert_eq!(
            cumulative_hash,
            vec![
                3, 251, 71, 255, 141, 93, 131, 14, 103, 242, 233, 103, 122, 213, 48, 118, 130, 141,
                40, 163, 106, 201, 194, 79, 165, 129, 3, 21, 147, 246, 141, 98
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
        let key = vec![1, 2, 3];
        let value = vec![4, 5, 6];
        ledger_kv
            .upsert(EntryLabel::Unspecified, key.clone(), value.clone())
            .unwrap();
        assert!(ledger_kv.commit_block().is_ok());
        let expected_parent_hash = vec![
            184, 181, 136, 219, 213, 194, 88, 79, 80, 71, 95, 100, 185, 182, 143, 44, 241, 81, 43,
            167, 162, 202, 53, 75, 64, 228, 236, 245, 68, 194, 139, 70,
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
            ledger_kv.metadata.borrow().parent_hash,
            expected_parent_hash
        );
    }

    #[test]
    fn test_save() {
        let mut metadata = create_temp_metadata();

        metadata.num_blocks = 10;
        metadata.parent_hash = vec![0, 1, 2, 3];

        // Call the save method
        metadata
            ._save_raw_metadata_bytes(&to_vec(&metadata).unwrap())
            .unwrap();

        // Read all contents of the metadata partition into a buffer
        let meta_partition = partition_table::get_metadata_partition();
        let read_end = meta_partition.end_lba.min(persistent_storage_size_bytes());
        let mut buf = vec![0u8; (read_end - meta_partition.start_lba) as usize];
        persistent_storage_read64(meta_partition.start_lba, &mut buf).unwrap();

        // Deserialize the metadata bytes from the buffer
        let deserialized_metadata: Metadata = Metadata::deserialize(&mut buf.as_slice()).unwrap();

        // Assert that the metadata fields are correctly deserialized
        assert_eq!(deserialized_metadata.num_blocks, 10);
        assert_eq!(deserialized_metadata.parent_hash, vec![0, 1, 2, 3]);

        // Assert that the deserialized metadata matches the original metadata
        assert_eq!(deserialized_metadata.num_blocks, 10);
        assert_eq!(deserialized_metadata.parent_hash, vec![0, 1, 2, 3]);
    }
}
