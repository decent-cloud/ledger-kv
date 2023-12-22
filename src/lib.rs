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
//! by label or in raw form. It also supports refreshing the in-memory index and metadata from the binary file.
//!
//! Example usage:
//!
//! ```rust
//! use std::path::PathBuf;
//! use ledger_kv::{LedgerKV, EntryLabel, Operation};
//! use ledger_kv::data_store::{DataBackend, MetadataBackend};
//!
//! let file_path = PathBuf::from("/tmp/ledger_kv/test_data.bin");
//! let data_backend = DataBackend::new(file_path.with_extension("bin"));
//! let metadata_backend = MetadataBackend::new(file_path.with_extension("meta"));
//!
//! // Create a new LedgerKV instance
//! let mut ledger_kv = LedgerKV::new(data_backend, metadata_backend).expect("Failed to create LedgerKV");
//!
//! // Insert a new entry
//! let label = EntryLabel::Unspecified;
//! let key = b"key".to_vec();
//! let value = b"value".to_vec();
//! ledger_kv.upsert(label.clone(), key.clone(), value.clone()).unwrap();
//!
//! // Retrieve all entries
//! let entries = ledger_kv.iter(None).collect::<Vec<_>>();
//! println!("All entries: {:?}", entries);
//!
//! // Delete an entry
//! ledger_kv.delete(label, key).unwrap();
//! ```

pub mod ledger_entry;

#[cfg(target_arch = "wasm32")]
pub mod data_store_wasm32;
#[cfg(target_arch = "wasm32")]
pub use data_store_wasm32 as data_store;

#[cfg(not(target_arch = "wasm32"))]
pub mod data_store_native;
#[cfg(not(target_arch = "wasm32"))]
pub use data_store_native as data_store;

use ahash::AHashMap;
use borsh::{from_slice, to_vec};
use borsh_derive::{BorshDeserialize, BorshSerialize};
use data_store::{DataBackend, MetadataBackend};
use indexmap::IndexMap;
pub use ledger_entry::{EntryLabel, Key, LedgerBlock, LedgerEntry, Operation, Value};
use log::{info, warn};
use sha2::{Digest, Sha256};
use std::cell::RefCell;

/// Struct representing the metadata of the ledger.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub(crate) struct Metadata {
    #[borsh(skip)]
    pub(crate) metadata_backend: MetadataBackend,
    /// The number of entries in the ledger.
    pub(crate) num_blocks: usize,
    /// The last offset in the file.
    pub(crate) last_offset: usize,
    /// The hash of the parent metadata.
    pub(crate) parent_hash: Vec<u8>,
}

impl Metadata {
    pub fn new(metadata_backend: MetadataBackend) -> Self {
        Metadata {
            metadata_backend,
            num_blocks: 0,
            last_offset: 0,
            parent_hash: Vec::new(),
        }
    }

    /// Refreshes the metadata by reading from the file.
    fn refresh(&mut self) {
        let metadata_bytes = self.metadata_backend.read_raw_metadata_bytes();

        if metadata_bytes.is_empty() {
            self.num_blocks = 0;
            self.last_offset = 0;
            self.parent_hash = Vec::new();
        } else {
            let deserialized_metadata: Metadata = from_slice::<Metadata>(&metadata_bytes).unwrap();
            self.num_blocks = deserialized_metadata.num_blocks;
            self.last_offset = deserialized_metadata.last_offset;
            self.parent_hash = deserialized_metadata.parent_hash;
        }

        info!(
            "Read metadata of num_blocks {} last_offset {}",
            self.num_blocks, self.last_offset
        );
    }

    fn append_entries(
        &mut self,
        ledger_block: &LedgerBlock,
        position: usize,
    ) -> anyhow::Result<()> {
        // let md: &mut Metadata = &mut *self.borrow_mut();
        self.num_blocks += 1;
        self.parent_hash = ledger_block.hash.clone();
        self.last_offset = position;
        let metadata_bytes = to_vec(self).expect("Failed to serialize metadata");
        self.metadata_backend
            .save_raw_metadata_bytes(&metadata_bytes)?;
        self.refresh();
        Ok(())
    }

    fn get_parent_hash(&self) -> &[u8] {
        self.parent_hash.as_slice()
    }
}

/// Struct representing the LedgerKV.
pub struct LedgerKV {
    data_backend: DataBackend,
    metadata: RefCell<Metadata>,
    entries_current_block: IndexMap<Key, LedgerEntry>,
    entries: AHashMap<EntryLabel, IndexMap<Key, LedgerEntry>>,
    entry_hash2offset: IndexMap<Key, usize>,
}

impl LedgerKV {
    pub fn new(
        data_backend: DataBackend,
        metadata_backend: MetadataBackend,
    ) -> anyhow::Result<Self> {
        LedgerKV {
            data_backend,
            metadata: RefCell::new(Metadata::new(metadata_backend)),
            entries_current_block: IndexMap::new(),
            entries: AHashMap::new(),
            entry_hash2offset: IndexMap::new(),
        }
        .refresh_ledger()
    }

    fn _compute_cumulative_hash(
        parent_hash: &[u8],
        block_entries: &[LedgerEntry],
    ) -> anyhow::Result<Vec<u8>> {
        let mut hasher = Sha256::new();
        hasher.update(parent_hash);
        for entry in block_entries.iter() {
            hasher.update(to_vec(entry)?);
        }
        Ok(hasher.finalize().to_vec())
    }

    fn _journal_append_kv_entry(&self, ledger_block: LedgerBlock) -> anyhow::Result<()> {
        // Prepare entry as serialized bytes
        let serialized_data = to_vec(&ledger_block)?;
        // Prepare entry len, as bytes
        let entry_len_bytes = serialized_data.len();
        let serialized_data_len = to_vec(&entry_len_bytes).expect("failed to serialize entry len");

        self.data_backend.append_to_ledger(&serialized_data_len)?;
        let position = self.data_backend.append_to_ledger(&serialized_data)?;

        println!("Entry hash: {:?}", ledger_block.hash);
        self.metadata
            .borrow_mut()
            .append_entries(&ledger_block, position)
    }

    pub fn begin_block(&mut self) -> anyhow::Result<()> {
        if !&self.entries_current_block.is_empty() {
            return Err(anyhow::format_err!("There is already an open transaction."));
        } else {
            self.entries_current_block.clear();
        }
        Ok(())
    }

    pub fn commit_block(&self) -> anyhow::Result<()> {
        if !self.entries_current_block.is_empty() {
            let block_entries = Vec::from_iter(self.entries_current_block.values().cloned());
            let hash = Self::_compute_cumulative_hash(
                self.metadata.borrow().get_parent_hash(),
                &block_entries,
            )?;
            let block = LedgerBlock::new(block_entries, self.metadata.borrow().last_offset, hash);
            self._journal_append_kv_entry(block)?;
        }
        Ok(())
    }

    pub fn upsert(&mut self, label: EntryLabel, key: Key, value: Value) -> anyhow::Result<()> {
        let entry = LedgerEntry::new(label.clone(), key.clone(), value.clone(), Operation::Upsert);

        self.entries_current_block
            .insert(key.clone(), entry.clone());

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

    pub fn delete(&mut self, label: EntryLabel, key: Key) -> anyhow::Result<()> {
        let entry = LedgerEntry::new(label.clone(), key.clone(), Vec::new(), Operation::Delete);

        self.entries_current_block.insert(key.clone(), entry);

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

    pub fn refresh_ledger(mut self) -> anyhow::Result<LedgerKV> {
        self.entries.clear();
        self.entry_hash2offset.clear();
        self.metadata.borrow_mut().refresh();

        // If the backend is not ready (e.g. the backing file does not exist), just return
        if !self.data_backend.ready() {
            return Err(anyhow::Error::msg("Backend not ready"));
        }

        let mut entries_hash2offset = IndexMap::new();

        self.metadata.borrow_mut().refresh();
        let num_blocks = self.metadata.borrow().num_blocks;
        info!("Num blocks: {}", self.metadata.borrow().num_blocks);

        let mut parent_hash = Vec::new();
        for ledger_block in self.data_backend.iter_raw(num_blocks).collect::<Vec<_>>() {
            // Update the in-memory IndexMap of entries, used for quick lookups
            let expected_hash =
                Self::_compute_cumulative_hash(&parent_hash, &ledger_block.entries)?;
            assert_eq!(expected_hash, ledger_block.hash);

            parent_hash.clear();
            parent_hash.extend_from_slice(&ledger_block.hash);

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

    pub fn iter(&self, label: Option<EntryLabel>) -> impl Iterator<Item = &LedgerEntry> {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_temp_ledger() -> LedgerKV {
        // Create a temporary directory for the test
        let file_path = tempfile::tempdir()
            .unwrap()
            .into_path()
            .join("test_ledger_store");
        let data_backend = DataBackend::new(file_path.with_extension("bin"));
        let metadata_backend = MetadataBackend::new(file_path.with_extension("meta"));
        LedgerKV::new(data_backend, metadata_backend)
            .expect("Failed to create a temp ledger for the test")
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

        let entry: LedgerEntry = ledger_kv
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
                key: key,
                value: value,
                operation: Operation::Upsert,
            }
        );
        assert_eq!(
            ledger_kv.metadata.borrow().parent_hash,
            expected_parent_hash
        );

        std::fs::remove_file(ledger_kv.data_backend.file_path.clone()).unwrap();
        std::fs::remove_file(
            ledger_kv
                .metadata
                .borrow()
                .metadata_backend
                .file_path
                .clone(),
        )
        .unwrap();
        assert!(ledger_kv.refresh_ledger().is_err());
    }
}
