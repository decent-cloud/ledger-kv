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
//! fn main() {
//!     let file_path = PathBuf::from("/tmp/ledger_kv/test_data.bin");
//!     let data_backend = DataBackend::new(file_path.with_extension("bin"));
//!     let metadata_backend = MetadataBackend::new(file_path.with_extension("meta"));
//!
//!     // Create a new LedgerKV instance
//!     let mut ledger_kv = LedgerKV::new(data_backend, metadata_backend);
//!
//!     // Insert a new entry
//!     let label = EntryLabel::Unspecified;
//!     let key = b"key".to_vec();
//!     let value = b"value".to_vec();
//!     ledger_kv.upsert(label.clone(), key.clone(), value.clone()).unwrap();
//!
//!     // Retrieve all entries
//!     let entries = ledger_kv.iter(None).collect::<Vec<_>>();
//!     println!("All entries: {:?}", entries);
//!
//!     // Delete an entry
//!     ledger_kv.delete(label, key).unwrap();
//! }
//! ```

pub mod kv_entry;

#[cfg(target_arch = "wasm32")]
pub mod data_store_wasm32_ic;
#[cfg(target_arch = "wasm32")]
pub use data_store_wasm32_ic as data_store;

#[cfg(not(target_arch = "wasm32"))]
pub mod data_store_native;
#[cfg(not(target_arch = "wasm32"))]
pub use data_store_native as data_store;

use ahash::AHashMap;
use borsh::{from_slice, to_vec};
use borsh_derive::{BorshDeserialize, BorshSerialize};
use data_store::{DataBackend, MetadataBackend};
use indexmap::IndexMap;
pub use kv_entry::{EntryLabel, KvEntry, Operation};
use log::{info, warn};
use sha2::{Digest, Sha256};
use std::cell::RefCell;

/// Struct representing the metadata of the ledger.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub(crate) struct Metadata {
    #[borsh(skip)]
    pub(crate) metadata_backend: MetadataBackend,
    /// The number of entries in the ledger.
    pub(crate) num_entries: usize,
    /// The last offset in the file.
    pub(crate) last_offset: usize,
    /// The hash of the parent metadata.
    pub(crate) parent_hash: Vec<u8>,
}

impl Metadata {
    pub fn new(metadata_backend: MetadataBackend) -> Self {
        Metadata {
            metadata_backend,
            num_entries: 0,
            last_offset: 0,
            parent_hash: Vec::new(),
        }
    }

    /// Refreshes the metadata by reading from the file.
    fn refresh(&mut self) {
        let metadata_bytes = self.metadata_backend.read_raw_metadata_bytes();

        if metadata_bytes.is_empty() {
            self.num_entries = 0;
            self.last_offset = 0;
            self.parent_hash = Vec::new();
        } else {
            let deserialized_metadata: Metadata = from_slice::<Metadata>(&metadata_bytes).unwrap();
            self.num_entries = deserialized_metadata.num_entries;
            self.last_offset = deserialized_metadata.last_offset;
            self.parent_hash = deserialized_metadata.parent_hash;
        }

        info!(
            "Read metadata of num_entries {} last_offset {}",
            self.num_entries, self.last_offset
        );
    }

    fn append_entry(&mut self, entry: &KvEntry, position: usize) -> anyhow::Result<()> {
        // let md: &mut Metadata = &mut *self.borrow_mut();
        self.num_entries += 1;
        self.parent_hash = entry.hash.clone();
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
    entries: AHashMap<EntryLabel, IndexMap<Vec<u8>, KvEntry>>,
    entry_hash2offset: IndexMap<Vec<u8>, usize>,
}

impl LedgerKV {
    pub fn new(data_backend: DataBackend, metadata_backend: MetadataBackend) -> Self {
        LedgerKV {
            data_backend,
            metadata: RefCell::new(Metadata::new(metadata_backend)),
            entries: AHashMap::new(),
            entry_hash2offset: IndexMap::new(),
        }
        .refresh_ledger()
    }

    fn _compute_cumulative_hash(parent_hash: &[u8], key: &[u8], value: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(parent_hash);
        hasher.update(key);
        hasher.update(value);
        hasher.finalize().to_vec()
    }

    fn _journal_append_kv_entry(&self, entry: &KvEntry) -> anyhow::Result<()> {
        // Prepare entry as serialized bytes
        let serialized_data = to_vec(&entry)?;
        // Prepare entry len, as bytes
        let entry_len_bytes = serialized_data.len();
        let serialized_data_len = to_vec(&entry_len_bytes).expect("failed to serialize entry len");

        self.data_backend.append_to_ledger(&serialized_data_len)?;
        let position = self.data_backend.append_to_ledger(&serialized_data)?;

        println!("Entry hash: {:?}", entry.hash);
        self.metadata.borrow_mut().append_entry(entry, position)
    }

    pub fn upsert(
        &mut self,
        label: EntryLabel,
        key: Vec<u8>,
        value: Vec<u8>,
    ) -> anyhow::Result<()> {
        let hash =
            Self::_compute_cumulative_hash(&self.metadata.borrow().get_parent_hash(), &key, &value);
        let entry = KvEntry::new(
            label.clone(),
            key.clone(),
            value.clone(),
            Operation::Upsert,
            self.metadata.borrow().last_offset,
            hash,
        );

        self._journal_append_kv_entry(&entry)?;

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

    pub fn delete(&mut self, label: EntryLabel, key: Vec<u8>) -> anyhow::Result<()> {
        let hash = Self::_compute_cumulative_hash(&self.metadata.borrow().parent_hash, &key, &[]);
        let entry = KvEntry::new(
            label.clone(),
            key.clone(),
            Vec::new(),
            Operation::Delete,
            0,
            hash,
        );

        self._journal_append_kv_entry(&entry)?;

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

    pub fn refresh_ledger(mut self) -> Self {
        self.entries.clear();
        self.entry_hash2offset.clear();
        self.metadata.borrow_mut().refresh();

        // If the backend is not ready (e.g. the backing file does not exist), just return
        if !self.data_backend.ready() {
            return self;
        }

        let mut entries_hash2offset = IndexMap::new();

        self.metadata.borrow_mut().refresh();
        let num_entries = self.metadata.borrow().num_entries;
        info!("Num entries: {}", self.metadata.borrow().num_entries);

        let mut parent_hash = Vec::new();
        for entry in self.data_backend.iter_raw(num_entries).collect::<Vec<_>>() {
            // Update the in-memory IndexMap of entries, used for quick lookups
            let expected_hash =
                Self::_compute_cumulative_hash(&parent_hash, &entry.key, &entry.value);
            assert_eq!(expected_hash, entry.hash);

            parent_hash.clear();
            parent_hash.extend_from_slice(&entry.hash);

            let entries = match self.entries.get_mut(&entry.label) {
                Some(entries) => entries,
                None => {
                    let new_map = IndexMap::new();
                    self.entries.insert(entry.label.clone(), new_map);
                    self.entries.get_mut(&entry.label).unwrap()
                }
            };

            match &entry.operation {
                Operation::Upsert => {
                    entries.insert(entry.key.clone(), entry.clone());
                    entries_hash2offset.insert(entry.hash, entry.entry_offset);
                }
                Operation::Delete => {
                    entries.remove(&entry.key);
                    entries_hash2offset.remove(&entry.hash);
                }
            }
        }

        self.entry_hash2offset = entries_hash2offset;

        self
    }

    pub fn iter(&self, label: Option<EntryLabel>) -> impl Iterator<Item = &KvEntry> {
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
    }

    #[test]
    fn test_compute_cumulative_hash() {
        let parent_hash = vec![0, 1, 2, 3];
        let key = vec![4, 5, 6, 7];
        let value = vec![8, 9, 10, 11];
        let cumulative_hash = LedgerKV::_compute_cumulative_hash(&parent_hash, &key, &value);

        // Cumulative hash is a sha256 hash of the parent hash, key, and value
        assert_eq!(
            cumulative_hash,
            vec![
                255, 243, 169, 188, 221, 55, 54, 61, 112, 60, 28, 79, 149, 18, 83, 54, 134, 21,
                120, 104, 240, 212, 241, 106, 15, 2, 208, 241, 218, 36, 249, 162
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
        let entries = ledger_kv.entries.get(&EntryLabel::Unspecified).unwrap();
        assert_eq!(
            entries.get(&key),
            Some(&KvEntry::new(
                EntryLabel::Unspecified,
                key,
                value,
                Operation::Upsert,
                0,
                ledger_kv.metadata.borrow().parent_hash.clone()
            ))
        );
        assert_eq!(ledger_kv.metadata.borrow().num_entries, 1);
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
            Some(&KvEntry::new(
                EntryLabel::NodeProvider,
                key.clone(),
                value.clone(),
                Operation::Upsert,
                0,
                ledger_kv.metadata.borrow().parent_hash.clone()
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
        let expected_hash = ledger_kv.metadata.borrow().parent_hash.clone();
        ledger_kv
            .delete(EntryLabel::Unspecified, key.clone())
            .unwrap();

        // Ensure that the entry is not deleted from the ledger since the entry_type doesn't match
        let entries_np = ledger_kv.entries.get(&EntryLabel::NodeProvider).unwrap();
        assert_eq!(
            entries_np.get(&key),
            Some(&KvEntry::new(
                EntryLabel::NodeProvider,
                key.clone(),
                value.clone(),
                Operation::Upsert,
                0,
                expected_hash
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
        let expected_parent_hash = vec![
            113, 146, 56, 92, 60, 6, 5, 222, 85, 187, 148, 118, 206, 29, 144, 116, 129, 144, 236,
            179, 42, 142, 237, 127, 82, 7, 179, 12, 246, 161, 254, 137,
        ];
        ledger_kv = ledger_kv.refresh_ledger();

        let entry: KvEntry = ledger_kv
            .entries
            .get(&EntryLabel::Unspecified)
            .unwrap()
            .values()
            .next()
            .unwrap()
            .clone();
        assert_eq!(
            entry,
            KvEntry {
                label: EntryLabel::Unspecified,
                key: key,
                value: value,
                operation: Operation::Upsert,
                entry_offset: 0,
                hash: vec![
                    113, 146, 56, 92, 60, 6, 5, 222, 85, 187, 148, 118, 206, 29, 144, 116, 129,
                    144, 236, 179, 42, 142, 237, 127, 82, 7, 179, 12, 246, 161, 254, 137
                ],
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
        ledger_kv = ledger_kv.refresh_ledger();

        assert_eq!(ledger_kv.entries.get(&EntryLabel::Unspecified), None);
        assert_eq!(ledger_kv.metadata.borrow().parent_hash, vec![]);
    }
}
