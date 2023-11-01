//! This module implements a key-value storage system called LedgerKV.
//!
//! The LedgerKV struct provides methods for inserting, deleting, and retrieving key-value entries.
//! It uses a journaling approach to store the entries in a binary file. Each entry is appended to the
//! file along with its length, allowing efficient retrieval and updates.
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
//!
//! fn main() {
//!     let data_dir = PathBuf::from("/tmp/ledger_kv/data");
//!     let description = "example";
//!
//!     // Create a new LedgerKV instance
//!     let mut ledger_kv = LedgerKV::new(data_dir, description);
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

mod kv_entry;
mod data_rw_trait;
use data_rw_trait::LedgerKvMetadata;

#[cfg(target_arch = "wasm32")]
mod data_rw_wasm32_ic;
#[cfg(target_arch = "wasm32")]
use data_rw_wasm32_ic as data_rw;

#[cfg(not(target_arch = "wasm32"))]
mod data_rw_native;
#[cfg(not(target_arch = "wasm32"))]
use data_rw_native as data_rw;

use ahash::AHashMap;
use borsh::{to_vec, BorshDeserialize};
use data_rw::Metadata;
use fs_err as fs;
use fs_err::{File, OpenOptions};
use indexmap::IndexMap;
use log::{info, warn};
use memmap2::Mmap;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::io::{Cursor, Seek, SeekFrom, Write};
use std::path::PathBuf;
pub use kv_entry::{KvEntry, EntryLabel, Operation};

/// Struct representing the LedgerKV.
pub struct LedgerKV {
    pub file_path: PathBuf,
    metadata: RefCell<Metadata>,
    entries: AHashMap<EntryLabel, IndexMap<Vec<u8>, KvEntry>>,
    entry_hash2offset: IndexMap<Vec<u8>, usize>,
}

impl LedgerKV {
    /// Creates a new `LedgerKV` instance.
    ///
    /// # Arguments
    ///
    /// * `data_dir` - The directory where the ledger data is stored.
    /// * `description` - A description of the ledger.
    ///
    /// # Returns
    ///
    /// A new `LedgerKV` instance.
    pub fn new(data_dir: PathBuf, description: &str) -> Self {
        fs::create_dir_all(&data_dir).unwrap();
        let mut file_path = data_dir.join(description);
        file_path.set_extension("bin");
        let metadata = Metadata::new(data_dir.clone(), description);
        let entries = AHashMap::new();
        let entries_hashes = IndexMap::new();

        LedgerKV {
            file_path,
            metadata: RefCell::new(metadata),
            entries,
            entry_hash2offset: entries_hashes,
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

    fn _get_append_journal_file(&self) -> anyhow::Result<File> {
        OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.file_path)
            .map_err(|e| anyhow::format_err!("Open file failed: {}", e))
    }

    fn _journal_append_kv_entry(&self, entry: &KvEntry) -> anyhow::Result<()> {
        // Prepare entry as serialized bytes
        let serialized_data = to_vec(&entry)?;
        // Prepare entry len, as bytes
        let entry_len_bytes = serialized_data.len();
        let serialized_data_len = to_vec(&entry_len_bytes).expect("failed to serialize entry len");

        let mut file = self._get_append_journal_file()?;
        // Append entry len, as bytes
        file.write_all(&serialized_data_len)
            .map_err(|e| anyhow::format_err!("Append file failed: {}", e))?;
        // Append entry
        file.write_all(&serialized_data)
            .map_err(|e| anyhow::format_err!("Append file failed: {}", e))?;

        println!("Entry hash: {:?}", entry.hash);
        self.metadata.borrow_mut().num_entries += 1;
        self.metadata.borrow_mut().parent_hash = entry.hash.clone();
        self.metadata.borrow_mut().last_offset = file.stream_position()? as usize;
        self.metadata.borrow_mut().save();
        self.metadata.borrow_mut().refresh();
        Ok(())
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

        // If the file does not exist, just return
        if !self.file_path.exists() {
            return self;
        }

        let mut entries_hash2offset = IndexMap::new();

        for entry in self.iter_raw().collect::<Vec<_>>() {
            // Update the in-memory IndexMap of entries, used for quick lookups

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

    pub fn iter_raw(&self) -> impl Iterator<Item = KvEntry> + '_ {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&self.file_path)
            .expect("failed to open ledger file");
        let mmap = unsafe { Mmap::map(&file).unwrap() };
        self.metadata.borrow_mut().refresh();
        let cursor = Cursor::new(mmap);

        info!("Num entries: {}", self.metadata.borrow().num_entries);
        // scan is used to build a lazy iterator
        // it gives us a way to maintain state between calls to the iterator
        // (in this case, the Cursor and parent_hash).
        let iterator =
            (0..self.metadata.borrow().num_entries).scan((cursor, Vec::new()), |state, _| {
                let (cursor, parent_hash) = state;
                let mut slice_begin = cursor.position() as usize;
                let mut slice = &cursor.get_ref()[slice_begin..];

                let entry_len_bytes = match usize::deserialize(&mut slice) {
                    Ok(len) => len,
                    Err(_) => panic!("Deserialize error"),
                };

                let size_of_usize = std::mem::size_of_val(&entry_len_bytes);
                slice_begin = cursor.position() as usize + size_of_usize;
                let mut slice = &cursor.get_ref()[slice_begin..];

                let entry = match KvEntry::deserialize(&mut slice) {
                    Ok(entry) => entry,
                    Err(_) => panic!("Deserialize error"),
                };

                let expected_hash =
                    Self::_compute_cumulative_hash(parent_hash, &entry.key, &entry.value);
                assert_eq!(expected_hash, entry.hash);
                parent_hash.clear();
                parent_hash.extend_from_slice(&entry.hash);

                let seek_offset = size_of_usize + entry_len_bytes;
                cursor
                    .seek(SeekFrom::Current(seek_offset as i64))
                    .expect("Seek error");

                Some(entry)
            });

        iterator
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn new_temp_ledger() -> LedgerKV {
        let data_dir = tempdir().unwrap().into_path();
        let file_name = "test.bin";
        LedgerKV::new(data_dir.clone(), file_name)
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
    fn test_get_append_journal_file() {
        let ledger_kv = new_temp_ledger();
        let result = ledger_kv._get_append_journal_file();
        assert!(result.is_ok());
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
        let parent_hash = ledger_kv.metadata.borrow().parent_hash.clone();
        fs::remove_file(ledger_kv.file_path.clone()).unwrap();
        ledger_kv = ledger_kv.refresh_ledger();

        assert_eq!(ledger_kv.entries.get(&EntryLabel::Unspecified), None);
        assert_eq!(ledger_kv.metadata.borrow().parent_hash, parent_hash);
    }
}
