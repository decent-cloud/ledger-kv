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
//!     let data_dir = PathBuf::from("data");
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
use ahash::AHashMap;
use borsh::{from_slice, to_vec, BorshDeserialize};
use borsh_derive::{BorshDeserialize, BorshSerialize};
use fs_err as fs;
use fs_err::{File, OpenOptions};
use indexmap::IndexMap;
use log::{info, warn};
use memmap2::Mmap;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

/// Enum defining the different labels for entries.
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug, Hash)]
pub enum EntryLabel {
    Unspecified,
    NodeProvider,
}

/// Enum defining the different operations that can be performed on entries.
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub enum Operation {
    Upsert,
    Delete,
}

/// Struct representing a key-value entry.
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct KvEntry {
    pub label: EntryLabel,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub operation: Operation,
    file_offset: usize,
    hash: Vec<u8>,
}

impl KvEntry {
    /// Creates a new `KvEntry` instance.
    ///
    /// # Arguments
    ///
    /// * `label` - The label of the entry.
    /// * `key` - The key of the entry.
    /// * `value` - The value of the entry.
    /// * `operation` - The operation to be performed on the entry.
    /// * `file_offset` - The file offset of the entry.
    /// * `hash` - The hash of the entry.
    ///
    /// # Returns
    ///
    /// A new `KvEntry` instance.
    pub fn new(
        label: EntryLabel,
        key: Vec<u8>,
        value: Vec<u8>,
        operation: Operation,
        file_offset: usize,
        hash: Vec<u8>,
    ) -> Self {
        KvEntry {
            label,
            key,
            value,
            operation,
            file_offset,
            hash,
        }
    }
}

/// Implements the `Display` trait for `KvEntry`.
impl std::fmt::Display for KvEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if let Ok(key) = String::from_utf8(self.key.to_owned()) {
            if let Ok(value) = String::from_utf8(self.value.to_owned()) {
                return write!(f, "@{} Key: {}, Value: {}", self.file_offset, key, value);
            }
        }
        write!(
            f,
            "@{} Key: {}, Value: {}",
            self.file_offset,
            String::from_utf8_lossy(&self.key),
            String::from_utf8_lossy(&self.value)
        )
    }
}

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
            Self::_compute_cumulative_hash(&self.metadata.borrow().parent_hash, &key, &value);
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
                    entries_hash2offset.insert(entry.hash, entry.file_offset);
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

/// Struct representing the metadata of the ledger.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct Metadata {
    /// The name of the file associated with the metadata.
    pub file_name: String,
    #[borsh(skip)]
    /// The path where the file is located.
    pub file_path: PathBuf,
    /// The number of entries in the ledger.
    pub num_entries: u64,
    /// The last offset in the file.
    pub last_offset: usize,
    /// The hash of the parent metadata.
    pub parent_hash: Vec<u8>,
}

impl Metadata {
    /// Creates a new instance of `Metadata`.
    ///
    /// # Arguments
    ///
    /// * `data_dir` - The directory where the data is stored.
    /// * `description` - A description for the metadata.
    ///
    /// # Returns
    ///
    /// A new instance of `Metadata`.
    pub fn new(data_dir: PathBuf, description: &str) -> Self {
        let file_name = format!("{}.meta", description);
        let mut file_path = data_dir.join(&file_name);
        file_path.set_extension("meta");
        let num_entries = 0;
        let last_offset = 0;
        let parent_hash = Vec::new();

        Metadata {
            file_name,
            file_path,
            num_entries,
            last_offset,
            parent_hash,
        }
    }

    /// Saves the metadata to a file.
    pub fn save(&self) {
        let mut file = File::create(&self.file_path).unwrap();
        let metadata_bytes = to_vec(self).unwrap();
        file.write_all(&metadata_bytes).unwrap();
    }

    /// Refreshes the metadata by reading from the file.
    pub fn refresh(&mut self) {
        if !self.file_path.exists() {
            warn!(
                "Metadata refresh: file {} does not exist",
                self.file_path.display()
            );
            return;
        }
        let mut file = File::open(&self.file_path).unwrap();
        let mut metadata_bytes = Vec::new();
        file.read_to_end(&mut metadata_bytes).unwrap_or_else(|_| {
            panic!(
                "Metadata refresh: failed to read file {}",
                self.file_path.display()
            )
        });

        let deserialized_metadata: Metadata = from_slice::<Metadata>(&metadata_bytes).unwrap();
        self.num_entries = deserialized_metadata.num_entries;
        self.last_offset = deserialized_metadata.last_offset;
        self.parent_hash = deserialized_metadata.parent_hash;
        info!(
            "Read metadata of num_entries {} last_offset {}",
            self.num_entries, self.last_offset
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fs_err::File;
    use std::io::{Read, Write};
    use tempfile::tempdir;

    #[test]
    fn test_save() {
        // Create a temporary file for testing
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("metadata.bin");

        // Create a Metadata instance
        let metadata = Metadata {
            file_name: String::from("metadata.bin"),
            file_path: file_path.clone(),
            num_entries: 10,
            last_offset: 0,
            parent_hash: vec![0, 1, 2, 3],
        };

        // Call the save method
        metadata.save();

        // Read the contents of the file
        let mut file = File::open(file_path).unwrap();
        let mut metadata_bytes = Vec::new();
        file.read_to_end(&mut metadata_bytes).unwrap();

        // Deserialize the metadata bytes
        let deserialized_metadata: Metadata = from_slice::<Metadata>(&metadata_bytes).unwrap();

        // Assert that the deserialized metadata matches the original metadata
        assert_eq!(deserialized_metadata.file_name, "metadata.bin");
        assert_eq!(deserialized_metadata.num_entries, 10);
        assert_eq!(deserialized_metadata.parent_hash, vec![0, 1, 2, 3]);
    }

    #[test]
    fn test_refresh() {
        // Create a temporary file for testing
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("metadata.bin");

        // Create a Metadata instance
        let mut metadata = Metadata {
            file_name: String::from("metadata.bin"),
            file_path: file_path.clone(),
            num_entries: 0,
            last_offset: 0,
            parent_hash: Vec::new(),
        };

        // Write some metadata bytes to the file
        let serialized_metadata: Vec<u8> = to_vec(&metadata).unwrap();
        let mut file = File::create(&file_path).unwrap();
        file.write_all(&serialized_metadata).unwrap();

        // Call the refresh method
        metadata.refresh();

        // Assert that the metadata fields are correctly refreshed
        assert_eq!(metadata.num_entries, 0);
        assert_eq!(metadata.parent_hash, Vec::new());
    }

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
