use borsh::{from_slice, to_vec, BorshDeserialize};
use borsh_derive::{BorshDeserialize, BorshSerialize};
use fs_err as fs;
use fs_err::{File, OpenOptions};
use log::{info, warn};
use memmap2::Mmap;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use crate::data_rw_trait::LedgerKvMetadata;

/// Struct representing the metadata of the ledger.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub(crate) struct Metadata {
    /// The name of the file associated with the metadata.
    pub(crate) file_name: String,
    #[borsh(skip)]
    /// The path where the file is located.
    pub(crate) file_path: PathBuf,
    /// The number of entries in the ledger.
    pub(crate) num_entries: usize,
    /// The last offset in the file.
    pub(crate) last_offset: usize,
    /// The hash of the parent metadata.
    pub(crate) parent_hash: Vec<u8>,
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
}

impl LedgerKvMetadata for Metadata {
    /// Saves the metadata to a file.
    fn save(&self) {
        let mut file = File::create(&self.file_path).unwrap();
        let metadata_bytes = to_vec(self).unwrap();
        file.write_all(&metadata_bytes).unwrap();
    }

    /// Refreshes the metadata by reading from the file.
    fn refresh(&mut self) {
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

    fn get_num_entries(&self) -> usize {
        self.num_entries
    }

    fn inc_num_entries(&mut self) {
        self.num_entries += 1;
    }

    fn get_parent_hash(&self) -> &[u8] {
        self.parent_hash.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fs_err::File;
    use std::io::{Read, Write};

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
}
