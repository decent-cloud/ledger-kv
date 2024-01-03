use borsh::BorshDeserialize;
use fs_err as fs;
use fs_err::{File, OpenOptions};
use log::warn;
use memmap2::Mmap;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

#[derive(Clone, Debug, Default)]
pub struct MetadataBackend {
    /// The full path to the metadata file.
    pub(crate) file_path: PathBuf,
}

impl MetadataBackend {
    pub fn new(file_path: PathBuf) -> Self {
        fs::create_dir_all(file_path.parent().expect("Could not find parent directory")).unwrap();
        MetadataBackend { file_path }
    }

    pub(crate) fn save_raw_metadata_bytes(&self, metadata_bytes: &[u8]) -> anyhow::Result<()> {
        let mut file = File::create(&self.file_path)?;
        file.write_all(metadata_bytes)
            .map_err(|e| anyhow::format_err!("Write to file failed: {}", e))
    }

    pub(crate) fn read_raw_metadata_bytes(&self) -> Vec<u8> {
        if self.file_path.exists() {
            let mut file = File::open(&self.file_path).unwrap();
            let mut metadata_bytes = Vec::new();
            file.read_to_end(&mut metadata_bytes).unwrap_or_else(|_| {
                panic!(
                    "Metadata refresh: failed to read file {}",
                    self.file_path.display()
                )
            });
            metadata_bytes
        } else {
            warn!(
                "Metadata refresh: file {} does not exist",
                self.file_path.display()
            );
            Vec::new()
        }
    }
}

pub struct DataBackend {
    /// The name of the file in which the data is stored.
    /// Right now, we only use a single file, but this can be changed in the future.
    pub(crate) file_path: PathBuf,
}

impl DataBackend {
    pub fn new(file_path: PathBuf) -> Self {
        fs::create_dir_all(file_path.parent().expect("Could not find parent directory")).unwrap();
        if !file_path.exists() {
            File::create(&file_path).expect("Failed to create a file");
        }
        DataBackend { file_path }
    }

    pub(crate) fn append_to_ledger(&self, bytes: &[u8]) -> anyhow::Result<usize> {
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.file_path)
            .map_err(|e| anyhow::format_err!("Open file failed: {}", e))?;

        file.write_all(bytes)
            .map_err(|e| anyhow::format_err!("Append file failed: {}", e))?;

        Ok(file.stream_position()? as usize)
    }

    pub fn ready(&self) -> bool {
        self.file_path.exists()
    }

    pub fn iter_raw(&self, num_blocks: usize) -> impl Iterator<Item = Vec<u8>> + '_ {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&self.file_path)
            .expect("failed to open ledger file");
        let mmap = unsafe { Mmap::map(&file).unwrap() };
        let cursor = Cursor::new(mmap);

        // scan is used to build a lazy iterator
        // it gives us a way to maintain state between calls to the iterator
        // (in this case, the Cursor).
        let iterator = (0..num_blocks).scan(cursor, |state, _| {
            let cursor = state;
            let mut slice_begin = cursor.position() as usize;
            let mut slice = &cursor.get_ref()[slice_begin..];

            let entry_len_bytes = match usize::deserialize(&mut slice) {
                Ok(len) => len,
                Err(_) => panic!("Deserialize error"),
            };

            let size_of_usize = std::mem::size_of_val(&entry_len_bytes);
            slice_begin = cursor.position() as usize + size_of_usize;
            let slice = &cursor.get_ref()[slice_begin..];
            let entry = slice.to_vec();

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
    use crate::Metadata;
    use borsh::{from_slice, to_vec};
    use fs_err::File;
    use std::io::{Read, Write};

    #[test]
    fn test_save() {
        let (file_path, mut metadata) = create_temp_metadata();

        metadata.num_blocks = 10;
        metadata.parent_hash = vec![0, 1, 2, 3];

        // Call the save method
        metadata
            .metadata_backend
            .save_raw_metadata_bytes(&to_vec(&metadata).unwrap())
            .unwrap();

        // Read the contents of the file
        let mut file = File::open(file_path).unwrap();
        let mut metadata_bytes = Vec::new();
        file.read_to_end(&mut metadata_bytes).unwrap();

        // Deserialize the metadata bytes
        let deserialized_metadata: Metadata = from_slice::<Metadata>(&metadata_bytes).unwrap();

        // Assert that the deserialized metadata matches the original metadata
        assert_eq!(deserialized_metadata.num_blocks, 10);
        assert_eq!(deserialized_metadata.parent_hash, vec![0, 1, 2, 3]);
    }

    #[test]
    fn test_refresh() {
        let (file_path, mut metadata) = create_temp_metadata();

        // Write some metadata bytes to the file
        let serialized_metadata: Vec<u8> = to_vec(&metadata).unwrap();
        let mut file = File::create(file_path).unwrap();
        file.write_all(&serialized_metadata).unwrap();

        // Call the refresh method
        metadata.refresh();

        // Assert that the metadata fields are correctly refreshed
        assert_eq!(metadata.num_blocks, 0);
        assert_eq!(metadata.parent_hash, Vec::new());
    }

    fn create_temp_metadata() -> (PathBuf, Metadata) {
        // Create a temporary directory for the test
        let file_path = tempfile::tempdir()
            .unwrap()
            .into_path()
            .join("test_ledger_store.meta");
        // let data_backend = DataBackend::new(file_path.join("test_ledger_store.bin"));
        let metadata_backend = MetadataBackend::new(file_path.clone());

        // Create a Metadata instance
        (file_path, Metadata::new(metadata_backend))
    }
}
