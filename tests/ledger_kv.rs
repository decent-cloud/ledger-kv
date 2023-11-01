use borsh::to_vec;
use fs_err::File;
use ledger_kv::Metadata;
use std::io::Write;

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
