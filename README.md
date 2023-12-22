# LedgerKV

## Overview

LedgerKV is a key-value store implemented in Rust. The primary feature of this library is its ability to store data in an append-only fashion, effectively forming a ledger. Additionally, it supports data integrity checks using SHA-256 checksums for ledger entries.

This library is designed for use in smart contract environments, capable of compiling for `wasm32` targets while also being usable and testable on `x86_64` architectures.

> **Note**: This library is still in the development stage. Use it at your own risk.

## Installation

Add LedgerKV to your `Cargo.toml`:

```toml
[dependencies]
ledger-kv = "0.1.1"
```

## Usage

Here is a basic example to get you started:

```rust
use std::path::PathBuf;
use ledger_kv::{LedgerKV, EntryLabel, Operation};
use ledger_kv::data_store::{DataBackend, MetadataBackend};

fn main() {
  let file_path = PathBuf::from("/tmp/ledger_kv/test_data.bin");
  let data_backend = DataBackend::new(file_path.with_extension("bin"));
  let metadata_backend = MetadataBackend::new(file_path.with_extension("meta"));

  // Create a new LedgerKV instance
  let mut ledger_kv = LedgerKV::new(data_backend, metadata_backend).expect("Failed to create LedgerKV");

  // Insert a new entry
  let label = EntryLabel::Unspecified;
  let key = b"key".to_vec();
  let value = b"value".to_vec();
  ledger_kv.upsert(label.clone(), key.clone(), value.clone()).unwrap();
  ledger_kv.upsert(label.clone(), b"key2".to_vec(), b"value2".to_vec()).unwrap();
  ledger_kv.commit_block().unwrap();

  // Retrieve all entries
  let entries = ledger_kv.iter(None).collect::<Vec<_>>();
  println!("All entries: {:?}", entries);

  // Delete an entry
  ledger_kv.delete(label, key).unwrap();
  ledger_kv.commit_block().unwrap();
}
```

## Features
* Append-Only Storage: Data is stored in an append-only manner, forming a ledger.
* Data Integrity: Uses SHA-256 checksums for verifying the integrity of ledger entries.
* Platform Support: Designed to work on both wasm32 and x86_64 targets.

##  Dependencies
This library is implemented in pure Rust.

## Contributing
We welcome contributions! Please submit a pull request if you would like to contribute.

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
