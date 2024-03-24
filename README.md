# LedgerKV

## Overview

LedgerKV is a key-value store implemented in Rust. The primary feature of this library is its ability to store data in an append-only fashion, effectively forming a ledger. Additionally, it supports data integrity checks using SHA-256 checksums for ledger entries.

This library is designed for use in smart contract environments, capable of compiling for `wasm32` targets while also being usable and testable on `x86_64` architectures.

> **Note**: This library is still in the development stage. Use it at your own risk.

## Installation

Add LedgerKV to your `Cargo.toml`:

```toml
[dependencies]
ledger-kv = "0.2.0"
```

## Usage

Here is a basic example to get you started:

```rust
use ledger_kv::LedgerKV;

fn main() {
    // Create a new LedgerKV instance
    let mut ledger_kv = LedgerKV::new().expect("Failed to create LedgerKV");

    // Insert a few new entries, each with a separate label
    ledger_kv.upsert("Label1", b"key1".to_vec(), b"value1".to_vec()).unwrap();
    ledger_kv.upsert("Label2", b"key2".to_vec(), b"value2".to_vec()).unwrap();
    ledger_kv.commit_block().unwrap();

    // Retrieve all entries
    let entries = ledger_kv.iter(None).collect::<Vec<_>>();
    println!("All entries: {:?}", entries);
    // Only entries with the Label1 label
    let entries = ledger_kv.iter(Some("Label1")).collect::<Vec<_>>();
    println!("Label1 entries: {:?}", entries);
    // Only entries with the Label2 label
    let entries = ledger_kv.iter(Some("Label2")).collect::<Vec<_>>();
    println!("Label2 entries: {:?}", entries);

    // Delete an entry
    ledger_kv.delete("Label1", b"key1".to_vec()).unwrap();
    ledger_kv.commit_block().unwrap();
    // Label1 entries are now empty
    assert_eq!(ledger_kv.iter(Some("Label1")).count(), 0);
    // Label2 entries still exist
    assert_eq!(ledger_kv.iter(Some("Label2")).count(), 1);
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
