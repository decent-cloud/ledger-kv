# LedgerKV

## Overview

LedgerKV is a key-value store implemented in Rust. The primary feature of this library is its ability to store data in an append-only fashion, effectively forming a ledger. Additionally, it supports data integrity checks using SHA-256 checksums for ledger entries.

This library is designed for use in smart contract environments, capable of compiling for `wasm32` targets while also being usable and testable on `x86_64` architectures.

> **Note**: This library is still in the development stage. Use it at your own risk.

## Installation

Add LedgerKV to your `Cargo.toml`:

```toml
[dependencies]
ledger-kv = "0.1.0"
```

## Usage

Here is a basic example to get you started:

```rust
use ledger_kv::LedgerKV;  // Replace with your actual library name
use ledger_kv::EntryLabel;
use ledger_kv::Operation;

let data_dir = PathBuf::from("/tmp/data/");
let description = "example_ledger";

// Create a new LedgerKV instance
let mut ledger = LedgerKV::new(data_dir, description);

// Perform an upsert (insert/update) operation
let key = vec![1, 2, 3];
let value = vec![4, 5, 6];
ledger.upsert(EntryLabel::NodeProvider, key, value).unwrap();

// Perform a delete operation
let key = vec![1, 2, 3];
ledger.delete(EntryLabel::NodeProvider, key).unwrap();
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
