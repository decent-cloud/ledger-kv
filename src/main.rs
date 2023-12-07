/// This file contains the implementation of a command-line interface (CLI) for interacting with the LedgerKV library.
///
/// The CLI allows users to perform various operations on a ledger, such as listing entries, adding key-value pairs, and deleting entries.
///
use ledger_kv::data_store;

use data_store::{DataBackend, MetadataBackend};

use clap::{arg, Arg, Command};
use ledger_kv::{EntryLabel, LedgerKV};
use std::path::PathBuf;
use std::str::FromStr;

/// Struct to hold the parsed command-line arguments
struct ParsedArgs {
    list: bool,
    add: Option<(String, String)>,
    delete: Option<String>,
    directory: Option<String>,
}

/// Parse the command-line arguments using clap library
fn parse_args() -> ParsedArgs {
    let matches = Command::new("LedgerKV CLI")
        .about("LedgerKV CLI")
        .arg(arg!(--list "List entries").required(false))
        .arg(
            Arg::new("add")
                .long("add")
                .help("Add key-value pair")
                .num_args(2),
        )
        .arg(arg!(--delete <KEY> "Delete key").required(false))
        .arg(
            arg!(--directory <VALUE> "Specify directory to store ledger")
                .required(false)
                .default_value("."),
        )
        .get_matches();

    let list = *matches.get_one::<bool>("list").unwrap_or(&false);

    let add = matches.get_many::<String>("add").map(|mut values| {
        (
            values.next().unwrap().to_string(),
            values.next().unwrap().to_string(),
        )
    });

    let delete = matches.get_one::<String>("delete").map(|s| s.to_string());

    let directory = matches
        .get_one::<String>("directory")
        .map(|s| s.to_string());

    ParsedArgs {
        list,
        add,
        delete,
        directory,
    }
}

fn main() -> anyhow::Result<()> {
    // Parse the command-line arguments
    let args = parse_args();

    // Extract the directory path from the parsed arguments
    let dir = args.directory.as_ref().expect("directory not provided");
    let data_dir = PathBuf::from_str(dir)
        .map_err(|e| format!("Failed to parse directory path {}: {}", dir, e))
        .unwrap();

    let file_path = data_dir.join("ledger_store");
    let data_backend = DataBackend::new(file_path.with_extension("bin"));
    let metadata_backend = MetadataBackend::new(file_path.with_extension("meta"));
    let mut ledger_kv = LedgerKV::new(data_backend, metadata_backend);

    if args.list {
        println!("Listing entries:");
        // Iterate over the entries in the ledger and print them
        for entry in ledger_kv.iter(None) {
            println!(
                "Key: {}, Value: {}",
                String::from_utf8_lossy(&entry.key),
                String::from_utf8_lossy(&entry.value)
            );
        }
    }

    if let Some((key, value)) = args.add {
        // Add or update an entry in the ledger
        ledger_kv.upsert(
            EntryLabel::Unspecified,
            key.as_bytes().to_vec(),
            value.as_bytes().to_vec(),
        )?;
        println!("Add entry with KEY: {}, VALUE: {}", key, value);
    }

    if let Some(key) = args.delete {
        // Delete an entry from the ledger
        ledger_kv.delete(EntryLabel::Unspecified, key.as_bytes().to_vec())?;
        println!("Delete entry with KEY: {}", key);
    }

    Ok(())
}
