/// This file contains the implementation of a command-line interface (CLI) for interacting with the LedgerKV library.
///
/// The CLI allows various ledger operations, such as listing, inserting/updating (upserting), and deleting entries.
///
use ledger_kv::{platform_specific, LedgerKV};

use borsh::{BorshDeserialize, BorshSerialize};
use clap::{arg, Arg, Command};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Once;

/// Struct to hold the parsed command-line arguments
struct ParsedArgs {
    list: bool,
    upsert: Option<(String, String)>,
    delete: Option<String>,
    path: Option<String>,
}

/// Parse the command-line arguments using clap library
fn parse_args() -> ParsedArgs {
    let matches = Command::new("LedgerKV CLI")
        .about("LedgerKV CLI")
        .arg(arg!(--list "List entries").required(false))
        .arg(
            Arg::new("upsert")
                .long("upsert")
                .help("Upsert key-value pair")
                .num_args(2),
        )
        .arg(arg!(--delete <KEY> "Delete key").required(false))
        .arg(arg!(--path <VALUE> "Specify file path for the ledger").required(false))
        .get_matches();

    let list = *matches.get_one::<bool>("list").unwrap_or(&false);

    let upsert = matches.get_many::<String>("upsert").map(|mut values| {
        (
            values.next().unwrap().to_string(),
            values.next().unwrap().to_string(),
        )
    });

    let delete = matches.get_one::<String>("delete").map(|s| s.to_string());

    let path = matches.get_one::<String>("path").map(|s| s.to_string());

    ParsedArgs {
        list,
        upsert,
        delete,
        path,
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug, Hash)]
pub enum EntryLabel {
    Unspecified,
    NodeProvider,
}

fn logs_init() {
    // Set log level to info by default
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }
    env_logger::init_from_env("RUST_LOG");
}

static INIT: Once = Once::new();

pub fn initialize() {
    INIT.call_once(|| {
        logs_init();
    });
}

fn main() -> anyhow::Result<()> {
    logs_init();

    // Parse the command-line arguments
    let args = parse_args();

    // Extract the file path from the parsed arguments
    let ledger_path = args.path.as_ref().map(|p| PathBuf::from_str(p).unwrap());

    platform_specific::override_backing_file(ledger_path);
    let mut ledger_kv = LedgerKV::new().expect("Failed to create ledger");

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

    if let Some((key, value)) = args.upsert {
        // Upsert (insert/update) an entry in the ledger
        ledger_kv.upsert(
            EntryLabel::Unspecified,
            key.as_bytes().to_vec(),
            value.as_bytes().to_vec(),
        )?;
        println!("Upsert entry with KEY: {}, VALUE: {}", key, value);
    }

    if let Some(key) = args.delete {
        // Delete an entry from the ledger
        ledger_kv.delete(EntryLabel::Unspecified, key.as_bytes().to_vec())?;
        println!("Delete entry with KEY: {}", key);
    }

    Ok(())
}
