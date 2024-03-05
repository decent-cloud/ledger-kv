use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use borsh::{BorshDeserialize, BorshSerialize};

/// Enum defining the different operations that can be performed on entries.
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub enum Operation {
    Upsert,
    Delete,
}

pub type Key = Vec<u8>;
pub type Value = Vec<u8>;

/// Struct representing an entry stored for a particular key in the key-value store.
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct LedgerEntry {
    pub label: String,
    pub key: Key,
    pub value: Value,
    pub operation: Operation,
}

impl LedgerEntry {
    /// Creates a new `LedgerEntry` instance.
    ///
    /// # Arguments
    ///
    /// * `label` - The label of the entry.
    /// * `key` - The key of the entry.
    /// * `value` - The value of the entry.
    /// * `operation` - The operation to be performed on the entry.
    ///
    /// # Returns
    ///
    /// A new `LedgerEntry` instance.
    pub fn new<S: AsRef<str>>(label: S, key: Key, value: Value, operation: Operation) -> Self {
        LedgerEntry {
            label: label.as_ref().to_string(),
            key,
            value,
            operation,
        }
    }
}

impl std::fmt::Display for LedgerEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let key = match String::from_utf8(self.key.clone()) {
            Ok(v) => v,
            Err(_) => BASE64.encode(self.key.clone()),
        };
        let value = match String::from_utf8(self.value.clone()) {
            Ok(v) => v,
            Err(_) => BASE64.encode(self.value.clone()),
        };
        write!(f, "[{}] Key: {}, Value: {}", self.label, key, value)
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct LedgerBlock {
    pub(crate) entries: Vec<LedgerEntry>,
    pub(crate) offset: u64,
    pub(crate) offset_next: Option<u64>,
    pub(crate) timestamp: u64,
    pub(crate) hash: Vec<u8>,
}

impl LedgerBlock {
    pub(crate) fn new(
        entries: Vec<LedgerEntry>,
        offset: u64,
        offset_next: Option<u64>,
        timestamp: u64,
        hash: Vec<u8>,
    ) -> Self {
        LedgerBlock {
            entries,
            offset,
            offset_next,
            timestamp,
            hash,
        }
    }
}

impl std::fmt::Display for LedgerBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "[{}] ~-=-~-=-~-=-~ Ledger block at offsets 0x{:x} .. {:x?} hash {}",
            self.timestamp,
            self.offset,
            self.offset_next,
            hex::encode(self.hash.as_slice())
        )?;
        for entry in &self.entries {
            write!(f, "\n[{}] {}", self.timestamp, entry)?
        }
        Ok(())
    }
}
