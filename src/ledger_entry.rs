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
pub struct LedgerEntry<TL> {
    pub label: TL,
    pub key: Key,
    pub value: Value,
    pub operation: Operation,
}

impl<TL> LedgerEntry<TL> {
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
    pub fn new(label: TL, key: Key, value: Value, operation: Operation) -> Self {
        LedgerEntry {
            label,
            key,
            value,
            operation,
        }
    }
}

/// Implements the `Display` trait for `LedgerEntry`.
impl<TL> std::fmt::Display for LedgerEntry<TL> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let key = match String::from_utf8(self.key.clone()) {
            Ok(v) => v,
            Err(_) => BASE64.encode(self.key.clone()),
        };
        let value = match String::from_utf8(self.value.clone()) {
            Ok(v) => v,
            Err(_) => BASE64.encode(self.value.clone()),
        };
        write!(f, "Key: {}, Value: {}", key, value)
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct LedgerBlock<TL> {
    pub(crate) entries: Vec<LedgerEntry<TL>>,
    pub(crate) offset: u64,
    pub(crate) offset_next: Option<u64>,
    pub(crate) timestamp: u64,
    pub(crate) hash: Vec<u8>,
}

impl<TL> LedgerBlock<TL> {
    pub(crate) fn new(
        entries: Vec<LedgerEntry<TL>>,
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

/// Implements the `Display` trait for `LedgerBlock`.
impl<TL> std::fmt::Display for LedgerBlock<TL> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "offset 0x{:x} offset_next {:x?} timestamp {}",
            self.offset, self.offset_next, self.timestamp
        )?;
        for entry in &self.entries {
            write!(f, "\n{}", entry)?
        }
        write!(f, "\nHash: {}", hex::encode(self.hash.as_slice()))
    }
}
