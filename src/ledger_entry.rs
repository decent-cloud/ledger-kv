use borsh_derive::{BorshDeserialize, BorshSerialize};

/// Enum defining the different labels for entries.
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug, Hash)]
pub enum EntryLabel {
    Unspecified,
    NodeProvider,
}

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
    pub label: EntryLabel,
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
    pub fn new(label: EntryLabel, key: Key, value: Value, operation: Operation) -> Self {
        LedgerEntry {
            label,
            key,
            value,
            operation,
        }
    }
}

/// Implements the `Display` trait for `LedgerEntry`.
impl std::fmt::Display for LedgerEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if let Ok(key) = String::from_utf8(self.key.to_owned()) {
            if let Ok(value) = String::from_utf8(self.value.to_owned()) {
                return write!(f, "Key: {}, Value: {}", key, value);
            }
        }
        write!(
            f,
            "Key: {}, Value: {}",
            String::from_utf8_lossy(&self.key),
            String::from_utf8_lossy(&self.value)
        )
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct LedgerBlock {
    pub(crate) entries: Vec<LedgerEntry>,
    pub(crate) offset: usize,
    pub(crate) hash: Vec<u8>,
}

impl LedgerBlock {
    pub(crate) fn new(entries: Vec<LedgerEntry>, offset: usize, hash: Vec<u8>) -> Self {
        LedgerBlock {
            entries,
            offset,
            hash,
        }
    }
}

/// Implements the `Display` trait for `LedgerBlock`.
impl std::fmt::Display for LedgerBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "@{}", self.offset)?;
        for entry in &self.entries {
            write!(f, "\n{}", entry)?
        }
        write!(f, "\nHash: {}", hex::encode(self.hash.as_slice()))
    }
}
