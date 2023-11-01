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

/// Struct representing a key-value entry.
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Debug)]
pub struct KvEntry {
    pub label: EntryLabel,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub operation: Operation,
    pub(crate) entry_offset: usize,
    pub(crate) hash: Vec<u8>,
}

impl KvEntry {
    /// Creates a new `KvEntry` instance.
    ///
    /// # Arguments
    ///
    /// * `label` - The label of the entry.
    /// * `key` - The key of the entry.
    /// * `value` - The value of the entry.
    /// * `operation` - The operation to be performed on the entry.
    /// * `entry_offset` - The offset where the entry starts.
    /// * `hash` - The hash of the entry.
    ///
    /// # Returns
    ///
    /// A new `KvEntry` instance.
    pub fn new(
        label: EntryLabel,
        key: Vec<u8>,
        value: Vec<u8>,
        operation: Operation,
        entry_offset: usize,
        hash: Vec<u8>,
    ) -> Self {
        KvEntry {
            label,
            key,
            value,
            operation,
            entry_offset,
            hash,
        }
    }
}

/// Implements the `Display` trait for `KvEntry`.
impl std::fmt::Display for KvEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if let Ok(key) = String::from_utf8(self.key.to_owned()) {
            if let Ok(value) = String::from_utf8(self.value.to_owned()) {
                return write!(f, "@{} Key: {}, Value: {}", self.entry_offset, key, value);
            }
        }
        write!(
            f,
            "@{} Key: {}, Value: {}",
            self.entry_offset,
            String::from_utf8_lossy(&self.key),
            String::from_utf8_lossy(&self.value)
        )
    }
}
