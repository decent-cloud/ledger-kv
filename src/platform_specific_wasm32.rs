pub use crate::{error, info, warn};
use ic_canister_log::{declare_log_buffer, export, log};
use ic_cdk::println;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::fmt;
use std::thread::LocalKey;

// Keep up to "capacity" last messages.
declare_log_buffer!(name = INFO, capacity = 10000);
declare_log_buffer!(name = WARN, capacity = 10000);
declare_log_buffer!(name = ERROR, capacity = 10000);

#[macro_export]
macro_rules! info {
    ($message:expr $(,$args:expr)* $(,)*) => {{
        log!($crate::platform_specific_wasm32::INFO, $message $(,$args)*);
    }}
}

#[macro_export]
macro_rules! warn {
    ($message:expr $(,$args:expr)* $(,)*) => {{
        log!($crate::platform_specific_wasm32::WARN, $message $(,$args)*);
    }}
}

#[macro_export]
macro_rules! error {
    ($message:expr $(,$args:expr)* $(,)*) => {{
        log!($crate::platform_specific_wasm32::ERROR, $message $(,$args)*);
    }}
}

pub const PERSISTENT_STORAGE_PAGE_SIZE: u64 = 64 * 1024;

lazy_static::lazy_static! {
    pub static ref PERSISTENT_STORAGE_READY: bool = false;
}

pub fn is_persistent_storage_ready() -> bool {
    *PERSISTENT_STORAGE_READY
}

pub fn persistent_storage_set_ready(value: bool) {
    *PERSISTENT_STORAGE_READY = value
}

pub fn persistent_storage_size_bytes() -> u64 {
    ic_cdk::api::stable::stable64_size() * PERSISTENT_STORAGE_PAGE_SIZE
}

pub fn persistent_storage_read64(offset: u64, buf: &mut [u8]) -> anyhow::Result<()> {
    info!(
        "Reading {} bytes from persistent storage @offset {}.",
        buf.len(),
        offset
    );
    Ok(ic_cdk::api::stable::stable64_read(offset, buf))
}

pub fn persistent_storage_write64(offset: u64, buf: &[u8]) {
    let stable_memory_size_bytes = persistent_storage_size_bytes();
    if stable_memory_size_bytes < offset + buf.len() as u64 {
        let stable_memory_bytes_new = offset + (buf.len() as u64).max(PERSISTENT_STORAGE_PAGE_SIZE);
        persistent_storage_grow64(
            (stable_memory_bytes_new - stable_memory_size_bytes) / PERSISTENT_STORAGE_PAGE_SIZE + 1,
        )
        .unwrap();
        info!(
            "Growing persistent storage to {} bytes.",
            stable_memory_bytes_new
        );
    }
    info!(
        "Writing {} bytes to persistent storage @offset {}.",
        buf.len(),
        offset
    );
    ic_cdk::api::stable::stable64_write(offset, buf)
}

pub fn persistent_storage_grow64(additional_pages: u64) -> Result<u64, String> {
    info!(
        "persistent_storage_grow64: {} additional_pages.",
        additional_pages
    );
    ic_cdk::api::stable::stable64_grow(additional_pages).map_err(|err| format!("{:?}", err))
}
