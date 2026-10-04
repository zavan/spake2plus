//! Planted lint violations: bin/canaries expects clippy to report each one,
//! so a lint switched off in `Cargo.toml` turns the canaries red.

#[allow(dead_code)]
fn allowed_without_a_reason() {}

/// A stale expectation.
#[expect(dead_code, reason = "planted: the function is used")]
pub fn expected() {}

pub fn undocumented() {}

/// Unwraps.
pub fn unwraps(value: Option<u8>) -> u8 {
    value.unwrap()
}

/// Indexes.
#[must_use]
pub fn indexes(bytes: &[u8]) -> u8 {
    bytes[0]
}

/// Prints.
pub fn prints() {
    println!("planted");
}

/// Uses `unsafe`.
#[must_use]
pub fn unsafe_block() -> u8 {
    unsafe { core::ptr::read(&1) }
}
