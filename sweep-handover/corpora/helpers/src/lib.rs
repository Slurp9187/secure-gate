//! Stands in for a third-party utility crate.
//!
//! A consumer's CI sweep scans the consumer's own repository. It does not scan
//! `~/.cargo/registry`, and it has no way to know that one of the 400 crates in the lock file
//! exposes a safe-looking function whose body is `unsafe { s.as_mut_vec() }`. This crate is here to
//! make that concrete rather than asserted: `consumer/src` is the only thing the sweep is pointed
//! at, and the token `as_mut_vec` does not occur in it.

/// Re-borrows a `String`'s bytes. Nothing here is unsound: the caller's safety obligation is
/// documented, and the corpus honours it by appending ASCII only.
///
/// # Safety
///
/// The caller must leave the buffer valid UTF-8 before the borrow ends.
pub unsafe fn bytes_mut(text: &mut String) -> &mut Vec<u8> {
    text.as_mut_vec()
}

/// Appends bytes to a buffer.
pub fn concat(buf: &mut Vec<u8>, extra: &[u8]) {
    buf.extend_from_slice(extra);
}
