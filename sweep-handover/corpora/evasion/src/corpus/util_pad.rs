//! Generic buffer utilities. Knows nothing about secrets, imports nothing from `secure-gate`.
//!
//! This is the file a windowed sweep cannot reach: the growth-capable calls live here, and the
//! `with_secret_mut` / `expose_secret_mut` call sites that make them dangerous live in other files.
//! A whole-file grep for growth identifiers would flag this module — and every other buffer utility
//! in every consumer crate with it.

/// Appends `extra` to `buf`.
pub fn pad(buf: &mut Vec<u8>, extra: &[u8]) {
    buf.extend_from_slice(extra);
}

/// Appends `extra` to `text`.
pub fn pad_text(text: &mut String, extra: &str) {
    text.push_str(extra);
}

/// Makes room for `n` more bytes without writing any.
pub fn make_room(buf: &mut Vec<u8>, n: usize) {
    buf.reserve(n);
}
