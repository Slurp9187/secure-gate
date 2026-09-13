//! A correct consumer, for measuring what a sweep costs when nothing is wrong.
//!
//! Every `secure-gate` use here follows the documented mitigation: the buffer is sized to its final
//! length before it is wrapped, and every mutation afterwards is capacity-stable. Everything else in
//! the file is ordinary byte wrangling on material that is not secret — request lines, header maps,
//! a hex table, an error report. That mixture is what a real consumer file looks like, and it is
//! where a sweep's findings have to be paid for by someone reading them.
//!
//! Nothing in this file leaks. `tests/measure.rs` asserts that for the secret-handling parts.

use std::fmt::Write as _;

use secure_gate::{RevealSecret, RevealSecretMut};

use crate::corpus::roles::{Passphrase, SessionToken};

/// Wraps a token that is already at its final size. Capacity never changes again.
pub fn seal(material: &[u8]) -> SessionToken {
    SessionToken::new_with(|v| {
        v.reserve_exact(material.len());
        v.extend_from_slice(material);
    })
}

/// A capacity-stable transform: same buffer, same capacity, no reallocation.
pub fn mask(tok: &mut SessionToken, key: u8) {
    tok.with_secret_mut(|v| {
        for b in v.iter_mut() {
            *b ^= key;
        }
    });
}

/// A capacity-stable truncation. `truncate` never reallocates and never shrinks capacity.
pub fn clip(tok: &mut SessionToken, len: usize) {
    tok.with_secret_mut(|v| v.truncate(len));
}

/// Reads the length without revealing anything.
pub fn size(tok: &SessionToken) -> usize {
    tok.with_secret(Vec::len)
}

/// Capacity-stable in-place case fold on a passphrase.
pub fn upcase(pw: &mut Passphrase) {
    pw.with_secret_mut(|s| s.make_ascii_uppercase());
}

// --------------------------------------------------------------------------- not secret

/// Builds a request line. Ordinary string growth on public data.
pub fn request_line(method: &str, path: &str, query: &[(&str, &str)]) -> String {
    let mut out = String::new();
    out.push_str(method);
    out.push(' ');
    out.push_str(path);
    for (i, (k, v)) in query.iter().enumerate() {
        out.push(if i == 0 { '?' } else { '&' });
        out.push_str(k);
        out.push('=');
        out.push_str(v);
    }
    out.push_str(" HTTP/1.1\r\n");
    out
}

/// Collects headers into a flat buffer. Ordinary `Vec` growth on public data.
pub fn render_headers(headers: &[(&str, &str)]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.reserve(headers.len() * 32);
    for (name, value) in headers {
        buf.extend_from_slice(name.as_bytes());
        buf.extend_from_slice(b": ");
        buf.extend_from_slice(value.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }
    buf.extend_from_slice(b"\r\n");
    buf
}

/// A lowercase hex table. Ordinary growth.
pub fn hex_table() -> Vec<String> {
    let mut table = Vec::with_capacity(256);
    for b in 0u16..256 {
        let mut s = String::new();
        let _ = write!(s, "{b:02x}");
        table.push(s);
    }
    table
}

/// Splits a buffer at a delimiter. Uses `split_off` on public data.
pub fn split_at_colon(line: &mut Vec<u8>) -> Option<Vec<u8>> {
    let i = line.iter().position(|&b| b == b':')?;
    let tail = line.split_off(i + 1);
    line.truncate(i);
    Some(tail)
}

/// Merges two public buffers.
pub fn merge(into: &mut Vec<u8>, from: &mut Vec<u8>) {
    into.append(from);
}

/// Normalises a public path, replacing the buffer.
pub fn normalize_path(p: &mut String) {
    *p = p.replace("//", "/");
}

/// Builds an error report. More ordinary growth.
pub fn report(errors: &[String]) -> String {
    let mut out = String::from("errors:\n");
    for (i, e) in errors.iter().enumerate() {
        let _ = writeln!(out, "  {i}: {e}");
    }
    out.shrink_to_fit();
    out
}

/// Collects the lengths of a slice of buffers.
pub fn lengths(bufs: &[Vec<u8>]) -> Vec<usize> {
    bufs.iter().map(Vec::len).collect()
}
