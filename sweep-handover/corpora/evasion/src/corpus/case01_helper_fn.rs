//! Class 1 — growth behind a helper function.
//!
//! The closure handed to `with_secret_mut` contains one call and nothing else. No identifier in
//! this file appears on any growth list: `pad`, `pad_text` and `make_room` are the consumer's own
//! names, and their bodies are in `super::util_pad`, which has no `secure-gate` import and no
//! access-route call to anchor a window on.
//!
//! `absorb_quietly` is the same shape with the helper reached through `expose_secret_mut`, and
//! `reserve_for_later` is the case where no payload is appended at all — the capacity request alone
//! abandons the buffer.

use secure_gate::RevealSecretMut;

use super::roles::{Passphrase, SessionToken};
use super::util_pad;

/// Appends audit material to a live token.
pub fn extend_token(tok: &mut SessionToken, extra: &[u8]) {
    tok.with_secret_mut(|buf| util_pad::pad(buf, extra));
}

/// Appends a suffix to a live passphrase.
pub fn extend_passphrase(pw: &mut Passphrase, extra: &str) {
    pw.with_secret_mut(|text| util_pad::pad_text(text, extra));
}

/// The same thing through the long-lived `&mut` tier.
pub fn absorb_quietly(tok: &mut SessionToken, extra: &[u8]) {
    util_pad::pad(tok.expose_secret_mut(), extra);
}

/// Asks for headroom and writes nothing. Still abandons the old buffer.
pub fn reserve_for_later(tok: &mut SessionToken, headroom: usize) {
    tok.with_secret_mut(|buf| util_pad::make_room(buf, headroom));
}
