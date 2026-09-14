//! Class 9 — real, compiled, executed code that lives where a text sweep must not look.
//!
//! Any sweep that does not strip comments scores on prose: the words `extend_from_slice` and
//! `push_str` appear throughout this corpus's own documentation. Stripping comments is therefore
//! mandatory — and it blinds the sweep to doctests, which `rustc` does compile and run.
//!
//! The leak below is byte-for-byte the one measured as `case01 with_secret_mut + helper fn (Vec)`:
//! 1008 of 1008 bytes abandoned non-zero. What is new is its location.
//!
//! ```rust
//! use evasion_corpus::corpus::roles::SessionToken;
//! use secure_gate::{RevealSecret, RevealSecretMut};
//!
//! let mut tok = SessionToken::new_with(|v| {
//!     v.reserve_exact(1008);
//!     v.extend(std::iter::repeat(0xD7u8).take(1008));
//! });
//! assert_eq!(tok.expose_secret().capacity(), 1008);
//! tok.with_secret_mut(|v| v.extend_from_slice(&[0xE3u8; 96]));
//! assert_eq!(tok.expose_secret().len(), 1104);
//! ```
//!
//! `#[cfg(doctest)]` and `include_str!`-ed markdown are the same hole: the compiler reads them and a
//! comment-stripping sweep cannot.

/// Nothing runs here. The executable code in this module is in the module doc above.
pub const WHERE_THE_CODE_IS: &str = "the module doc comment";
