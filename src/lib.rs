// =================================================================================
// src/lib.rs
// =================================================================================
#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;

pub mod macros;
pub mod secure_types;
pub use secure_types::*;

// Re-export secrecy traits when zeroize is enabled
#[cfg(feature = "zeroize")]
pub use secrecy::{ExposeSecret, ExposeSecretMut};
