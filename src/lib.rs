// =================================================================================
// src/lib.rs
// =================================================================================

#![no_std]
#![forbid(unsafe_code)]
// #![warn(missing_docs, rust_2018_idioms)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;

pub mod macros;
pub mod secure_types;

pub use secure_types::*;

#[cfg(feature = "zeroize")]
pub use secrecy::{ExposeSecret, ExposeSecretMut};
