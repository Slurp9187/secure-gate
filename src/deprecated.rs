// src/deprecated.rs
#![allow(deprecated)]

pub use crate::aliases::SecurePasswordBuilder;

/// Legacy alias — will be removed in 1.0.0
#[deprecated(
    since = "0.3.1",
    note = "use SecurePasswordBuilder instead — clearer intent and matches the builder pattern"
)]
pub type SecurePasswordMut = SecurePasswordBuilder;
