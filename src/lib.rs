// =================================================================================
// src/lib.rs
// =================================================================================
#![no_std]
#![forbid(unsafe_code)]
// #![warn(missing_docs, rust_2018_idioms)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
extern crate alloc;
pub mod macros;
mod private;
pub mod secure_types;
pub use secure_types::*;

// FIXED: Imports for fallback (String and ToString) - unconditional for no_std
use alloc::string::String;

#[cfg(not(feature = "zeroize"))]
use alloc::string::ToString;

#[cfg(feature = "zeroize")]
pub use secrecy::{ExposeSecret, ExposeSecretMut};
/// Convenience: Secure password alias.
#[cfg(feature = "zeroize")]
pub type SecurePassword = Secure<crate::private::SecretString>;
#[cfg(not(feature = "zeroize"))]
pub type SecurePassword = Secure<String>;

// Gated From impls (only for fallback mode; SecretString has its own)
#[cfg(not(feature = "zeroize"))]
impl From<&str> for SecurePassword {
    fn from(s: &str) -> Self {
        Self::new(s.to_string())
    }
}
#[cfg(not(feature = "zeroize"))]
impl From<String> for SecurePassword {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

// From impls for zeroize mode (using SecretString::from)
#[cfg(feature = "zeroize")]
impl From<&str> for SecurePassword {
    fn from(s: &str) -> Self {
        Self::new(crate::private::SecretString::from(s))
    }
}
#[cfg(feature = "zeroize")]
impl From<String> for SecurePassword {
    fn from(s: String) -> Self {
        Self::new(crate::private::SecretString::from(s))
    }
}

// Re-export SecretString for use in tests (avoids private module access)
#[cfg(feature = "zeroize")]
pub use private::SecretString;
