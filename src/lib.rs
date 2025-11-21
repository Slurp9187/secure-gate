// src/lib.rs
//
// Core secure wrapper types and traits

#![no_std]
#![cfg_attr(not(feature = "unsafe-wipe"), forbid(unsafe_code))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![allow(deprecated)]
#![allow(type_alias_bounds)]

extern crate alloc;

#[cfg(feature = "zeroize")]
use alloc::string::String;

// Public modules
pub mod aliases;
pub mod deprecated;
pub mod macros;
mod password;
pub mod secure_gate;

// The One True Type
pub use secure_gate::SecureGate;

/// Short prefix
pub type SG<T> = SecureGate<T>;

// Public re-exports
pub use aliases::*;

// Legacy bridge
#[cfg(feature = "zeroize")]
pub use deprecated::*;

// Re-export secrecy primitives when zeroize is enabled
#[cfg(feature = "zeroize")]
pub use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};

/// Fixed-size truly stack-allocated password (max 127 bytes + zero padding)
/// Uses zeroize::Zeroizing<[u8; 128]> under the hood – zero heap allocation
#[cfg(feature = "stack")]
pub type SecureStackPassword = SecureGate<zeroize::Zeroizing<[u8; 128]>>;

#[cfg(feature = "stack")]
impl TryFrom<&str> for SecureStackPassword {
    type Error = &'static str;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let bytes = s.as_bytes();
        if bytes.len() >= 128 {
            return Err("password too long for SecureStackPassword (max 127 bytes)");
        }

        let mut buf = [0u8; 128];
        buf[..bytes.len()].copy_from_slice(bytes);

        Ok(Self::new(zeroize::Zeroizing::new(buf)))
    }
}

#[cfg(feature = "stack")]
impl TryFrom<String> for SecureStackPassword {
    type Error = &'static str;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.as_str().try_into()
    }
}
