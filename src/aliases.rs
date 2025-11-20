// src/aliases.rs
//
// Define type aliases and From impls for secure wrappers

use crate::secure_gate::SecureGate;
use alloc::{
    string::{String, ToString},
    vec::Vec,
};

#[cfg(feature = "zeroize")]
use alloc::boxed::Box;

use core::{convert::Infallible, str::FromStr};

#[cfg(feature = "zeroize")]
use secrecy::ExposeSecret;
#[cfg(feature = "zeroize")]
use secrecy::SecretBox;
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, Zeroizing};

/// Secure byte slice: SecureGate<[u8]>
pub type SecureBytes = SecureGate<[u8]>;

impl From<Vec<u8>> for SecureBytes {
    fn from(vec: Vec<u8>) -> Self {
        let boxed = vec.into_boxed_slice();
        SecureGate::new_unsized(boxed)
    }
}

#[cfg(feature = "zeroize")]
impl Clone for SecureBytes {
    fn clone(&self) -> Self {
        Self::from(self.expose().to_vec())
    }
}
#[cfg(not(feature = "zeroize"))]
impl Clone for SecureBytes {
    fn clone(&self) -> Self {
        Self::from(self.expose().to_vec())
    }
}

/// Secure string: SecureGate<str>
pub type SecureStr = SecureGate<str>;

impl From<String> for SecureStr {
    fn from(s: String) -> Self {
        let boxed = s.into_boxed_str();
        SecureGate::new_unsized(boxed)
    }
}

impl From<&str> for SecureStr {
    fn from(s: &str) -> Self {
        Self::from(String::from(s))
    }
}

impl FromStr for SecureStr {
    type Err = Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from(s))
    }
}

#[cfg(feature = "zeroize")]
impl Clone for SecureStr {
    fn clone(&self) -> Self {
        Self::from(self.expose().to_string())
    }
}
#[cfg(not(feature = "zeroize"))]
impl Clone for SecureStr {
    fn clone(&self) -> Self {
        Self::from(self.expose().to_string())
    }
}

/// Recommended for nearly all password use — immutable, zero-realloc, safest
#[cfg(feature = "zeroize")]
pub type SecurePassword = SecureGate<SecretBox<str>>;

#[cfg(not(feature = "zeroize"))]
pub type SecurePassword = SecureGate<String>;

#[cfg(feature = "zeroize")]
impl From<&str> for SecurePassword {
    fn from(s: &str) -> Self {
        SecureGate::new(SecretBox::new(s.into()))
    }
}

#[cfg(feature = "zeroize")]
impl From<String> for SecurePassword {
    fn from(s: String) -> Self {
        SecureGate::new(SecretBox::new(s.into_boxed_str()))
    }
}

#[cfg(not(feature = "zeroize"))]
impl From<&str> for SecurePassword {
    fn from(s: &str) -> Self {
        SecureGate::new(s.to_string())
    }
}

#[cfg(not(feature = "zeroize"))]
impl From<String> for SecurePassword {
    fn from(s: String) -> Self {
        SecureGate::new(s)
    }
}

/// Only when you need to build/append/pepper at runtime
#[cfg(feature = "zeroize")]
pub type SecurePasswordBuilder = SecureGate<SecretBox<String>>;

#[cfg(not(feature = "zeroize"))]
pub type SecurePasswordBuilder = SecureGate<String>;

#[cfg(feature = "zeroize")]
impl From<&str> for SecurePasswordBuilder {
    fn from(s: &str) -> Self {
        SecureGate::new(SecretBox::new(Box::new(s.to_string())))
    }
}

#[cfg(feature = "zeroize")]
impl From<String> for SecurePasswordBuilder {
    fn from(s: String) -> Self {
        SecureGate::new(SecretBox::new(Box::new(s)))
    }
}

/// Critical fix: use expose() + expose_mut() on the SecretBox directly
#[cfg(feature = "zeroize")]
impl SecurePasswordBuilder {
    pub fn into_password(&mut self) -> SecurePassword {
        let inner = self.expose_mut();
        let s = inner.expose_secret().clone();
        inner.zeroize();
        SecurePassword::from(s)
    }

    pub fn build(&mut self) -> SecurePassword {
        self.into_password()
    }
}

// =====================================================================
// Fixed-size secret aliases — heap fallback when !stack
// =====================================================================

#[cfg(not(feature = "stack"))]
pub type SecureKey32 = SecureGate<[u8; 32]>;
#[cfg(not(feature = "stack"))]
pub type SecureKey64 = SecureGate<[u8; 64]>;

#[cfg(not(feature = "stack"))]
pub type SecureIv16 = SecureGate<[u8; 16]>;
#[cfg(not(feature = "stack"))]
pub type SecureSalt16 = SecureGate<[u8; 16]>;
#[cfg(not(feature = "stack"))]
pub type SecureNonce12 = SecureGate<[u8; 12]>;
#[cfg(not(feature = "stack"))]
pub type SecureNonce16 = SecureGate<[u8; 16]>;
#[cfg(not(feature = "stack"))]
pub type SecureNonce24 = SecureGate<[u8; 24]>;
#[cfg(not(feature = "stack"))]
pub type SecureNonce96 = SecureGate<[u8; 12]>;
#[cfg(not(feature = "stack"))]
pub type SecureNonce128 = SecureGate<[u8; 16]>;

// =====================================================================
// Fixed-size secret aliases — stack when feature = "stack"
// =====================================================================

#[cfg(feature = "stack")]
pub type SecureKey32 = Zeroizing<[u8; 32]>;
#[cfg(feature = "stack")]
pub type SecureKey64 = Zeroizing<[u8; 64]>;
#[cfg(feature = "stack")]
pub type SecureIv16 = Zeroizing<[u8; 16]>;
#[cfg(feature = "stack")]
pub type SecureSalt16 = Zeroizing<[u8; 16]>;
#[cfg(feature = "stack")]
pub type SecureNonce12 = Zeroizing<[u8; 12]>;
#[cfg(feature = "stack")]
pub type SecureNonce16 = Zeroizing<[u8; 16]>;
#[cfg(feature = "stack")]
pub type SecureNonce24 = Zeroizing<[u8; 24]>;
#[cfg(feature = "stack")]
pub type SecureNonce96 = Zeroizing<[u8; 12]>;
#[cfg(feature = "stack")]
pub type SecureNonce128 = Zeroizing<[u8; 16]>;

// =====================================================================
// Deprecated aliases for backward compatibility (zeroize only)
// =====================================================================

#[cfg(feature = "zeroize")]
#[deprecated(since = "0.4.1", note = "use SecureIv16 instead")]
pub type SecureIv = SecureIv16;

#[cfg(feature = "zeroize")]
#[deprecated(since = "0.4.1", note = "use SecureSalt16 instead")]
pub type SecureSalt = SecureSalt16;

// Constructors for stack types
#[cfg(feature = "stack")]
pub fn key32(bytes: [u8; 32]) -> SecureKey32 {
    Zeroizing::new(bytes)
}
#[cfg(feature = "stack")]
pub fn key64(bytes: [u8; 64]) -> SecureKey64 {
    Zeroizing::new(bytes)
}
#[cfg(feature = "stack")]
pub fn iv16(bytes: [u8; 16]) -> SecureIv16 {
    Zeroizing::new(bytes)
}
#[cfg(feature = "stack")]
pub fn salt16(bytes: [u8; 16]) -> SecureSalt16 {
    Zeroizing::new(bytes)
}
#[cfg(feature = "stack")]
pub fn nonce12(bytes: [u8; 12]) -> SecureNonce12 {
    Zeroizing::new(bytes)
}
#[cfg(feature = "stack")]
pub fn nonce16(bytes: [u8; 16]) -> SecureNonce16 {
    Zeroizing::new(bytes)
}
#[cfg(feature = "stack")]
pub fn nonce24(bytes: [u8; 24]) -> SecureNonce24 {
    Zeroizing::new(bytes)
}
#[cfg(feature = "stack")]
pub fn nonce96(bytes: [u8; 12]) -> SecureNonce96 {
    Zeroizing::new(bytes)
}
#[cfg(feature = "stack")]
pub fn nonce128(bytes: [u8; 16]) -> SecureNonce128 {
    Zeroizing::new(bytes)
}
