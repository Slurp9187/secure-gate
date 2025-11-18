// src/aliases.rs
//
// Define type aliases and From impls for secure wrappers

use crate::heap::HeapSecure;
use alloc::{
    string::{String, ToString},
    vec::Vec,
};

#[cfg(feature = "zeroize")]
use alloc::boxed::Box;

use core::{convert::Infallible, str::FromStr};

#[cfg(feature = "zeroize")]
use crate::{ExposeSecret, ExposeSecretMut};
#[cfg(feature = "zeroize")]
use secrecy::SecretBox;
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// Secure byte slice: `HeapSecure<[u8]>` (From<Vec<u8>>).
pub type SecureBytes = HeapSecure<[u8]>;

impl From<Vec<u8>> for SecureBytes {
    fn from(vec: Vec<u8>) -> Self {
        let boxed = vec.into_boxed_slice();
        HeapSecure::new_unsized(boxed)
    }
}

#[cfg(feature = "zeroize")]
impl Clone for SecureBytes {
    fn clone(&self) -> Self {
        // Fixed: use .expose() instead of .expose_secret()
        Self::from(self.expose().to_vec())
    }
}
#[cfg(not(feature = "zeroize"))]
impl Clone for SecureBytes {
    fn clone(&self) -> Self {
        Self::from(self.expose().to_vec())
    }
}

/// Secure string: `HeapSecure<str>` (From<String>, From<&str>, FromStr).
pub type SecureStr = HeapSecure<str>;

impl From<String> for SecureStr {
    fn from(s: String) -> Self {
        let boxed = s.into_boxed_str();
        HeapSecure::new_unsized(boxed)
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
        // Fixed: use .expose() instead of .expose_secret()
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
pub type SecurePassword = HeapSecure<SecretBox<str>>;

#[cfg(not(feature = "zeroize"))]
pub type SecurePassword = HeapSecure<String>;

#[cfg(feature = "zeroize")]
impl From<&str> for SecurePassword {
    fn from(s: &str) -> Self {
        HeapSecure::new(SecretBox::new(s.into()))
    }
}

#[cfg(feature = "zeroize")]
impl From<String> for SecurePassword {
    fn from(s: String) -> Self {
        HeapSecure::new(SecretBox::new(s.into_boxed_str()))
    }
}

#[cfg(not(feature = "zeroize"))]
impl From<&str> for SecurePassword {
    fn from(s: &str) -> Self {
        HeapSecure::new(s.to_string())
    }
}

#[cfg(not(feature = "zeroize"))]
impl From<String> for SecurePassword {
    fn from(s: String) -> Self {
        HeapSecure::new(s)
    }
}

/// Only when you need to build/append/pepper at runtime — preferred name
#[cfg(feature = "zeroize")]
pub type SecurePasswordBuilder = HeapSecure<SecretBox<String>>;

#[cfg(not(feature = "zeroize"))]
pub type SecurePasswordBuilder = HeapSecure<String>;

#[cfg(feature = "zeroize")]
impl From<&str> for SecurePasswordBuilder {
    fn from(s: &str) -> Self {
        HeapSecure::new(SecretBox::new(Box::new(s.to_string())))
    }
}

#[cfg(feature = "zeroize")]
impl From<String> for SecurePasswordBuilder {
    fn from(s: String) -> Self {
        HeapSecure::new(SecretBox::new(Box::new(s)))
    }
}

// SecurePasswordBuilder::into_password – fixed
#[cfg(feature = "zeroize")]
impl SecurePasswordBuilder {
    pub fn into_password(&mut self) -> SecurePassword {
        // Fixed: use the blanket impl from traits.rs
        let s: String = self.expose_secret().clone();
        // Optional: zeroize the builder (Drop will do it anyway)
        self.expose_secret_mut().zeroize();
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
pub type SecureKey32 = HeapSecure<[u8; 32]>;
#[cfg(not(feature = "stack"))]
pub type SecureKey64 = HeapSecure<[u8; 64]>;
#[cfg(not(feature = "stack"))]
pub type SecureIv = HeapSecure<[u8; 16]>;
#[cfg(not(feature = "stack"))]
pub type SecureSalt = HeapSecure<[u8; 16]>;
#[cfg(not(feature = "stack"))]
pub type SecureNonce12 = HeapSecure<[u8; 12]>;
#[cfg(not(feature = "stack"))]
pub type SecureNonce16 = HeapSecure<[u8; 16]>;
#[cfg(not(feature = "stack"))]
pub type SecureNonce24 = HeapSecure<[u8; 24]>;

// =====================================================================
// Fixed-size secret aliases — stack when feature = "stack"
// =====================================================================

#[cfg(feature = "stack")]
pub type SecureKey32 = crate::stack::Key32;
#[cfg(feature = "stack")]
pub type SecureKey64 = crate::stack::Key64;
#[cfg(feature = "stack")]
pub type SecureIv = crate::stack::Iv;
#[cfg(feature = "stack")]
pub type SecureSalt = crate::stack::Salt;
#[cfg(feature = "stack")]
pub type SecureNonce12 = crate::stack::Nonce12;
#[cfg(feature = "stack")]
pub type SecureNonce16 = crate::stack::Nonce16;
#[cfg(feature = "stack")]
pub type SecureNonce24 = crate::stack::Nonce24;
