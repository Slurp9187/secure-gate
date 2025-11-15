// =================================================================================
// src/private.rs
// =================================================================================
#[cfg(feature = "zeroize")]
use super::*;
#[cfg(feature = "zeroize")]
use alloc::string::{String, ToString};
#[cfg(feature = "zeroize")]
use core::ops::{Deref, DerefMut};
#[cfg(feature = "zeroize")]
use secrecy::CloneableSecret;
#[cfg(feature = "serde")]
#[cfg(feature = "zeroize")]
use serde::{Deserialize, Serialize, Serializer};
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

#[cfg(feature = "zeroize")]
/// Newtype for String enabling safe cloning + zeroization.
/// Use via SecurePassword alias.
///
/// # Warning
/// Direct use of `SecretString` is not recommended outside of testing.
/// Always wrap in `Secure<SecretString>` for protection. `Debug` output is redacted.
#[derive(Clone, Default, Zeroize, PartialEq)]
pub struct SecretString(pub String);

#[cfg(feature = "zeroize")]
impl From<String> for SecretString {
    fn from(s: String) -> Self {
        Self(s)
    }
}

#[cfg(feature = "zeroize")]
impl From<&str> for SecretString {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

#[cfg(feature = "zeroize")]
impl core::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretString([REDACTED])")
    }
}

#[cfg(feature = "zeroize")]
impl Deref for SecretString {
    type Target = String;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(feature = "zeroize")]
impl DerefMut for SecretString {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(feature = "zeroize")]
impl CloneableSecret for SecretString {}

#[cfg(all(feature = "serde", feature = "zeroize"))]
impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::from)
    }
}

#[cfg(feature = "zeroize")]
#[cfg(feature = "serde")]
impl Serialize for SecretString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

#[cfg(all(feature = "serde", feature = "zeroize"))]
impl secrecy::SerializableSecret for SecretString {}
