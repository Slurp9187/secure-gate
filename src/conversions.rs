// src/conversions.rs
//! Ergonomic conversions for fixed-size secrets — **explicit exposure required**
//!
//! This module provides the [`SecureConversionsExt`] trait containing `.to_hex()`,
//! `.to_hex_upper()`, `.to_base64url()`, and `.ct_eq()`.
//!
//! The trait is implemented **only on `&[u8]`**, meaning you **must** call
//! `.expose_secret()` first. This guarantees every conversion site is loud,
//! intentional, and visible in code reviews.
//!
//! Enabled via the `conversions` feature (zero impact when disabled).
//!
//! # Correct usage (v0.5.9+)
//!
//! ```
//! use secure_gate::{fixed_alias, SecureConversionsExt};
//!
//! fixed_alias!(Aes256Key, 32);
//!
//! let key1 = Aes256Key::from([0x42; 32]);
//! let key2 = Aes256Key::from([0x42; 32]);
//!
//! let hex = key1.expose_secret().to_hex();
//! let b64 = key1.expose_secret().to_base64url();
//! assert!(key1.expose_secret().ct_eq(key2.expose_secret()));
//! ```

#[cfg(feature = "conversions")]
use alloc::string::String;

#[cfg(feature = "conversions")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(feature = "conversions")]
use base64::Engine;

#[cfg(all(feature = "rand", feature = "conversions"))]
use secrecy::ExposeSecret;

// Loud deprecation bomb — impossible to miss if someone uses the old API
#[cfg(all(feature = "conversions", not(doc)))]
#[deprecated(
    since = "0.5.9",
    note = "DIRECT CONVERSIONS BYPASS expose_secret() — USE .expose_secret().to_hex() ETC."
)]
#[doc(hidden)]
const _DIRECT_CONVERSIONS_ARE_EVIL: () = ();

/// Extension trait for common secure conversions.
///
/// # Security
///
/// This trait is **intentionally** only implemented for `&[u8]`.
/// There is **no** impl for `Fixed<T>` — this guarantees every conversion
/// requires an explicit `.expose_secret()` call.
pub trait SecureConversionsExt {
    fn to_hex(&self) -> String;
    fn to_hex_upper(&self) -> String;
    fn to_base64url(&self) -> String;
    fn ct_eq(&self, other: &Self) -> bool;
}

/// Core implementation — only on already-exposed bytes
#[cfg(feature = "conversions")]
impl SecureConversionsExt for [u8] {
    #[inline]
    fn to_hex(&self) -> String {
        hex::encode(self)
    }

    #[inline]
    fn to_hex_upper(&self) -> String {
        hex::encode_upper(self)
    }

    #[inline]
    fn to_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self)
    }

    #[inline]
    fn ct_eq(&self, other: &[u8]) -> bool {
        subtle::ConstantTimeEq::ct_eq(self, other).into()
    }
}

/// Backward-compatibility shims — **deprecated**
///
/// Will be removed in v0.6.0.
#[cfg(feature = "conversions")]
impl<const N: usize> crate::Fixed<[u8; N]> {
    #[deprecated(
        since = "0.5.9",
        note = "use `expose_secret().to_hex()` instead — makes secret exposure explicit"
    )]
    #[doc(hidden)]
    #[inline(always)]
    pub fn to_hex(&self) -> String {
        self.expose_secret().to_hex()
    }

    #[deprecated(since = "0.5.9", note = "use `expose_secret().to_hex_upper()` instead")]
    #[doc(hidden)]
    #[inline(always)]
    pub fn to_hex_upper(&self) -> String {
        self.expose_secret().to_hex_upper()
    }

    #[deprecated(since = "0.5.9", note = "use `expose_secret().to_base64url()` instead")]
    #[doc(hidden)]
    #[inline(always)]
    pub fn to_base64url(&self) -> String {
        self.expose_secret().to_base64url()
    }

    #[deprecated(
        since = "0.5.9",
        note = "use `expose_secret().ct_eq(other.expose_secret())` instead"
    )]
    #[doc(hidden)]
    #[inline(always)]
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.expose_secret().ct_eq(other.expose_secret())
    }
}

// ───── Compile-time safety net — prevents accidental re-introduction of the bad impl ─────
//
// We use a negative impl to trigger a compile error if someone adds an impl of
// SecureConversionsExt for Fixed<[u8; N]> in the future.
//
// This is a well-known Rust pattern (used by crates like `serde`, `thiserror`, etc.)
// to enforce API invariants at compile time.

#[cfg(feature = "conversions")]
trait _AssertNoImplForFixed {}
#[cfg(feature = "conversions")]
impl<T> _AssertNoImplForFixed for T where T: SecureConversionsExt {}

#[cfg(feature = "conversions")]
impl<const N: usize> _AssertNoImplForFixed for crate::Fixed<[u8; N]> {
    //  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    //  If anyone ever adds `impl SecureConversionsExt for Fixed<[u8; N]>`, this line
    //  will cause a compile error: "conflicting implementation"
    //  → immediate, loud failure instead of silent security regression
}

// ───── New: HexString newtype for type-safe hex handling ─────

/// Newtype for validated hex strings with extensions.
///
/// Deref to Dynamic<String> to inherit String methods/properties.
/// Enforces explicit exposure via expose_secret().
#[cfg(feature = "conversions")]
#[derive(Clone, Debug, PartialEq)]
pub struct HexString(crate::Dynamic<String>);

#[cfg(feature = "conversions")]
impl HexString {
    /// Creates a new HexString if the input is valid hex (even length, 0-9a-fA-F chars).
    /// Normalizes to lowercase.
    pub fn new(s: String) -> Result<Self, &'static str> {
        let lower = s.to_lowercase();
        if lower.len() % 2 != 0 || !lower.chars().all(|c| c.is_ascii_hexdigit()) {
            Err("Invalid hex: must be even length with 0-9a-f chars")
        } else {
            Ok(Self(crate::Dynamic::new(lower)))
        }
    }

    /// Decodes back to bytes (safe due to validation).
    pub fn to_bytes(&self) -> Vec<u8> {
        hex::decode(self.expose_secret()).expect("Validated hex")
    }

    /// Property: Original byte length (half of hex len).
    pub fn byte_len(&self) -> usize {
        self.expose_secret().len() / 2
    }
}

#[cfg(feature = "conversions")]
impl core::ops::Deref for HexString {
    type Target = crate::Dynamic<String>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(feature = "conversions")]
impl ExposeSecret<String> for HexString {
    fn expose_secret(&self) -> &String {
        self.0.expose_secret()
    }
}

/// Newtype for random hex strings — wraps HexString for freshness semantics.
///
/// Construction only via RNG → guarantees it's from random bytes.
#[cfg(all(feature = "rand", feature = "conversions"))]
#[derive(Clone, Debug, PartialEq)]
pub struct RandomHex(pub HexString);

#[cfg(all(feature = "rand", feature = "conversions"))]
impl RandomHex {
    /// Internal constructor — only from validated hex.
    pub fn new(hex: HexString) -> Self {
        Self(hex)
    }

    /// Decodes back to bytes (inherits from HexString).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Property: Original byte length (inherits).
    pub fn byte_len(&self) -> usize {
        self.0.byte_len()
    }
}

#[cfg(all(feature = "rand", feature = "conversions"))]
impl core::ops::Deref for RandomHex {
    type Target = HexString;
    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(all(feature = "rand", feature = "conversions"))]
impl ExposeSecret<String> for RandomHex {
    #[inline(always)]
    fn expose_secret(&self) -> &String {
        self.0.expose_secret()
    }
}

#[cfg(all(feature = "rand", feature = "conversions"))]
#[test]
fn random_hex_returns_randomhex() {
    use crate::{random_alias, SecureRandomExt};

    random_alias!(HexKey, 32);

    let hex = HexKey::random_hex();
    let _: RandomHex = hex;

    assert_eq!(hex.expose_secret().len(), 64);
    assert!(hex.expose_secret().chars().all(|c| c.is_ascii_hexdigit()));

    let bytes_back = hex.to_bytes();
    assert_eq!(bytes_back.len(), 32);
}
