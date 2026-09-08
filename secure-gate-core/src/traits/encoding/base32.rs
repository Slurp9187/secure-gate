//! Base32 encoding trait (RFC 4648 §6, uppercase, unpadded).
//!
//! > **Import path:** `use secure_gate::ToBase32;`
//!
//! This trait provides secure, explicit encoding of byte data to Base32 strings
//! using the RFC 4648 §6 alphabet (`A`–`Z`, `2`–`7`), uppercase, without `=`
//! padding — the form used for TOTP/HOTP shared secrets in `otpauth://` key URIs
//! (RFC 6238 / RFC 4226) and the densest form that fits QR alphanumeric mode. It
//! is intended for intentional export scenarios only (QR codes, API responses,
//! audited logging).
//!
//! Requires the `encoding-base32` feature.
//!
//! # Security Notes
//!
//! - **Full secret exposure**: The resulting string contains the **entire** secret.
//!   Always treat output as sensitive; do not log or persist without protection.
//! - **Always wiped**: `to_base32()` returns
//!   [`EncodedSecret`](crate::EncodedSecret)
//!   (wrapping `Zeroizing<String>` with redacted `Debug`). Use plain `to_base32()`
//!   only for public values.
//! - **Explicit exposure**: `to_base32()` (and the other encoding methods) perform deliberate full-secret exposure —
//!   the same security contract as `with_secret` or `expose_secret`. Direct calls do not
//!   appear in `grep expose_secret` / `grep with_secret` audit sweeps. For audit-first teams
//!   or multi-step operations, prefer `with_secret(|b| b.to_base32())` — the borrow
//!   checker enforces the reference cannot escape the closure.
//! - **Canonical form only**: uppercase, unpadded. See
//!   [`FromBase32Str`](crate::FromBase32Str) for what the decoder accepts.
//!
//! # Example
//!
//! ```rust
//! # #[cfg(feature = "encoding-base32")]
//! use secure_gate::{Fixed, ToBase32, RevealSecret};
//! # #[cfg(feature = "encoding-base32")]
//! {
//! let secret = Fixed::new([0x42u8; 4]);
//!
//! // Blanket impl on the inner byte array (via with_secret):
//! let b32 = secret.with_secret(|s| s.to_base32());
//! assert_eq!(&*b32, "IJBEEQQ");
//!
//! // Wrapper method (Direct Fixed<[u8; N]> API — same result):
//! assert_eq!(&*secret.to_base32(), "IJBEEQQ");
//! // Both return an `EncodedSecret`: wiped on drop, `Debug` redacted.
//! }
//! ```
#[cfg(all(feature = "encoding-base32", feature = "alloc"))]
use base32ct::{Base32UpperUnpadded, Encoding};

/// Extension trait for encoding byte data as Base32 strings (RFC 4648 §6, uppercase, unpadded).
///
/// *Requires feature `encoding-base32`.*
///
/// Blanket-implemented for all `AsRef<[u8]>` types, and implemented directly on the
/// byte-shaped wrappers (`Fixed<[u8; N]>`, `Dynamic<Vec<u8>>`). Uses the RFC 4648 §6
/// alphabet (`A`–`Z`, `2`–`7`) without `=` padding. To encode a secret wrapper, call
/// `key.to_base32()` with this trait in scope (ergonomically safest for single
/// operations), or use `with_secret(|b| b.to_base32())` for multi-step operations
/// or when audit-greppability matters.
#[cfg(all(feature = "encoding-base32", feature = "alloc"))]
pub trait ToBase32 {
    /// Encode bytes as Base32 (RFC 4648 §6 alphabet, uppercase, no padding).
    fn to_base32(&self) -> crate::EncodedSecret;
}

// Blanket impl to cover any AsRef<[u8]> (e.g., &[u8], Vec<u8>, [u8; N], etc.)
#[cfg(all(feature = "encoding-base32", feature = "alloc"))]
impl<T: AsRef<[u8]> + super::EncodableBytes + ?Sized> ToBase32 for T {
    #[inline(always)]
    fn to_base32(&self) -> crate::EncodedSecret {
        crate::EncodedSecret::new(Base32UpperUnpadded::encode_string(self.as_ref()))
    }
}
