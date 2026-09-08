//! URL-safe Base64 encoding trait.
//!
//! > **Import path:** `use secure_gate::ToBase64Url;`
//!
//! This trait provides secure, explicit encoding of byte data to URL-safe
//! base64 strings (no padding, RFC 4648). It is intended for intentional
//! export scenarios only (QR codes, API responses, audited logging).
//!
//! Requires the `encoding-base64` feature.
//!
//! # Security Notes
//!
//! - **Full secret exposure**: The resulting string contains the **entire** secret.
//!   Always treat output as sensitive; do not log or persist without protection.
//! - **Always wiped**: `to_base64url()` returns
//!   [`EncodedSecret`](crate::EncodedSecret), which wraps `Zeroizing<String>`, redacts
//!   its `Debug`, and wipes on drop.
//!   Public values come back in the same wrapper. `.into_inner()` is the named point where that
//!   protection ends.
//! - **Explicit exposure**: `to_base64url()` (and the other encoding methods) perform deliberate full-secret exposure —
//!   the same security contract as `with_secret` or `expose_secret`. Direct calls do not
//!   appear in `grep expose_secret` / `grep with_secret` audit sweeps. For audit-first teams
//!   or multi-step operations, prefer `with_secret(|b| b.to_base64url())` — the borrow
//!   checker enforces the reference cannot escape the closure.
//! - **URL-safe**: No padding (`=`), safe for URLs/JSON/filenames.
//!
//! # Example
//!
//! ```rust
//! # #[cfg(feature = "encoding-base64")]
//! use secure_gate::{Fixed, ToBase64Url, RevealSecret};
//! # #[cfg(feature = "encoding-base64")]
//! {
//! let secret = Fixed::new([0x42u8; 4]);
//!
//! // Blanket impl on the inner byte array (via with_secret):
//! let b64 = secret.with_secret(|s| s.to_base64url());
//! assert_eq!(&*b64, "QkJCQg");
//!
//! // Wrapper method (Direct Fixed<[u8; N]> API — same result):
//! assert_eq!(&*secret.to_base64url(), "QkJCQg");
//! // Returns an `EncodedSecret`: wiped on drop, `Debug` redacted.
//! }
//! ```
#[cfg(all(feature = "encoding-base64", feature = "alloc"))]
use base64ct::{Base64UrlUnpadded, Encoding};

/// Extension trait for encoding byte data as URL-safe base64 strings (no padding).
///
/// *Requires feature `encoding-base64`.*
///
/// Blanket-implemented for `AsRef<[u8]>` + [`EncodableBytes`](super::EncodableBytes), and implemented directly on the
/// byte-shaped wrappers (`Fixed<[u8; N]>`, `Dynamic<Vec<u8>>`). Uses the RFC 4648
/// URL-safe alphabet without `=` padding. To encode a secret wrapper, call
/// `key.to_base64url()` with this trait in scope (ergonomically safest for single
/// operations), or use `with_secret(|b| b.to_base64url())` for multi-step operations
/// or when audit-greppability matters.
#[cfg(all(feature = "encoding-base64", feature = "alloc"))]
pub trait ToBase64Url {
    /// Encode bytes as URL-safe base64 (no padding).
    fn to_base64url(&self) -> crate::EncodedSecret;
}

// Blanket impl over AsRef<[u8]> + EncodableBytes (e.g. &[u8], Vec<u8>, [u8; N]).
#[cfg(all(feature = "encoding-base64", feature = "alloc"))]
impl<T: AsRef<[u8]> + super::EncodableBytes + ?Sized> ToBase64Url for T {
    #[inline(always)]
    fn to_base64url(&self) -> crate::EncodedSecret {
        crate::EncodedSecret::new(Base64UrlUnpadded::encode_string(self.as_ref()))
    }
}
