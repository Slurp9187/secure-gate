//! Encoding traits for explicit secret-to-string conversion.
//!
//! > **Import paths:** `use secure_gate::ToHex;` etc. (not `secure_gate::traits::encoding::hex::ToHex`)
//!
//! All encoding traits require `alloc`. Every encoder returns
//! [`EncodedSecret`](crate::EncodedSecret): the encoded form is a second full copy of
//! the secret, and it stays wiped until it drops.
//! See the [`decoding`](super::decoding) module for the reverse direction.
//!
//! Each encoding trait has its own feature gate:
//!
//! | Trait            | Feature             |
//! |------------------|---------------------|
//! | [`ToHex`]        | `encoding-hex`      |
//! | [`ToBase32`]     | `encoding-base32`   |
//! | [`ToBase64Url`]  | `encoding-base64`   |
//! | [`ToBech32`]     | `encoding-bech32`   |
//! | [`ToBech32m`]    | `encoding-bech32`   |
pub mod base32;
pub mod base64_url;
pub mod bech32;
#[cfg(feature = "encoding-bech32")]
pub mod bech32m;
pub mod hex;

/// Marker for types that may be **encoded**: byte-shaped sources.
///
/// Every encoding trait in this module is blanket-implemented for
/// `T: AsRef<[u8]> + EncodableBytes`. The second bound is what keeps string-shaped
/// types out, and it is load-bearing rather than decorative — removing it changes
/// which calls compile.
///
/// # Why the extra bound exists
///
/// `str` and `String` implement `AsRef<[u8]>`, so an `AsRef<[u8]>`-only blanket made
/// every string an encoding *input* — even though strings are this crate's decoding
/// input. Two silent wrong answers followed from that:
///
/// - `encoded.to_hex()` compiled for an [`EncodedSecret`](crate::EncodedSecret), which
///   derefs to `str`. It hex-encoded the *encoded text*: a 32-byte key came back as 124
///   hex characters, with no signature or name to suggest anything was wrong.
/// - `"text".to_hex()` encoded a string's UTF-8 bytes, which is occasionally what
///   someone means and usually not.
///
/// Both are now compile errors. Write `.as_bytes()` when you did mean the UTF-8.
///
/// # Implementing it
///
/// Implemented here for `[u8]`, `[u8; N]` and `Vec<u8>`. It is an **opt-in marker** in
/// the same family as [`CloneableSecret`](crate::CloneableSecret) and
/// [`SerializableSecret`](crate::SerializableSecret): implement it for your own
/// byte-shaped newtype to make it encodable.
///
/// ```rust
/// # #[cfg(all(feature = "encoding-hex", feature = "alloc"))] {
/// use secure_gate::{EncodableBytes, ToHex};
///
/// struct Nonce([u8; 12]);
/// impl AsRef<[u8]> for Nonce {
///     fn as_ref(&self) -> &[u8] { &self.0 }
/// }
/// impl EncodableBytes for Nonce {}
///
/// assert_eq!(Nonce([0xAB; 12]).to_hex().len(), 24);
/// # }
/// ```
///
/// The orphan rule means no downstream crate can implement it for `str` or `String`,
/// so the hole cannot be reopened from outside.
#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base32",
    feature = "encoding-base64",
    feature = "encoding-bech32",
))]
pub trait EncodableBytes {}

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base32",
    feature = "encoding-base64",
    feature = "encoding-bech32",
))]
impl EncodableBytes for [u8] {}

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base32",
    feature = "encoding-base64",
    feature = "encoding-bech32",
))]
impl<const N: usize> EncodableBytes for [u8; N] {}

#[cfg(all(
    feature = "alloc",
    any(
        feature = "encoding-hex",
        feature = "encoding-base32",
        feature = "encoding-base64",
        feature = "encoding-bech32",
    )
))]
impl EncodableBytes for alloc::vec::Vec<u8> {}

// Every encoding trait produces EncodedSecret — all require alloc
#[cfg(all(feature = "encoding-base32", feature = "alloc"))]
pub use base32::ToBase32;
#[cfg(all(feature = "encoding-base64", feature = "alloc"))]
pub use base64_url::ToBase64Url;
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
pub use bech32::ToBech32;
#[cfg(feature = "encoding-bech32")]
pub use bech32::{BECH32_CODE_LENGTH, Bech32Sized, Bech32Standard, bech32_code_length};
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
pub use bech32m::ToBech32m;
#[cfg(feature = "encoding-bech32")]
pub use bech32m::{Bech32mSized, Bech32mStandard};
#[cfg(all(feature = "encoding-hex", feature = "alloc"))]
pub use hex::ToHex;
