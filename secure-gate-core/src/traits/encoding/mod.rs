//! Encoding traits for explicit secret-to-string conversion.
//!
//! > **Import paths:** `use secure_gate::ToHex;` etc. (not `secure_gate::traits::encoding::hex::ToHex`)
//!
//! All encoding traits require `alloc` (they return `String` or [`EncodedSecret`](crate::EncodedSecret)).
//! Prefer zeroizing variants (`*_zeroizing`) when the encoded form is sensitive.
//! See the [`decoding`](super::decoding) module for the reverse direction.
//!
//! Each encoding trait has its own feature gate:
//!
//! | Trait            | Feature             |
//! |------------------|---------------------|
//! | [`ToHex`]        | `encoding-hex`      |
//! | [`ToBase64Url`]  | `encoding-base64`   |
//! | [`ToBech32`]     | `encoding-bech32`   |
//! | [`ToBech32m`]    | `encoding-bech32m`  |
pub mod base64_url;
pub mod bech32;
#[cfg(feature = "encoding-bech32m")]
pub mod bech32m;
pub mod hex;

// Encoding traits produce String / EncodedSecret — all require alloc
#[cfg(all(feature = "encoding-base64", feature = "alloc"))]
pub use base64_url::ToBase64Url;
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
pub use self::bech32::ToBech32;
#[cfg(all(feature = "encoding-bech32m", feature = "alloc"))]
pub use bech32m::ToBech32m;
#[cfg(all(feature = "encoding-hex", feature = "alloc"))]
pub use hex::ToHex;
