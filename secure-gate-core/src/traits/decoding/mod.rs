//! Decoding traits for explicit string-to-bytes conversion.
//!
//! > **Import paths:** `use secure_gate::FromHexStr;` etc. (not `secure_gate::traits::decoding::hex::FromHexStr`)
//!
//! All decoding traits return `Vec<u8>` (require `alloc`). For no-alloc targets, use
//! `Fixed::try_from_hex`, `Fixed::try_from_base64url`, etc. — these decode directly into
//! a stack-allocated buffer. Treat all input as untrusted. Prefer HRP-validated bech32 methods.
//! See the [`encoding`](super::encoding) module for the reverse direction.
//!
//! Each decoding trait has its own feature gate:
//!
//! | Trait               | Feature             |
//! |---------------------|---------------------|
//! | [`FromHexStr`]      | `encoding-hex`      |
//! | [`FromBase64UrlStr`]| `encoding-base64`   |
//! | [`FromBech32Str`]   | `encoding-bech32`   |
//! | [`FromBech32mStr`]  | `encoding-bech32m`  |
pub mod base64_url;
pub mod bech32;
#[cfg(feature = "encoding-bech32m")]
pub mod bech32m;
pub mod hex;

#[cfg(all(feature = "encoding-base64", feature = "alloc"))]
pub use base64_url::FromBase64UrlStr;
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
pub use self::bech32::FromBech32Str;
#[cfg(all(feature = "encoding-bech32m", feature = "alloc"))]
pub use bech32m::FromBech32mStr;
#[cfg(all(feature = "encoding-hex", feature = "alloc"))]
pub use hex::FromHexStr;
