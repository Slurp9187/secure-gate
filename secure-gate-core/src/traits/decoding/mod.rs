//! Re-exports for all decoding traits.
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
