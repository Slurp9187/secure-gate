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

#[cfg(feature = "encoding-base64")]
pub use self::base64_url::FromBase64UrlStr;
#[cfg(feature = "encoding-bech32")]
pub use self::bech32::FromBech32Str;
#[cfg(feature = "encoding-bech32m")]
pub use self::bech32m::FromBech32mStr;
#[cfg(feature = "encoding-hex")]
pub use self::hex::FromHexStr;
