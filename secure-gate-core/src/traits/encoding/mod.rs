//! Re-exports for all encoding traits.
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

#[cfg(feature = "encoding-base64")]
pub use self::base64_url::ToBase64Url;
#[cfg(feature = "encoding-bech32")]
pub use self::bech32::ToBech32;
#[cfg(feature = "encoding-bech32m")]
pub use self::bech32m::ToBech32m;
#[cfg(feature = "encoding-hex")]
pub use self::hex::ToHex;
