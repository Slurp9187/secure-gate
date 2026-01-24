// secure-gate/src/traits/encoding/mod.rs
pub mod base64_url;
pub mod bech32;
pub mod bech32m;
pub mod hex;

#[cfg(feature = "encoding-base64")]
pub use base64_url::ToBase64Url;
#[cfg(feature = "encoding-bech32")]
pub use bech32::ToBech32;
#[cfg(feature = "encoding-bech32")]
pub use bech32m::ToBech32m;
#[cfg(feature = "encoding-hex")]
pub use hex::ToHex;
