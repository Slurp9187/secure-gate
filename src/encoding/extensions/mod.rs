pub mod core;
#[cfg(feature = "encoding-hex")]
pub mod hex;
#[cfg(feature = "encoding-base64")]
pub mod base64;
#[cfg(feature = "encoding-bech32")]
pub mod bech32;

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
pub use core::SecureEncodingExt;
#[cfg(feature = "encoding-hex")]
pub use hex::HexStringView;
#[cfg(feature = "encoding-base64")]
pub use base64::Base64StringView;
#[cfg(feature = "encoding-bech32")]
pub use bech32::Bech32StringView;
