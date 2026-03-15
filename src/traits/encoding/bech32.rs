//! Bech32 encoding trait.
//!
//! This trait provides secure, explicit encoding of byte data to Bech32 strings
//! (BIP-173 checksum) with a specified Human-Readable Part (HRP). Designed for
//! intentional export (addresses, QR codes, audited logs).
//!
//! Requires the `encoding-bech32` feature.
//!
//! # Security Notes
//! - **Full secret exposure**: The resulting string contains the **entire** secret.
//!   Use only after explicit `.expose_secret()`.
//! - **HRP protection**: The HRP prevents cross-protocol confusion; `try_to_bech32`
//!   allows optional validation on round-trip.
//! - **Checksummed**: Uses the custom `Bech32Large` (4096 Fe32 limit) for large secrets.
//! - **Scoped access enforced**: No implicit exposure paths exist.
//!
//! # Example
//!
//! ```rust
//! # #[cfg(feature = "encoding-bech32")]
//! use secure_gate::{Fixed, ToBech32, ExposeSecret};
//!
//! # #[cfg(feature = "encoding-bech32")]
//! {
//! let secret = Fixed::new([0x42u8; 20]);
//! let bech32 = secret.expose_secret().to_bech32("test");
//! assert!(bech32.starts_with("test1"));
//! # }
//! ```
#[cfg(feature = "encoding-bech32")]
use super::super::helpers::bech32::{encode_lower, Bech32Large, Hrp};

#[cfg(feature = "encoding-bech32")]
use crate::error::Bech32Error;

/// Extension trait for encoding byte data to Bech32 strings with a specified HRP.
///
/// Requires `encoding-bech32` feature.
///
/// All methods require explicit `.expose_secret()` access first.
#[cfg(feature = "encoding-bech32")]
pub trait ToBech32 {
    /// Encode bytes as Bech32 with the specified HRP (infallible version).
    fn to_bech32(&self, hrp: &str) -> alloc::string::String;

    /// Fallibly encode bytes as Bech32 with the specified HRP and optional expected-HRP validation.
    fn try_to_bech32(
        &self,
        hrp: &str,
        expected_hrp: Option<&str>,
    ) -> Result<alloc::string::String, Bech32Error>;
}

// Blanket impl to cover any AsRef<[u8]> (e.g., &[u8], Vec<u8>, [u8; N], etc.)
#[cfg(feature = "encoding-bech32")]
impl<T: AsRef<[u8]> + ?Sized> ToBech32 for T {
    #[inline(always)]
    fn to_bech32(&self, hrp: &str) -> alloc::string::String {
        let hrp_parsed = Hrp::parse(hrp).expect("invalid hrp");
        encode_lower::<Bech32Large>(hrp_parsed, self.as_ref()).expect("bech32 encoding failed")
    }

    #[inline(always)]
    fn try_to_bech32(
        &self,
        hrp: &str,
        expected_hrp: Option<&str>,
    ) -> Result<alloc::string::String, Bech32Error> {
        let hrp_parsed = Hrp::parse(hrp).map_err(|_| Bech32Error::InvalidHrp)?;
        if let Some(exp) = expected_hrp {
            if hrp != exp {
                #[cfg(debug_assertions)]
                return Err(Bech32Error::UnexpectedHrp {
                    expected: exp.to_string(),
                    got: hrp.to_string(),
                });
                #[cfg(not(debug_assertions))]
                return Err(Bech32Error::UnexpectedHrp);
            }
        }
        encode_lower::<Bech32Large>(hrp_parsed, self.as_ref())
            .map_err(|_| Bech32Error::OperationFailed)
    }
}
