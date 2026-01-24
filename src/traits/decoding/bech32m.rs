//! # FromBech32mStr Trait
//!
//! Extension trait for decoding Bech32m strings to byte data.
//!
//! This trait provides secure, explicit decoding of Bech32m strings (BIP-350 checksum) to byte vectors.
//! Input should be treated as untrusted; use fallible methods.
//!
//! ## Security Warning
//!
//! Decoding input from untrusted sources should use fallible `try_` methods.
//! Invalid input may indicate tampering or errors.
//!
//! ## Example
//!
//! ```rust
//! use secure_gate::traits::FromBech32mStr;
//! let bech32m_string = "bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5ss52r5n";
//! let (hrp, bytes) = bech32m_string.try_from_bech32m().unwrap();
//! // hrp is "bc", bytes is the decoded Vec<u8>
//! ```

#[cfg(feature = "encoding-bech32")]
use ::bech32;

#[cfg(feature = "encoding-bech32")]
use crate::utilities::encoding::fes_to_u8s;
#[cfg(feature = "encoding-bech32")]
use crate::error::Bech32Error;

#[cfg(feature = "encoding-bech32")]
pub trait FromBech32mStr {
    /// Fallibly decode a Bech32m string to (HRP, bytes).
    fn try_from_bech32m(&self) -> Result<(String, Vec<u8>), Bech32Error>;

    /// Fallibly decode a Bech32m string, expecting the specified HRP, returning bytes.
    fn try_from_bech32m_expect_hrp(&self, expected_hrp: &str) -> Result<Vec<u8>, Bech32Error>;
}

// Blanket impl to cover any AsRef<str> (e.g., &str, String, etc.)
#[cfg(feature = "encoding-bech32")]
impl<T: AsRef<str> + ?Sized> FromBech32mStr for T {
    fn try_from_bech32m(&self) -> Result<(String, Vec<u8>), Bech32Error> {
        let s = self.as_ref();
        let (hrp, data) = bech32::decode(s).map_err(|_| Bech32Error::OperationFailed)?;
        let re_encoded = bech32::encode::<bech32::Bech32m>(hrp.clone(), &data)
            .map_err(|_| Bech32Error::OperationFailed)?;
        if re_encoded == s {
            Ok((hrp.as_str().to_string(), fes_to_u8s(data)))
        } else {
            Err(Bech32Error::OperationFailed)
        }
    }

    fn try_from_bech32m_expect_hrp(&self, expected_hrp: &str) -> Result<Vec<u8>, Bech32Error> {
        let (hrp, data) = self.try_from_bech32m()?;
        if hrp != expected_hrp {
            return Err(Bech32Error::UnexpectedHrp {
                expected: expected_hrp.to_string(),
                got: hrp,
            });
        }
        Ok(data)
    }
}
