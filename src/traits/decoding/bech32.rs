// secure-gate/src/traits/decoding/bech32.rs

#[cfg(feature = "encoding-bech32")]
use super::super::helpers::bech32::{encode_lower, Bech32Large, Fe32, Fe32IterExt, Hrp};
#[cfg(feature = "encoding-bech32")]
use crate::error::Bech32Error;

#[cfg(feature = "encoding-bech32")]
/// Extension trait for decoding Bech32 strings to byte data.
///
/// Input should be treated as untrusted; use fallible methods.
///
/// # Security Warning
///
/// Decoding input from untrusted sources should use fallible `try_` methods.
/// Invalid input may indicate tampering or errors.
pub trait FromBech32Str {
    /// Fallibly decode a Bech32 string to (HRP, bytes).
    fn try_from_bech32(&self) -> Result<(String, Vec<u8>), Bech32Error>;

    /// Fallibly decode a Bech32 string, expecting the specified HRP, returning bytes.
    fn try_from_bech32_expect_hrp(&self, expected_hrp: &str) -> Result<Vec<u8>, Bech32Error>;
}

// Blanket impl to cover any AsRef<str> (e.g., &str, String, etc.)
#[cfg(feature = "encoding-bech32")]
impl<T: AsRef<str> + ?Sized> FromBech32Str for T {
    fn try_from_bech32(&self) -> Result<(String, Vec<u8>), Bech32Error> {
        let s = self.as_ref();
        if let Some(pos) = s.find('1') {
            let hrp_str = &s[..pos];
            let data_str = &s[pos + 1..];
            let hrp = Hrp::parse(hrp_str).map_err(|_| Bech32Error::InvalidHrp)?;
            // For Bech32Large, checksum is 6 chars
            if data_str.len() < 6 {
                return Err(Bech32Error::OperationFailed);
            }
            let data_part = &data_str[..data_str.len() - 6];
            let mut fe32s = Vec::new();
            for c in data_part.chars() {
                let fe = Fe32::from_char(c).map_err(|_| Bech32Error::OperationFailed)?;
                fe32s.push(fe);
            }
            let data: Vec<u8> = fe32s.iter().copied().fes_to_bytes().collect();
            // Validate by re-encoding with Bech32Large
            let re_encoded = encode_lower::<Bech32Large>(hrp, &data)
                .map_err(|_| Bech32Error::OperationFailed)?;
            if re_encoded != s {
                return Err(Bech32Error::OperationFailed);
            }
            if data.is_empty() {
                return Err(Bech32Error::OperationFailed);
            }
            Ok((hrp.to_string(), data))
        } else {
            Err(Bech32Error::OperationFailed)
        }
    }

    fn try_from_bech32_expect_hrp(&self, expected_hrp: &str) -> Result<Vec<u8>, Bech32Error> {
        let (hrp, data) = self.try_from_bech32()?;
        if !hrp.to_string().eq_ignore_ascii_case(expected_hrp) {
            return Err(Bech32Error::UnexpectedHrp {
                expected: expected_hrp.to_string(),
                got: hrp.to_string(),
            });
        }
        Ok(data)
    }
}
