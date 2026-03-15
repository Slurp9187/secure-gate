//! Bech32 encoding and decoding utilities.
//!
//! This internal helper module re-exports the public API from the `bech32` crate (v0.11)
//! and provides bit conversion utilities via iterators. It is used exclusively by the
//! decoding and encoding traits in `traits::decoding` and `traits::encoding`.
//!
//! # Key Re-exports
//!
//! - `decode`, `encode_lower` — full encoding/decoding functions
//! - `Fe32`, `Hrp`, `Bech32m` — core types
//! - `Fe32IterExt` — iterator extensions for 8→5 and 5→8 bit conversion
//!
//! # Bit Conversion
//!
//! - 8→5 bit: `data.iter().copied().bytes_to_fes()` (pads with zeros)
//! - 5→8 bit: `fes_iter.fes_to_bytes()` (drops trailing <8 bits)
//!
//! # Custom Checksum: `Bech32Large`
//!
//! A custom checksum variant extending classic Bech32 (BIP-173) with a much higher
//! payload limit (`CODE_LENGTH = 4096` Fe32 values). This allows safe handling of
//! large secrets (up to ~3.2 KB raw data) while maintaining the standard 6-character
//! checksum.
//!
//! Used internally by the `ToBech32` / `FromBech32Str` traits for large payloads.
//!
//! # Usage in Traits
//!
//! ```rust
//! # {
//! use bech32::{encode_lower, Hrp};
//! use secure_gate::Bech32Large;
//!
//! let hrp = Hrp::parse("test").unwrap();
//! let data = vec![0u8; 1000]; // ~1 KB payload
//!
//! // Encoding (large payload)
//! let encoded = encode_lower::<Bech32Large>(hrp, &data).unwrap();
//! assert!(encoded.starts_with("test"));
//! # }
//! ```
//! This module is part of the public API for advanced users who need direct access
//! to the Bech32 checksum variants. For most use cases, prefer the traits
//! ("ToBech32", "FromBech32Str", etc.) instead.

#[cfg(feature = "encoding-bech32")]
pub use bech32::{encode_lower, primitives::decode::CheckedHrpstring, Bech32m, Hrp};

#[cfg(feature = "encoding-bech32")]
pub use super::super::encoding::bech32::Bech32Large;

// Tests remain unchanged (they are not part of rustdoc)
#[cfg(feature = "encoding-bech32")]
#[cfg(test)]
mod tests {
    use super::*;
    use bech32::primitives::iter::ByteIterExt;
    use bech32::{decode, Bech32, Fe32IterExt, NoChecksum};
    use bech32::{Fe32, Hrp};

    #[test]
    fn test_bit_conversion_large_uncapped() {
        let large_data = vec![0u8; 4096];
        let fes: Vec<Fe32> = large_data.iter().copied().bytes_to_fes().collect();
        assert_eq!(fes.len(), (large_data.len() * 8).div_ceil(5));

        let bytes_back: Vec<u8> = fes.iter().copied().fes_to_bytes().collect();
        assert_eq!(bytes_back, large_data);
    }

    #[test]
    fn test_full_encode_decode_uncapped() {
        let large_data = vec![0u8; 1000];
        let hrp = Hrp::parse("test").unwrap();
        let encoded = encode_lower::<NoChecksum>(hrp, &large_data).unwrap();
        assert!(encoded.len() > 1000 * 8 / 5);

        let s = &encoded;
        let pos = s.rfind('1').unwrap();
        let hrp_str = &s[..pos];
        let data_str = &s[pos + 1..];
        let decoded_hrp = Hrp::parse(hrp_str).unwrap();
        let mut fe32s = Vec::new();
        for c in data_str.chars() {
            fe32s.push(Fe32::from_char(c).unwrap());
        }
        let decoded_data: Vec<u8> = fe32s.iter().copied().fes_to_bytes().collect();
        assert_eq!(decoded_hrp, hrp);
        assert_eq!(decoded_data, large_data);
    }

    #[test]
    #[should_panic(expected = "TooLong")]
    fn test_capped_overflow_bech32m() {
        let large_data = vec![0u8; 800];
        let hrp = Hrp::parse("test").unwrap();
        let _ = encode_lower::<Bech32m>(hrp, &large_data).unwrap();
    }

    #[test]
    fn test_bip173_roundtrip() {
        let data = b"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"[4..].to_vec();
        let hrp = Hrp::parse("bc").unwrap();
        let encoded = encode_lower::<Bech32>(hrp, &data).unwrap();
        let (decoded_hrp, decoded_data) = decode(&encoded).unwrap();
        assert_eq!(decoded_hrp, hrp);
        assert_eq!(decoded_data, data);
    }

    #[test]
    fn test_bech32_large_with_checksum() {
        let large_data = vec![0u8; 1000];
        let hrp = Hrp::parse("test").unwrap();
        let encoded = encode_lower::<Bech32Large>(hrp, &large_data).unwrap();

        let pos = encoded.rfind('1').unwrap();
        let hrp_str = &encoded[..pos];
        let data_str = &encoded[pos + 1..];
        let decoded_hrp = Hrp::parse(hrp_str).unwrap();
        let data_part = &data_str[..data_str.len() - 6];
        let mut fe32s = Vec::new();
        for c in data_part.chars() {
            fe32s.push(Fe32::from_char(c).unwrap());
        }
        let decoded_data: Vec<u8> = fe32s.iter().copied().fes_to_bytes().collect();

        assert_eq!(decoded_hrp, hrp);
        assert_eq!(decoded_data, large_data);

        let re_encoded = encode_lower::<Bech32Large>(decoded_hrp, &decoded_data).unwrap();
        assert_eq!(re_encoded, encoded);
    }
}
