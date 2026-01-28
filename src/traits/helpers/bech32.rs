//! Bech32 encoding and decoding utilities.
//!
//! Re-exports public API from the `bech32` crate (v0.11) for bit conversion via iterators,
//! full encoding/decoding, and types. No custom implementation needed.
//!
//! - For 8→5 bit conversion: `data.iter().copied().bytes_to_fes()` (pads with 0s).
//! - For 5→8 bit conversion: `fes_iter.fes_to_bytes()` (drops trailing <8 bits).
//! - Checksummed large payloads: Use `Bech32Large` (4096 Fe32 limit, BIP-173 checksum).
//! - Uncapped no-checksum: Use `NoChecksum` (usize::MAX limit).
//! - Encoding: `encode_lower::<Bech32Large>(Hrp::parse("hrp")?, data)?`.
//! - Decoding: Traits use manual parse + re-encode validation for `Bech32Large`; `decode` for standard.
//
#[cfg(feature = "encoding-bech32")]
pub use bech32::{decode, encode_lower, primitives::iter::Fe32IterExt, Bech32m, Fe32, Hrp};

#[cfg(feature = "encoding-bech32")]
use bech32::primitives::checksum::Checksum;

/// Custom Bech32 checksum with extended CODE_LENGTH for large payloads,
/// matching classic Bech32 (BIP-173) but with higher limit like age implementations.
#[cfg(feature = "encoding-bech32")]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Bech32Large {}

#[cfg(feature = "encoding-bech32")]
impl Checksum for Bech32Large {
    type MidstateRepr = u32;

    const CODE_LENGTH: usize = 4096;

    const CHECKSUM_LENGTH: usize = 6;

    const GENERATOR_SH: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

    const TARGET_RESIDUE: u32 = 1;
}

// Alias Fe32 for traits if needed
#[cfg(feature = "encoding-bech32")]
#[cfg(test)]
mod tests {
    use super::*;
    use bech32::primitives::iter::ByteIterExt;
    use bech32::Hrp;
    use bech32::{Bech32, NoChecksum};

    #[test]
    fn test_bit_conversion_large_uncapped() {
        let large_data = vec![0u8; 4096]; // Classic Bech32 equiv ~3.2KB input
        let fes: Vec<Fe32> = large_data.iter().copied().bytes_to_fes().collect();
        assert_eq!(fes.len(), (large_data.len() * 8).div_ceil(5)); // 6554

        let bytes_back: Vec<u8> = fes.iter().copied().fes_to_bytes().collect();
        assert_eq!(bytes_back, large_data); // Roundtrip (drops 0-pad)
    }

    #[test]
    fn test_full_encode_decode_uncapped() {
        let large_data = vec![0u8; 1000]; // >800 bytes, uncapped
        let hrp = Hrp::parse("test").unwrap();
        let encoded = encode_lower::<NoChecksum>(hrp, &large_data).unwrap();
        assert!(encoded.len() > 1000 * 8 / 5); // ~1600 chars

        // Manual decode for NoChecksum (no checksum validation)
        let s = &encoded;
        let pos = s.find('1').unwrap();
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
        let _ = encode_lower::<Bech32m>(hrp, &large_data).unwrap(); // Panic on >1023 Fe32
    }

    // Adapt BIP-173 vector with standard Bech32
    #[test]
    fn test_bip173_roundtrip() {
        let data = b"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"[4..].to_vec(); // Strip HRP
        let hrp = Hrp::parse("bc").unwrap();
        let encoded = encode_lower::<Bech32>(hrp, &data).unwrap();
        let (decoded_hrp, decoded_data) = decode(&encoded).unwrap();
        assert_eq!(decoded_hrp, hrp);
        assert_eq!(decoded_data, data);
    }

    // Test large with Bech32Large
    #[test]
    fn test_bech32_large_with_checksum() {
        let large_data = vec![0u8; 1000]; // ~1600 Fe32 < 4096
        let hrp = Hrp::parse("test").unwrap();
        let encoded = encode_lower::<Bech32Large>(hrp, &large_data).unwrap();
        // Manual decode: parse HRP and data part (without checksum)
        let pos = encoded.find('1').unwrap();
        let hrp_str = &encoded[..pos];
        let data_str = &encoded[pos + 1..];
        let decoded_hrp = Hrp::parse(hrp_str).unwrap();
        let data_part = &data_str[..data_str.len() - 6]; // Remove 6 checksum chars
        let mut fe32s = Vec::new();
        for c in data_part.chars() {
            fe32s.push(Fe32::from_char(c).unwrap());
        }
        let decoded_data: Vec<u8> = fe32s.iter().copied().fes_to_bytes().collect();
        assert_eq!(decoded_hrp, hrp);
        assert_eq!(decoded_data, large_data);
        // Verify re-encode matches
        let re_encoded = encode_lower::<Bech32Large>(decoded_hrp, &decoded_data).unwrap();
        assert_eq!(re_encoded, encoded);
    }
}
