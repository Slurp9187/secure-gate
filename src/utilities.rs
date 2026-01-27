//! Shared utility functions for the `secure-gate` crate.
//!
//! This module contains internal helpers for cryptographic operations,
//! constant-time equality, and encoding utilities.

#[cfg(feature = "ct-eq-hash")]
use crate::ConstantTimeEq;

/// Constant-time hash-based equality check.
/// Uses BLAKE3 with optional random keying for collision resistance.
#[cfg(feature = "ct-eq-hash")]
#[inline]
pub(crate) fn ct_eq_hash_bytes(data1: &[u8], data2: &[u8]) -> bool {
    if data1.len() != data2.len() {
        return false;
    }

    #[cfg(feature = "rand")]
    {
        use once_cell::sync::Lazy;
        use rand::{rngs::OsRng, TryRngCore};

        static HASH_EQ_KEY: Lazy<[u8; 32]> = Lazy::new(|| {
            let mut key = [0u8; 32];
            OsRng
                .try_fill_bytes(&mut key)
                .expect("OsRng failure is a program error");
            key
        });

        let mut hasher_a = blake3::Hasher::new_keyed(&HASH_EQ_KEY);
        let mut hasher_b = blake3::Hasher::new_keyed(&HASH_EQ_KEY);

        hasher_a.update(data1);
        hasher_b.update(data2);

        hasher_a
            .finalize()
            .as_bytes()
            .ct_eq(hasher_b.finalize().as_bytes())
    }

    #[cfg(not(feature = "rand"))]
    {
        let hash_a = blake3::hash(data1);
        let hash_b = blake3::hash(data2);
        hash_a.as_bytes().ct_eq(hash_b.as_bytes())
    }
}

/// Bit conversion utility for Bech32 encoding.
/// Converts between different bit widths (e.g., 8-bit bytes to 5-bit values).
#[cfg(feature = "encoding-bech32")]
#[inline]
pub(crate) fn convert_bits(
    from: u8,
    to: u8,
    pad: bool,
    data: &[u8],
) -> Result<(alloc::vec::Vec<u8>, usize), ()> {
    if !(1..=8).contains(&from) || !(1..=8).contains(&to) {
        return Err(());
    }
    let mut acc = 0u64;
    let mut bits = 0u8;
    let mut ret = alloc::vec::Vec::new();
    let maxv = (1u64 << to) - 1;
    let _max_acc = (1u64 << (from + to - 1)) - 1;
    for &v in data {
        if ((v as u32) >> from) != 0 {
            return Err(());
        }
        acc = (acc << from) | (v as u64);
        bits += from;
        while bits >= to {
            bits -= to;
            ret.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            ret.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return Err(());
    }
    Ok((ret, bits as usize))
}

/// Convert 5-bit values back to 8-bit bytes.
/// Used during Bech32 decoding to reconstruct original byte data.
#[cfg(feature = "encoding-bech32")]
#[inline]
pub(crate) fn fes_to_u8s<T: Into<u8>>(data: Vec<T>) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(data.len() * 5 / 8 + 1);
    let mut carry: u16 = 0;
    let mut carry_bits: u8 = 0;

    for fe in data {
        carry = (carry << 5) | (fe.into() as u16);
        carry_bits += 5;

        while carry_bits >= 8 {
            carry_bits -= 8;
            let byte = (carry >> carry_bits) as u8;
            bytes.push(byte);
            carry &= (1 << carry_bits) - 1;
        }
    }

    bytes
}

#[cfg(feature = "encoding-bech32")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fes_to_u8s_small() {
        let data = vec![0];
        let result = fes_to_u8s(data);
        assert_eq!(result, Vec::<u8>::new());
    }

    #[test]
    fn test_fes_to_u8s_bip173() {
        // Test with BIP173 test vector
        let s = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let (hrp, data_5bit) = ::bech32::decode(s).expect("decode failed");
        assert_eq!(hrp.as_str(), "bc");
        let bytes = fes_to_u8s(data_5bit);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn fes_to_u8s_large_input() {
        let large_input = vec![31u8; 8192]; // 8192 × 5 = 40,960 bits ≈ 5 KB
        let result = fes_to_u8s(large_input);
        assert_eq!(result.len(), 5120);
        assert!(result.iter().all(|&b| b == 255)); // 31 (11111) packs to 255 (11111111)
    }
}
