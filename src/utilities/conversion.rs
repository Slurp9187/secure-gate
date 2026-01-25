// secure-gate/src/utilities/encoding.rs
/// Local implementation of bit conversion for Bech32, since bech32 crate doesn't expose it in v0.11.
#[cfg(feature = "encoding-bech32")]
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

/// Convert 5-bit Fe32 values (from bech32 decode) back into 8-bit bytes.
///
/// Used internally during bech32 deserialization.
#[cfg(feature = "encoding-bech32")]
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
        // Small input: [0] (version 0) -> should produce empty or partial byte, but discarded
        let data = vec![0];
        let result = fes_to_u8s(data);
        assert_eq!(result, Vec::<u8>::new()); // No full ...
    }

    #[test]
    fn test_fes_to_u8s_bip173() {
        // Test with BIP173 vector to ensure no overflow
        let s = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let (hrp, data_5bit) = ::bech32::decode(s).expect("decode failed");
        assert_eq!(hrp.as_str(), "bc");
        let bytes = fes_to_u8s(data_5bit);
        // Should produce some bytes without panicking
        assert!(!bytes.is_empty());
    }

    #[test]
    fn fes_to_u8s_large_input() {
        let large_input = vec![31u8; 8192]; // 8192 × 5 = 40 960 bits ≈ 5 KB
        let result = fes_to_u8s(large_input);
        assert_eq!(result.len(), 5120); // exact if no remainder
                                        // Optional: check no panic, some non-zero bytes, etc.
        assert!(result.iter().all(|&b| b == 255)); // since 31 is 11111, packed to 11111111
    }
}
