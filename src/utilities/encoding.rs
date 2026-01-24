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
pub(crate) fn fes_to_u8s(data: Vec<u8>) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut acc: u64 = 0;
    let mut bits: u8 = 0;

    for fe in data {
        acc = (acc << 5) | (fe as u64);
        bits += 5;

        while bits >= 8 {
            bits -= 8;
            bytes.push(((acc >> bits) & 0xFF) as u8);
        }
    }

    bytes
}
