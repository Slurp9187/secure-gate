// Convert Vec<u8> (5-bit values) to Vec<u8> by unpacking into 8-bit bytes.
#[cfg(feature = "hash-eq")]
use crate::ConstantTimeEq;

#[cfg(feature = "encoding-bech32")]
pub(crate) fn fes_to_u8s(data: alloc::vec::Vec<u8>) -> alloc::vec::Vec<u8> {
    let mut bytes = alloc::vec::Vec::new();
    let mut acc = 0u64;
    let mut bits = 0u8;
    for fe in data {
        acc = (acc << 5) | (fe as u64);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            bytes.push(((acc >> bits) & 0xFF) as u8);
        }
    }
    // For bech32, assume no padding needed as checksum is separate
    bytes
}

/// Shared hash_eq implementation for byte slices.
#[cfg(feature = "hash-eq")]
pub(crate) fn hash_eq_bytes(data1: &[u8], data2: &[u8]) -> bool {
    #[cfg(feature = "rand")]
    {
        use once_cell::sync::Lazy;
        use rand::{rngs::OsRng, TryRngCore};

        static HASH_EQ_KEY: Lazy<[u8; 32]> = Lazy::new(|| {
            let mut key = [0u8; 32];
            let mut rng = OsRng;
            rng.try_fill_bytes(&mut key).expect("RNG failure");
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
            .into()
    }

    #[cfg(not(feature = "rand"))]
    {
        let hash_a = blake3::hash(data1);
        let hash_b = blake3::hash(data2);

        hash_a.as_bytes().ct_eq(hash_b.as_bytes()).into()
    }
}

/// Shared hash_eq_opt implementation for byte slices.
#[cfg(feature = "hash-eq")]
pub(crate) fn hash_eq_opt_bytes(
    data1: &[u8],
    data2: &[u8],
    hash_threshold_bytes: Option<usize>,
) -> bool {
    let threshold = hash_threshold_bytes.unwrap_or(32);

    if data1.len() != data2.len() {
        return false;
    }

    let size = data1.len();

    if size <= threshold {
        data1.ct_eq(data2)
    } else {
        hash_eq_bytes(data1, data2)
    }
}

/// Helper function to try decoding a string as bech32, hex, or base64 in priority order.
#[cfg(feature = "serde-deserialize")]
pub(crate) fn try_decode(_s: &str) -> Result<alloc::vec::Vec<u8>, crate::DecodingError> {
    #[cfg(feature = "encoding-bech32")]
    if let Ok((_, data)) = ::bech32::decode(_s) {
        let bytes = fes_to_u8s(data);
        return Ok(bytes);
    }
    #[cfg(feature = "encoding-hex")]
    if let Ok(data) = ::hex::decode(_s) {
        return Ok(data);
    }

    #[cfg(feature = "encoding-base64")]
    if let Ok(data) = general_purpose::URL_SAFE_NO_PAD.decode(_s) {
        return Ok(data);
    }

    Err(crate::DecodingError::InvalidEncoding)
}

#[cfg(all(feature = "serde-deserialize", feature = "encoding-base64"))]
use base64::{engine::general_purpose, Engine};
