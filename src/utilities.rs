//! Shared utility functions for the `secure-gate` crate.
//!
//! This module contains helpers used by both `Fixed` and `Dynamic` secret types,
//! especially for random generation, constant-time / hash-based equality,
//! and string decoding during deserialization.

#[cfg(feature = "hash-eq")]
use crate::ConstantTimeEq;

#[cfg(feature = "rand")]
use rand::{rngs::OsRng, TryRngCore};

#[cfg(all(feature = "serde-deserialize", feature = "encoding-base64"))]
use base64::{engine::general_purpose, Engine as _};

/// Fills a mutable byte slice with cryptographically secure random bytes
/// using the OS-provided RNG.
///
/// # Panics
/// Panics on RNG failure (fail-fast behavior suitable for cryptographic code).
///
/// # Example
/// ```
/// # #[cfg(feature = "rand")]
/// # {
/// use secure_gate::utilities::fill_random_bytes_mut;
/// let mut key = [0u8; 32];
/// fill_random_bytes_mut(&mut key);
/// # }
/// ```
#[cfg(feature = "rand")]
pub fn fill_random_bytes_mut(bytes: &mut [u8]) {
    OsRng
        .try_fill_bytes(bytes)
        .expect("OsRng failure is a program error");
}

// ─────────────────────────────────────────────────────────────────────────────
//                Hash-based / constant-time equality helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Constant-time / hash-based equality check for arbitrary byte slices.
///
/// When the `rand` feature is enabled, uses a static random key + BLAKE3.
/// Otherwise falls back to plain BLAKE3 (still constant-time via `ct_eq`).
#[cfg(feature = "hash-eq")]
pub(crate) fn hash_eq_bytes(data1: &[u8], data2: &[u8]) -> bool {
    #[cfg(feature = "rand")]
    {
        use once_cell::sync::Lazy;

        static HASH_EQ_KEY: Lazy<[u8; 32]> = Lazy::new(|| {
            let mut key = [0u8; 32];
            fill_random_bytes_mut(&mut key); // now reuses the shared helper
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

/// Equality check that uses direct constant-time comparison for small inputs
/// and hash-based comparison for larger inputs (side-channel resistance).
#[cfg(feature = "hash-eq")]
pub(crate) fn hash_eq_opt_bytes(
    data1: &[u8],
    data2: &[u8],
    hash_threshold_bytes: Option<usize>,
) -> bool {
    if data1.len() != data2.len() {
        return false;
    }

    let threshold = hash_threshold_bytes.unwrap_or(32);

    if data1.len() <= threshold {
        data1.ct_eq(data2)
    } else {
        hash_eq_bytes(data1, data2)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//                   String → bytes decoding helpers
// ─────────────────────────────────────────────────────────────────────────────

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

/// Attempt to decode a string as bech32 → hex → base64 (in that priority order).
///
/// Returns `Ok(Vec<u8>)` on success or appropriate `DecodingError`.
#[cfg(feature = "serde-deserialize")]
pub(crate) fn try_decode(s: &str) -> Result<Vec<u8>, crate::DecodingError> {
    #[cfg(feature = "encoding-bech32")]
    if let Ok((_, data)) = bech32::decode(s) {
        return Ok(fes_to_u8s(data));
    }

    #[cfg(feature = "encoding-hex")]
    if let Ok(data) = hex::decode(s) {
        return Ok(data);
    }

    #[cfg(feature = "encoding-base64")]
    if let Ok(data) = general_purpose::URL_SAFE_NO_PAD.decode(s) {
        return Ok(data);
    }

    Err(crate::DecodingError::InvalidEncoding)
}

/// Decode string to bytes using supported encodings (for serde error mapping).
///
/// Convenience wrapper that converts errors to `String` for serde visitors.
#[cfg(feature = "serde-deserialize")]
pub fn decode_string_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    try_decode(s).map_err(|e| e.to_string())
}

/// Serde visitor helper: decode string → check exact length → copy to `[u8; N]`.
#[cfg(feature = "serde-deserialize")]
pub fn visit_byte_string<E, const N: usize>(v: &str, expected_len: usize) -> Result<[u8; N], E>
where
    E: serde::de::Error,
{
    let bytes = decode_string_to_bytes(v).map_err(E::custom)?;

    if bytes.len() != expected_len {
        return Err(E::invalid_length(
            bytes.len(),
            &expected_len.to_string().as_str(),
        ));
    }

    let mut arr = [0u8; N];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}
