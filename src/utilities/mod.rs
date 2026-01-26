//! Shared utility functions for the `secure-gate` crate.
//!
//! This module contains helpers used by both `Fixed` and `Dynamic` secret types,
//! especially for random generation, constant-time / hash-based equality,
//! and string decoding during deserialization.

pub mod conversion;
pub mod decoding;

#[cfg(feature = "ct-eq-hash")]
use crate::ConstantTimeEq;

// ─────────────────────────────────────────────────────────────────────────────
//                Hash-based / constant-time equality helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Constant-time / hash-based equality check for arbitrary byte slices.
///
/// When the `rand` feature is enabled, uses a static random key + BLAKE3.
/// Otherwise falls back to plain BLAKE3 (still constant-time via `ct_eq`).
#[cfg(feature = "ct-eq-hash")]
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

// ─────────────────────────────────────────────────────────────────────────────
//                   String → bytes decoding helpers
// ─────────────────────────────────────────────────────────────────────────────
