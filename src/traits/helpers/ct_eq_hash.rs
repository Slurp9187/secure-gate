//! Constant-time hash-based equality utilities.
//!
//! This internal helper module provides a single fast path for probabilistic,
//! constant-time equality checks on large or variable-length secrets using
//! BLAKE3 hashing.
//!
//! It is used exclusively by the [`ConstantTimeEqExt`] trait (and its
//! recommended [`ct_eq_auto`] method) when secrets exceed the default
//! 32-byte threshold.
//!
//! # Security Properties
//!
//! - **Always constant-time**: Digest comparison uses `subtle::ConstantTimeEq`.
//! - **Keyed mode (when `rand` enabled)**: A per-process random 32-byte key
//!   is generated once via `OsRng` and reused. This adds resistance to
//!   multi-target precomputation and rainbow-table attacks.
//! - **Unkeyed fallback**: When `rand` is disabled, plain BLAKE3 is used
//!   (still collision-resistant and constant-time).
//! - **Negligible collision risk**: ~2⁻²⁵⁶ for any practical secret size.
//!
//! # Performance
//!
//! Hashing scales far better than byte-by-byte comparison for secrets > 1 KB.
//! See [`CT_EQ_AUTO.md`](../CT_EQ_AUTO.md) for benchmarks and threshold tuning guidance.
//!
//! This module is **not part of the public API**. Users should call
//! `.ct_eq_hash()` or `.ct_eq_auto()` on `Fixed<T>` / `Dynamic<T>` instead.

#[cfg(feature = "ct-eq-hash")]
use crate::ConstantTimeEq;

/// Constant-time hash-based equality check.
///
/// Uses BLAKE3 (keyed when the `rand` feature is enabled) to compare two byte
/// slices. Returns `false` immediately on length mismatch.
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
