#[cfg(feature = "hash-eq")]
use crate::ConstantTimeEq;

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
    }

    #[cfg(not(feature = "rand"))]
    {
        let hash_a = blake3::hash(data1);
        let hash_b = blake3::hash(data2);
        hash_a.as_bytes().ct_eq(hash_b.as_bytes())
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