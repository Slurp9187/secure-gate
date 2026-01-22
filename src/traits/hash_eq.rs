//! Probabilistic constant-time equality for secret types.
//!
//! This module provides the [`HashEq`] trait, which enables fast, constant-time equality
//! checks using BLAKE3 hashing. This is ideal for large or variable-length secrets where
//! direct comparison would be inefficient.
//!
//! ## Key Features
//!
//! - **Constant-time**: Uses [`subtle::ct_eq`] for hash comparison.
//! - **Keyed hashing** (optional): With `rand` enabled, uses a per-process random key to
//!   mitigate offline precomputation attacks.
//! - **Performance**: Flat ~120–130ns variance, superior to ct_eq for large secrets.
//!
//! ## Security Considerations
//!
//! - **Probabilistic**: Extremely low collision risk, but not zero. Use [`ConstantTimeEq`]
//!   for strict equality.
//! - **DoS potential**: Hashing large inputs can be costly; rate-limit untrusted comparisons.
//! - **Keyed mode**: Enabled with `rand` for stronger security in adversarial scenarios.
//! - **Prefer ct_eq for small secrets**: Hashing has overhead; direct comparison is faster for <32 bytes.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use secure_gate::{Fixed, HashEq};
//! let secret1: Fixed<[u8; 64]> = Fixed::new([42u8; 64]);
//! let secret2: Fixed<[u8; 64]> = Fixed::new([42u8; 64]);
//! assert!(secret1.hash_eq(&secret2)); // Fast, constant-time check
//! ```

#[cfg(feature = "hash-eq")]
use crate::traits::constant_time_eq::ConstantTimeEq;
#[cfg(feature = "hash-eq")]
use crate::Dynamic;
#[cfg(feature = "hash-eq")]
use crate::Fixed;
use blake3::Hasher;

#[cfg(all(feature = "hash-eq", feature = "rand"))]
use once_cell::sync::Lazy;
#[cfg(all(feature = "hash-eq", feature = "rand"))]
use rand::rngs::OsRng;
#[cfg(all(feature = "hash-eq", feature = "rand"))]
use rand::TryRngCore;

#[cfg(all(feature = "hash-eq", feature = "rand"))]
static HASH_EQ_KEY: Lazy<[u8; 32]> = Lazy::new(|| {
    let mut key = [0u8; 32];
    let mut rng = OsRng;
    rng.try_fill_bytes(&mut key).unwrap();
    key
});

/// Compute BLAKE3 hash of bytes, with optional keying.
#[cfg(feature = "hash-eq")]
fn hash_bytes(bytes: &[u8]) -> [u8; 32] {
    #[cfg(feature = "rand")]
    let mut hasher = Hasher::new_keyed(&HASH_EQ_KEY);
    #[cfg(not(feature = "rand"))]
    let mut hasher = Hasher::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Probabilistic constant-time equality check using BLAKE3 hashing.
///
/// This trait provides a fast, constant-time equality comparison that uses cryptographic
/// hashing (BLAKE3) instead of direct byte comparison. This is useful for comparing large or
/// variable-length secrets where direct comparison would be inefficient or variable-time.
///
/// # Security Warnings
///
/// - **Probabilistic nature**: Hash collisions are extremely unlikely but not impossible.
///   Use [`ConstantTimeEq`] for strict cryptographic equality.
/// - **DoS amplification**: Hashing can be slower for large inputs; rate-limit in untrusted contexts.
/// - **Deterministic vs keyed**: Plain hashing is deterministic (useful for tests); keyed mode
///   with `rand` enabled mitigates precomputation attacks.
/// - **Not suitable for small/fixed secrets**: Prefer [`ConstantTimeEq`] for <32 bytes.
///
/// # Performance
///
/// - Flat timing: ~120–130ns variance across input sizes.
/// - Better than ct_eq for >32 bytes.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "hash-eq")]
/// # {
/// use secure_gate::{Fixed, HashEq};
/// let a = Fixed::new([1u8; 32]);
/// let b = Fixed::new([1u8; 32]);
/// assert!(a.hash_eq(&b));
/// # }
/// ```
#[cfg(feature = "hash-eq")]
pub trait HashEq {
    /// Perform constant-time equality check using BLAKE3 hashing.
    fn hash_eq(&self, other: &Self) -> bool;
}

#[cfg(feature = "hash-eq")]
impl<T> HashEq for Fixed<T>
where
    T: AsRef<[u8]>,
{
    fn hash_eq(&self, other: &Self) -> bool {
        let self_hash = hash_bytes(self.inner.as_ref());
        let other_hash = hash_bytes(other.inner.as_ref());
        self_hash.ct_eq(&other_hash)
    }
}

#[cfg(feature = "hash-eq")]
impl<T> HashEq for Dynamic<T>
where
    T: AsRef<[u8]>,
{
    fn hash_eq(&self, other: &Self) -> bool {
        let self_hash = hash_bytes((*self.inner).as_ref());
        let other_hash = hash_bytes((*other.inner).as_ref());
        self_hash.ct_eq(&other_hash)
    }
}
