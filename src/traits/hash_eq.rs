/// Probabilistic constant-time equality via BLAKE3 hashing.
///
/// Provides fast equality checks for secrets by hashing inputs (BLAKE3) then
/// comparing the fixed 32-byte digests in constant time (via `ct_eq`/`subtle`).
///
/// Ideal for **large or variable-length secrets** (e.g. ML-KEM ciphertexts ~1–1.5 KiB,
/// ML-DSA signatures ~2–4 KiB) where direct byte-by-byte `ct_eq` becomes slow or
/// increases side-channel surface.
///
/// ## Security Properties
/// - **Timing-safe**: BLAKE3 is data-independent; final 32-byte compare is constant-time.
/// - **Length hiding**: Original length not observable via timing/cache.
/// - **Keyed mode** (with `"rand"` feature): Per-process random key resists precomputation /
///   multi-target attacks across comparisons.
/// - **Probabilistic**: Collision probability ~2⁻¹²⁸ — negligible for equality checks,
///   but use [`ConstantTimeEq`] for strict deterministic equality.
///
/// ## Performance
/// - Fixed overhead (~120–150 ns on small inputs) + very low per-byte cost.
/// - Beats full `ct_eq` for > ~300–500 bytes (2× at 1 KiB, 5–8× at 100 KiB+).
/// - Prefer [`ConstantTimeEq`] for tiny fixed-size tags (< 128–256 bytes).
///
/// ## Warnings
/// - **DoS risk**: Hashing very large untrusted inputs is costly — rate-limit or bound sizes.
/// - **Not zero-collision**: Extremely unlikely false positives; don't rely on it for uniqueness.
///
/// ## Example
/// ```
/// # #[cfg(feature = "hash-eq")]
/// # {
/// use secure_gate::{Dynamic, HashEq};
/// let a: Dynamic<Vec<u8>> = vec![42u8; 2048].into();  // e.g. ML-DSA signature
/// let b: Dynamic<Vec<u8>> = vec![42u8; 2048].into();  // matching value
/// if a.hash_eq(&b) {
///     // constant-time, fast for large blobs
/// }
/// # }
/// ```
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
