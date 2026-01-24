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
///   but use [`crate::ConstantTimeEq`] for strict deterministic equality.
///
/// ## Usage Recommendations
/// - For most use cases, prefer [`HashEq::hash_eq_opt`] — it automatically selects the best strategy based on size.
/// - Use plain [`HashEq::hash_eq`] only for large inputs (>32 bytes) or when uniform probabilistic behavior is needed.
/// - Use [`crate::ConstantTimeEq`] for small deterministic equality (<32 bytes).
///
/// ## Performance
/// - Fixed overhead (~120–150 ns on small inputs) + very low per-byte cost.
/// - Beats full `ct_eq` for > ~300–500 bytes (2× at 1 KiB, 5–8× at 100 KiB+).
/// - Prefer [`crate::ConstantTimeEq`] for tiny fixed-size tags (< 128–256 bytes).
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
/// if a.hash_eq_opt(&b, None) {
///     // constant-time, fast for large blobs
/// }
/// # }
/// ```
#[cfg(feature = "hash-eq")]
pub trait HashEq {
    /// Probabilistic constant-time equality check using BLAKE3 hashing.
    ///
    /// This provides a fast, constant-time equality comparison via BLAKE3 + fixed-size digest compare.
    /// Useful for large/variable-length secrets where direct `ct_eq` is slow or increases side-channel risk.
    ///
    /// # Security Warnings
    /// - Probabilistic: collisions extremely unlikely (~2⁻¹²⁸), but not impossible.
    ///   Use `ConstantTimeEq` for strict deterministic equality.
    /// - DoS risk: hashing large untrusted inputs is costly — bound sizes or rate-limit.
    /// - Deterministic unless `"rand"` feature is enabled (then per-process random key).
    ///
    /// # Performance
    /// - Fixed overhead ~120–150 ns + very low per-byte cost.
    /// - Beats full `ct_eq` for inputs > ~300–500 bytes.
    ///
    fn hash_eq(&self, other: &Self) -> bool;

    /// **Recommended** hybrid equality check: `ct_eq` for small inputs, `hash_eq` for large ones.
    ///
    /// Automatically chooses the faster/appropriate path while preserving constant-time safety.
    ///
    /// - Uses `ct_eq` (deterministic, zero collision risk) if size ≤ threshold
    /// - Uses `hash_eq` (probabilistic, faster for large inputs) if size > threshold
    /// - Default threshold: 32 bytes (conservative crossover point)
    /// - Length mismatch → `false` immediately (length is public metadata)
    ///
    /// # Arguments
    /// - `hash_threshold_bytes`: `None` = use default (32), `Some(n)` = custom threshold
    ///
    /// # When to use
    /// Prefer this method in most cases unless you need:
    /// - strict determinism on all sizes → use `ConstantTimeEq`
    /// - uniform probabilistic behavior → use plain `hash_eq`
    ///
    /// # Examples
    /// ```
    /// # #[cfg(feature = "hash-eq")]
    /// # {
    /// use secure_gate::{Dynamic, Fixed, HashEq};
    ///
    /// let small_a = Fixed::new([42u8; 16]);
    /// let small_b = Fixed::new([42u8; 16]);
    /// assert!(small_a.hash_eq_opt(&small_b, None));           // → ct_eq path
    ///
    /// let large_a: Dynamic<Vec<u8>> = vec![42u8; 2048].into();
    /// let large_b: Dynamic<Vec<u8>> = vec![42u8; 2048].into();
    /// assert!(large_a.hash_eq_opt(&large_b, None));           // → hash_eq path
    ///
    /// // Force hashing even on small input
    /// assert!(small_a.hash_eq_opt(&small_b, Some(0)));
    /// # }
    /// ```
    fn hash_eq_opt(&self, other: &Self, hash_threshold_bytes: Option<usize>) -> bool;
}
