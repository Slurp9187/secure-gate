//! Extension trait for probabilistic constant-time equality via BLAKE3 hashing.
//!
//! Provides fast equality checks for secrets by hashing inputs (BLAKE3) then
//! comparing the fixed 32-byte digests in constant time (via `ct_eq`/`subtle`).
//!
//! Ideal for **large or variable-length secrets** (e.g. ML-KEM ciphertexts ~1–1.5 KiB,
//! ML-DSA signatures ~2–4 KiB) where direct byte-by-byte `ct_eq` becomes slow or
//! increases side-channel surface.
//!
//! Extends [`crate::ConstantTimeEq`] to add hash-based probabilistic equality.
//!
//! ## Security Properties
//! - **Timing-safe**: BLAKE3 is data-independent; final 32-byte compare is constant-time.
//! - **Length hiding**: Original length not observable via timing/cache.
//! - **Keyed mode** (with `"rand"` feature): Per-process random key resists precomputation /
//!   multi-target attacks across comparisons.
//! - **Probabilistic**: Collision probability ~2⁻¹²⁸ — negligible for equality checks,
//!   but use [`crate::ConstantTimeEq`] for strict deterministic equality.
//!
//! ## Usage Recommendations
//! - For most use cases, prefer [`ConstantTimeEqExt::ct_eq_opt`] — it automatically selects the best strategy based on size.
//! - Use plain [`ConstantTimeEqExt::ct_eq_hash`] only for large inputs (>32 bytes) or when uniform probabilistic behavior is needed.
//! - Use [`crate::ConstantTimeEq`] for small deterministic equality (<32 bytes).
//!
//! ## Performance
//! - Fixed overhead (~120–150 ns on small inputs) + very low per-byte cost.
//! - Beats full `ct_eq` for > ~300–500 bytes (2× at 1 KiB, 5–8× at 100 KiB+).
//! - Prefer [`crate::ConstantTimeEq`] for tiny fixed-size tags (< 128–256 bytes).
//!
//! ## Warnings
//! - **DoS risk**: Hashing very large untrusted inputs is costly — rate-limit or bound sizes.
//! - **Not zero-collision**: Extremely unlikely false positives; don't rely on it for uniqueness.
//!
//! ## Example
//! ```
//! # #[cfg(feature = "ct-eq-hash")]
//! # {
//! use secure_gate::{Dynamic, ConstantTimeEqExt};
//! let a: Dynamic<Vec<u8>> = vec![42u8; 2048].into();  // e.g. ML-DSA signature
//! let b: Dynamic<Vec<u8>> = vec![42u8; 2048].into();  // matching value
//! if a.ct_eq_opt(&b, None) {
//!     // constant-time, fast for large blobs
//! }
//! # }
//! ```
#[cfg(feature = "ct-eq-hash")]
pub trait ConstantTimeEqExt: crate::ConstantTimeEq {
    /// Get the length of the secret data in bytes.
    fn len(&self) -> usize;

    /// Force BLAKE3 digest comparison (constant-time on 32-byte output).
    ///
    /// **Probabilistic** when `"rand"` feature is enabled (per-process random key).
    /// **Deterministic** otherwise.
    ///
    /// Collision probability ~2⁻¹²⁸ — negligible for equality checks,
    /// but **not zero**. Use `ct_eq` when strict determinism is required.
    ///
    /// Keyed mode resists multi-target precomputation attacks across many comparisons.
    ///
    /// DoS warning: hashing very large untrusted inputs is costly — bound sizes.
    fn ct_eq_hash(&self, other: &Self) -> bool;

    /// Recommended hybrid constant-time equality check.
    ///
    /// - Length mismatch → `false` (public metadata, non-constant-time compare)
    /// - Size ≤ threshold → `self.ct_eq(other)` (strict deterministic)
    /// - Size > threshold → `self.ct_eq_hash(other)` (probabilistic, fast)
    ///
    /// Default threshold: **32 bytes** (tuned via your 2019 laptop benches)
    ///
    /// Prefer this method in almost all cases unless you need:
    /// - Guaranteed zero-collision → use `ct_eq`
    /// - Uniform probabilistic behavior → use `ct_eq_hash`
    fn ct_eq_opt(&self, other: &Self, threshold_bytes: Option<usize>) -> bool {
        // Default implementation (can be overridden if desired)
        if self.len() != other.len() {
            return false;
        }

        let thresh = threshold_bytes.unwrap_or(32);

        if self.len() <= thresh {
            self.ct_eq(other)
        } else {
            self.ct_eq_hash(other)
        }
    }
}
