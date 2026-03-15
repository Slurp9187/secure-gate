//! Extension trait for probabilistic constant-time equality via BLAKE3 hashing.
//!
//! This trait extends [`ConstantTimeEq`] to provide fast, timing-safe equality
//! checks for **large or variable-length secrets** by comparing fixed-size BLAKE3
//! digests instead of byte-by-byte comparison.
//!
//! Ideal for:
//! - ML-KEM/ML-DSA ciphertexts & signatures (~1–4 KiB)
//! - Long authentication tokens
//! - Any secret > ~300–500 bytes where full `ct_eq` becomes slow
//!
//! Requires the `ct-eq-hash` feature.
//!
//! # Security Properties
//!
//! - **Always timing-safe**: BLAKE3 is data-independent; final 32-byte digest
//!   comparison uses `subtle::ConstantTimeEq`.
//! - **Length hiding**: Original length is not observable via timing or cache.
//! - **Keyed mode** (when `rand` enabled): A per-process random 32-byte key
//!   generated via `OsRng` resists multi-target precomputation and rainbow-table
//!   attacks across many comparisons.
//! - **Unkeyed fallback**: When `rand` is disabled, plain BLAKE3 is used — still
//!   cryptographically collision-resistant and constant-time.
//! - **Collision probability**: ~2⁻²⁵⁶ — negligible for equality checks, but
//!   **not zero**. Use [`ConstantTimeEq`] when strict determinism is required.
//!
//! # Usage Recommendations
//!
//! - **Preferred**: [`ct_eq_auto`] — automatically selects:
//!   - `ct_eq` for small inputs (≤ 32 bytes default)
//!   - `ct_eq_hash` for larger inputs
//! - Use `ct_eq_hash` directly only when you need uniform probabilistic behavior.
//! - Use `ConstantTimeEq` directly for small, fixed-size secrets (< 128–256 bytes).
//!
//! # Performance
//!
//! - Fixed BLAKE3 overhead (~120–150 ns on small inputs) + very low per-byte cost.
//! - Beats full `ct_eq` for > ~300–500 bytes (2× faster at 1 KiB, 5–8× at 100 KiB+).
//! - See [`CT_EQ_AUTO.md`](../CT_EQ_AUTO.md) for benchmarks and threshold tuning.
//!
//! # DoS Warning
//!
//! Hashing very large **untrusted** inputs is computationally expensive.
//! Always bound input sizes or rate-limit before calling these methods on user data.
//!
//! # Example
//!
//! ```rust
//! # #[cfg(feature = "ct-eq-hash")]
//! use secure_gate::{Fixed, ConstantTimeEqExt};
//!
//! # #[cfg(feature = "ct-eq-hash")]
//! {
//! let large_a = Fixed::<[u8; 2048]>::new([42u8; 2048]);
//! let large_b = Fixed::<[u8; 2048]>::new([42u8; 2048]);
//! let large_c = Fixed::<[u8; 2048]>::new([99u8; 2048]);
//!
//! // Fast probabilistic comparison for large secrets
//! assert!(large_a.ct_eq_hash(&large_b));
//! assert!(!large_a.ct_eq_hash(&large_c));
//!
//! // Recommended: automatic selection
//! assert!(large_a.ct_eq_auto(&large_b, None));      // uses ct_eq_hash
//! assert!(large_a.ct_eq_auto(&large_b, Some(4096))); // forces ct_eq_hash
//! # }
//! ```
#[cfg(feature = "ct-eq-hash")]
#[allow(clippy::len_without_is_empty)]
pub trait ConstantTimeEqExt: crate::ConstantTimeEq {
    /// Returns the length of the secret data in bytes.
    ///
    /// Note: This trait intentionally does **not** provide `.is_empty()` to avoid
    /// method name conflicts with [`ExposeSecret::len`] / `.is_empty()`.
    /// Use `.len() == 0` or `.expose_secret().is_empty()` when you need emptiness checks.
    fn len(&self) -> usize;

    /// Force BLAKE3 digest comparison (constant-time on 32-byte output).
    ///
    /// **Probabilistic** when the `rand` feature is enabled (per-process random key).
    /// **Deterministic** otherwise.
    ///
    /// Collision probability ~2⁻²⁵⁶ — negligible for equality checks,
    /// but **not zero**. Use `ct_eq` when strict determinism is required.
    ///
    /// Keyed mode resists multi-target precomputation attacks across many comparisons.
    ///
    /// DoS warning: hashing very large untrusted inputs is costly — bound sizes.
    fn ct_eq_hash(&self, other: &Self) -> bool;

    /// Recommended hybrid constant-time equality check.
    ///
    /// Automatically chooses the best strategy:
    ///
    /// - Length mismatch → `false` (public metadata, non-constant-time compare)
    /// - Size ≤ threshold → `self.ct_eq(other)` (strict deterministic)
    /// - Size > threshold → `self.ct_eq_hash(other)` (probabilistic, fast)
    ///
    /// Default threshold: **32 bytes** — optimal on most hardware for small secrets.
    /// Customize with `threshold_bytes: Some(n)` if your benchmarks show a different
    /// optimal crossover point (e.g., `64`, `1024`, or `0` to always use `ct_eq`).
    ///
    /// Prefer this method in almost all cases unless you need:
    /// - Guaranteed zero-collision → use `ct_eq`
    /// - Uniform probabilistic behavior → use `ct_eq_hash`
    ///
    /// See [CT_EQ_AUTO.md](../CT_EQ_AUTO.md) for benchmarks and threshold tuning guidance.
    fn ct_eq_auto(&self, other: &Self, threshold_bytes: Option<usize>) -> bool {
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
