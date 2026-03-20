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
//! - **Preferred**: [`ConstantTimeEqExt::ct_eq_auto`] — automatically selects:
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
//! `==` is deliberately not implemented on secret wrappers — use `ct_eq_auto`.
//!
//! # Example
//!
//! ```rust,no_run
//! use secure_gate::{Fixed, ConstantTimeEqExt};
//!
//! let large_a = Fixed::<[u8; 2048]>::new([42u8; 2048]);
//! let large_b = Fixed::<[u8; 2048]>::new([42u8; 2048]);
//! let large_c = Fixed::<[u8; 2048]>::new([99u8; 2048]);
//!
//! // Recommended: automatic strategy selection (hash path uses OsRng when `rand` enabled)
//! assert!(large_a.ct_eq_auto(&large_b));
//! assert!(!large_a.ct_eq_auto(&large_c));
//!
//! // Power users: explicit threshold (uses ct_eq for all ≤ 64B inputs)
//! assert!(large_a.ct_eq_auto_with_threshold(&large_b, 64));
//! // Force hash path for all sizes (threshold 0)
//! assert!(large_a.ct_eq_auto_with_threshold(&large_b, 0));
//!
//! // Direct hash path (uniform probabilistic behavior):
//! assert!(large_a.ct_eq_hash(&large_b));
//! assert!(!large_a.ct_eq_hash(&large_c));
//! ```
#[cfg(feature = "ct-eq-hash")]
/// Default crossover threshold for [`ConstantTimeEqExt::ct_eq_auto`].
///
/// Inputs ≤ this many bytes use `ct_eq` (deterministic); larger inputs use
/// `ct_eq_hash` (BLAKE3, probabilistic). Validated at ~32 bytes on typical
/// hardware — see [CT_EQ_AUTO.md](../CT_EQ_AUTO.md).
///
/// `ct_eq_auto` uses this value internally. Call `ct_eq_auto_with_threshold`
/// directly only when your benchmarks show a different optimal crossover point.
/// Values above 4096 are capped at 4096.
pub const CT_EQ_AUTO_THRESHOLD: usize = 32;

#[cfg(feature = "ct-eq-hash")]
#[allow(clippy::len_without_is_empty)]
pub trait ConstantTimeEqExt: crate::ConstantTimeEq {
    /// Returns the length of the secret data in bytes.
    ///
    /// # Implementation Notes
    ///
    /// This trait intentionally does **not** provide an `is_empty()` method
    /// (`#[allow(clippy::len_without_is_empty)]`). Adding `is_empty` would shadow the
    /// same method from [`crate::ExposeSecret`], causing ambiguous-method-call errors
    /// in generic contexts. Use `.len() == 0` when an emptiness check is needed.
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

    /// Recommended constant-time equality check using the automatic hybrid strategy.
    ///
    /// Uses [`CT_EQ_AUTO_THRESHOLD`] (32 bytes) as the crossover:
    ///
    /// - Length mismatch → `false` (public metadata, non-constant-time compare)
    /// - Size ≤ threshold → `self.ct_eq(other)` (strict deterministic)
    /// - Size > threshold → `self.ct_eq_hash(other)` (probabilistic, fast)
    ///
    /// This is the idiomatic call for most users. If you need a custom crossover
    /// point based on your own benchmarks, use [`ct_eq_auto_with_threshold`](Self::ct_eq_auto_with_threshold) directly.
    ///
    /// Prefer this method over `ct_eq_hash` for variable/mixed-size secrets unless
    /// you specifically need uniform probabilistic behavior.
    ///
    /// See [CT_EQ_AUTO.md](../CT_EQ_AUTO.md) for benchmarks and threshold tuning guidance.
    fn ct_eq_auto(&self, other: &Self) -> bool {
        self.ct_eq_auto_with_threshold(other, CT_EQ_AUTO_THRESHOLD)
    }

    /// Power-user variant of [`ct_eq_auto`](Self::ct_eq_auto) with an explicit threshold.
    ///
    /// Automatically chooses the best strategy:
    ///
    /// - Length mismatch → `false` (public metadata, non-constant-time compare)
    /// - Size ≤ threshold → `self.ct_eq(other)` (strict deterministic)
    /// - Size > threshold → `self.ct_eq_hash(other)` (probabilistic, fast)
    ///
    /// `threshold_bytes` is capped at 4096 — values above it behave identically to `Some(4096)`.
    /// Pass `0` to force `ct_eq_hash` for all input sizes.
    ///
    /// Prefer [`ct_eq_auto`](Self::ct_eq_auto) in almost all cases. Use this method only when
    /// your benchmarks show a different optimal crossover point for your specific hardware.
    ///
    /// See [CT_EQ_AUTO.md](../CT_EQ_AUTO.md) for benchmarks and threshold tuning guidance.
    fn ct_eq_auto_with_threshold(&self, other: &Self, threshold_bytes: usize) -> bool {
        if self.len() != other.len() {
            return false;
        }
        let thresh = threshold_bytes.min(4096);
        if self.len() <= thresh {
            self.ct_eq(other)
        } else {
            self.ct_eq_hash(other)
        }
    }
}

#[cfg(feature = "ct-eq-hash")]
use crate::ConstantTimeEq;

/// Internal constant-time hash-based equality helper.
///
/// Uses BLAKE3 (keyed with a per-process random key when `rand` is enabled;
/// plain when `rand` is disabled) to compare two byte slices in constant time.
/// Returns `false` immediately on length mismatch (length is public metadata).
///
/// Collision probability: 2⁻²⁵⁶ per comparison.
///
/// # Implementation Notes
///
/// The per-process key is generated once via `OsRng` and stored in a `Lazy<[u8; 32]>`.
/// This resists multi-target precomputation and rainbow-table attacks across many
/// comparisons. Without `rand`, plain BLAKE3 is still cryptographically secure.
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
        // HASH_EQ_KEY is process-lifetime and intentionally not zeroized.
        // An attacker with process memory read access can recover it, enabling
        // offline forgery of ct_eq_hash results. For secrets requiring post-use
        // erasure of all derived material, use ct_eq (deterministic) instead.
        // This is a known, accepted trade-off: the key's purpose is to resist
        // multi-target precomputation across sessions, not single-session forgery.
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
