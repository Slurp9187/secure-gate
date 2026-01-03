// ==========================================================================
// src/rng.rs
// ==========================================================================

use crate::{Dynamic, Fixed};
use rand::rngs::OsRng;
use rand::RngCore;

/// Fixed-length cryptographically secure random value.
///
/// This is a newtype over `Fixed<[u8; N]>` that enforces construction only via secure RNG.
/// Guarantees freshness — cannot be created from arbitrary bytes.
///
/// Requires the "rand" feature.
///
/// # Examples
///
/// Basic usage:
/// ```
/// # #[cfg(feature = "rand")]
/// # {
/// use secure_gate::rng::FixedRng;
/// let random: FixedRng<32> = FixedRng::generate();
/// assert_eq!(random.len(), 32);
/// # }
/// ```
///
/// With alias:
/// ```
/// # #[cfg(feature = "rand")]
/// # {
/// use secure_gate::fixed_alias_rng;
/// fixed_alias_rng!(Nonce, 24);
/// let nonce = Nonce::generate();
/// # }
/// ```
pub struct FixedRng<const N: usize>(Fixed<[u8; N]>);

impl<const N: usize> FixedRng<N> {
    /// Generate fresh random bytes using the OS RNG.
    ///
    /// Uses `rand::rngs::OsRng` directly for maximum throughput.
    /// Panics if the RNG fails (rare, but correct for crypto code).
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "rand")]
    /// # {
    /// use secure_gate::rng::FixedRng;
    /// let random = FixedRng::<16>::generate();
    /// assert!(!random.is_empty());
    /// # }
    /// ```
    pub fn generate() -> Self {
        let mut bytes = [0u8; N];
        OsRng
            .try_fill_bytes(&mut bytes)
            .expect("OsRng failed — this should never happen on supported platforms");
        Self(Fixed::new(bytes))
    }

    /// Expose the random bytes for read-only access.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "rand")]
    /// # {
    /// use secure_gate::rng::FixedRng;
    /// let random = FixedRng::<4>::generate();
    /// let bytes = random.expose_secret();
    /// # }
    /// ```
    #[inline(always)]
    pub fn expose_secret(&self) -> &[u8; N] {
        self.0.expose_secret()
    }

    /// Returns the fixed length in bytes.
    #[inline(always)]
    pub const fn len(&self) -> usize {
        N
    }

    /// Returns `true` if the length is zero.
    #[inline(always)]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    /// Consume the wrapper and return the inner `Fixed<[u8; N]>`.
    ///
    /// This transfers ownership without exposing the secret bytes.
    /// The returned `Fixed` retains all security guarantees (zeroize, etc.).
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "rand")]
    /// # {
    /// use secure_gate::{Fixed, rng::FixedRng};
    /// let random = FixedRng::<32>::generate();
    /// let fixed: Fixed<[u8; 32]> = random.into_inner();
    /// // Can now use fixed.expose_secret() as needed
    /// # }
    /// ```
    #[inline(always)]
    pub fn into_inner(self) -> Fixed<[u8; N]> {
        self.0
    }
}

impl<const N: usize> core::fmt::Debug for FixedRng<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<const N: usize> From<FixedRng<N>> for Fixed<[u8; N]> {
    /// Convert a `FixedRng` to `Fixed`, transferring ownership.
    ///
    /// This preserves all security guarantees. The `FixedRng` type
    /// ensures the value came from secure RNG, and this conversion
    /// transfers that value to `Fixed` without exposing bytes.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "rand")]
    /// # {
    /// use secure_gate::{Fixed, rng::FixedRng};
    /// let key: Fixed<[u8; 32]> = FixedRng::<32>::generate().into();
    /// # }
    /// ```
    #[inline(always)]
    fn from(rng: FixedRng<N>) -> Self {
        rng.into_inner()
    }
}

/// Heap-allocated cryptographically secure random bytes.
///
/// This is a newtype over `Dynamic<Vec<u8>>` for semantic clarity.
/// Like `FixedRng`, guarantees freshness via RNG construction.
///
/// Requires the "rand" feature.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "rand")]
/// # {
/// use secure_gate::rng::DynamicRng;
/// let random = DynamicRng::generate(64);
/// assert_eq!(random.len(), 64);
/// # }
/// ```
pub struct DynamicRng(Dynamic<Vec<u8>>);

impl DynamicRng {
    /// Generate fresh random bytes of the specified length.
    ///
    /// Panics if the RNG fails.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "rand")]
    /// # {
    /// use secure_gate::rng::DynamicRng;
    /// let random = DynamicRng::generate(128);
    /// # }
    /// ```
    pub fn generate(len: usize) -> Self {
        let mut bytes = vec![0u8; len];
        OsRng
            .try_fill_bytes(&mut bytes)
            .expect("OsRng failed — this should never happen on supported platforms");
        Self(Dynamic::from(bytes))
    }

    /// Expose the random bytes for read-only access.
    #[inline(always)]
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }

    /// Returns the length in bytes.
    #[inline(always)]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if empty.
    #[inline(always)]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consume and return the inner `Dynamic<Vec<u8>>`.
    #[inline(always)]
    pub fn into_inner(self) -> Dynamic<Vec<u8>> {
        self.0
    }
}

impl core::fmt::Debug for DynamicRng {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl From<DynamicRng> for Dynamic<Vec<u8>> {
    /// Convert a `DynamicRng` to `Dynamic`, transferring ownership.
    ///
    /// This preserves all security guarantees. The `DynamicRng` type
    /// ensures the value came from secure RNG, and this conversion
    /// transfers that value to `Dynamic` without exposing bytes.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "rand")]
    /// # {
    /// use secure_gate::{Dynamic, rng::DynamicRng};
    /// let random: Dynamic<Vec<u8>> = DynamicRng::generate(64).into();
    /// # }
    /// ```
    #[inline(always)]
    fn from(rng: DynamicRng) -> Self {
        rng.into_inner()
    }
}
