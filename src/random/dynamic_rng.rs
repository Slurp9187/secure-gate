// secure-gate/src/random/dynamic_rng.rs
use crate::Dynamic;
use rand::rand_core::OsError;
use rand::rngs::OsRng;
use rand::TryRngCore;

/// Heap-allocated cryptographically secure random bytes with encoding methods.
///
/// This is a newtype over `Dynamic<Vec<u8>>` for semantic clarity.
/// Like `FixedRng`, guarantees freshness via RNG construction.
///
/// Requires the "rand" feature.
///
/// Supports direct encoding to Hex, Base64, Bech32, and Bech32m via convenience methods.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "rand")]
/// # {
/// use secure_gate::random::DynamicRng;
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
    /// use secure_gate::random::DynamicRng;
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

    /// Try to generate fresh random bytes of the specified length.
    ///
    /// Returns an error if the RNG fails.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "rand")]
    /// # {
    /// use secure_gate::random::DynamicRng;
    /// let random: Result<DynamicRng, rand::rand_core::OsError> = DynamicRng::try_generate(64);
    /// assert!(random.is_ok());
    /// # }
    /// ```
    pub fn try_generate(len: usize) -> Result<Self, OsError> {
        let mut bytes = vec![0u8; len];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map(|_| Self(Dynamic::from(bytes)))
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
    /// use secure_gate::{Dynamic, random::DynamicRng};
    /// let random: Dynamic<Vec<u8>> = DynamicRng::generate(64).into();
    /// # }
    /// ```
    #[inline(always)]
    fn from(rng: DynamicRng) -> Self {
        rng.into_inner()
    }
}
