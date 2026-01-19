use crate::Dynamic;
use rand::rand_core::OsError;
use rand::rngs::OsRng;
use rand::TryRngCore;

/// Heap-allocated cryptographically secure random bytes with encoding methods.
///
/// This is a newtype over `Dynamic<Vec<u8>>` for semantic clarity.
/// Like `FixedRandom`, guarantees freshness via RNG construction.
///
/// Requires the `rand` feature.
///
/// Supports direct encoding to Hex, Base64, Bech32, and Bech32m via convenience methods.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "rand")]
/// # {
/// use secure_gate::{random::DynamicRandom, ExposeSecret};
/// let random = DynamicRandom::generate(64);
/// assert_eq!(random.len(), 64);
/// # }
/// ```
pub struct DynamicRandom(pub(crate) Dynamic<Vec<u8>>);

impl DynamicRandom {
    /// Generate fresh random bytes of the specified length.
    ///
    /// Panics if the RNG fails.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "rand")]
    /// # {
    /// use secure_gate::random::DynamicRandom;
    /// let random = DynamicRandom::generate(128);
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
    /// use secure_gate::random::DynamicRandom;
    /// let random: Result<DynamicRandom, rand::rand_core::OsError> = DynamicRandom::try_generate(64);
    /// assert!(random.is_ok());
    /// # }
    /// ```
    pub fn try_generate(len: usize) -> Result<Self, OsError> {
        let mut bytes = vec![0u8; len];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map(|_| Self(Dynamic::from(bytes)))
    }

    /// Consume and return the inner `Dynamic<Vec<u8>>`.
    #[inline(always)]
    pub fn into_inner(self) -> Dynamic<Vec<u8>> {
        self.0
    }
}

/// Debug implementation (always redacted).
impl core::fmt::Debug for DynamicRandom {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl From<DynamicRandom> for Dynamic<Vec<u8>> {
    /// Convert a `DynamicRandom` to `Dynamic`, transferring ownership.
    ///
    /// This preserves all security guarantees. The `DynamicRandom` type
    /// ensures the value came from secure RNG, and this conversion
    /// transfers that value to `Dynamic` without exposing bytes.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "rand")]
    /// # {
    /// use secure_gate::{Dynamic, random::DynamicRandom};
    /// let random: Dynamic<Vec<u8>> = DynamicRandom::generate(64).into();
    /// # }
    /// ```
    #[inline(always)]
    fn from(rng: DynamicRandom) -> Self {
        rng.into_inner()
    }
}
