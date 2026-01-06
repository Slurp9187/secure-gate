// secure-gate/src/random/fixed_rng.rs
use crate::Fixed;
use rand::rand_core::OsError;
use rand::rngs::OsRng;
use rand::TryRngCore;

/// Fixed-length cryptographically secure random value with encoding methods.
///
/// This is a newtype over `Fixed<[u8; N]>` that enforces construction only via secure RNG.
/// Guarantees freshness — cannot be created from arbitrary bytes.
///
/// Requires the "rand" feature.
///
/// Supports direct encoding to Hex, Base64, Bech32, and Bech32m via convenience methods.
///
/// # Examples
///
/// Basic usage:
/// ```
/// # #[cfg(feature = "rand")]
/// # {
/// use secure_gate::random::FixedRng;
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
    /// use secure_gate::random::FixedRng;
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

    /// Try to generate fresh random bytes using the OS RNG.
    ///
    /// Returns an error if the RNG fails.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "rand")]
    /// # {
    /// use secure_gate::random::FixedRng;
    /// let random: Result<FixedRng<32>, rand::rand_core::OsError> = FixedRng::try_generate();
    /// assert!(random.is_ok());
    /// # }
    /// ```
    pub fn try_generate() -> Result<Self, OsError> {
        let mut bytes = [0u8; N];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map(|_| Self(Fixed::new(bytes)))
    }

    /// Expose the random bytes for read-only access.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "rand")]
    /// # {
    /// use secure_gate::random::FixedRng;
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
    /// use secure_gate::{Fixed, random::FixedRng};
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
    /// use secure_gate::{Fixed, random::FixedRng};
    /// let key: Fixed<[u8; 32]> = FixedRng::<32>::generate().into();
    /// # }
    /// ```
    #[inline(always)]
    fn from(rng: FixedRng<N>) -> Self {
        rng.into_inner()
    }
}
