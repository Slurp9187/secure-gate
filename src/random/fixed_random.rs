use crate::Fixed;
use rand::rand_core::OsError;
use rand::rngs::OsRng;
use rand::TryRngCore;

/// Fixed-length cryptographically secure random value with encoding methods.
///
/// This is a newtype over `Fixed<[u8; N]>` that enforces construction only via secure RNG.
/// Guarantees freshness — cannot be created from arbitrary bytes.
///
/// Requires the `rand` feature.
///
/// Supports direct encoding to Hex, Base64, Bech32, and Bech32m via convenience methods.
///
/// # Examples
///
/// Basic usage:
/// ```
/// # #[cfg(feature = "rand")]
/// # {
/// use secure_gate::random::FixedRandom;
/// let random: FixedRandom<32> = FixedRandom::generate();
/// assert_eq!(random.len(), 32);
/// # }
/// ```
///
/// With alias:
/// ```
/// # #[cfg(feature = "rand")]
/// # {
/// use secure_gate::fixed_alias_random;
/// fixed_alias_random!(Nonce, 24);
/// let nonce = Nonce::generate();
/// # }
/// ```
pub struct FixedRandom<const N: usize>(pub(crate) Fixed<[u8; N]>);

impl<const N: usize> FixedRandom<N> {
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
    /// use secure_gate::random::FixedRandom;
    /// let random = FixedRandom::<16>::generate();
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
    /// use secure_gate::random::FixedRandom;
    /// let random: Result<FixedRandom<32>, rand::rand_core::OsError> = FixedRandom::try_generate();
    /// assert!(random.is_ok());
    /// # }
    /// ```
    pub fn try_generate() -> Result<Self, OsError> {
        let mut bytes = [0u8; N];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map(|_| Self(Fixed::new(bytes)))
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
    /// use secure_gate::{Fixed, random::FixedRandom};
    /// let random = FixedRandom::<32>::generate();
    /// let fixed: Fixed<[u8; 32]> = random.into_inner();
    /// // Can now use fixed.expose_secret() as needed
    /// # }
    /// ```
    #[inline(always)]
    pub fn into_inner(self) -> Fixed<[u8; N]> {
        self.0
    }
}

/// Debug implementation (always redacted).
impl<const N: usize> core::fmt::Debug for FixedRandom<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<const N: usize> From<FixedRandom<N>> for Fixed<[u8; N]> {
    /// Convert a `FixedRandom` to `Fixed`, transferring ownership.
    ///
    /// This preserves all security guarantees. The `FixedRandom` type
    /// ensures the value came from secure RNG, and this conversion
    /// transfers that value to `Fixed` without exposing bytes.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "rand")]
    /// # {
    /// use secure_gate::{Fixed, random::FixedRandom};
    /// let key: Fixed<[u8; 32]> = FixedRandom::<32>::generate().into();
    /// # }
    /// ```
    #[inline(always)]
    fn from(rng: FixedRandom<N>) -> Self {
        rng.into_inner()
    }
}
