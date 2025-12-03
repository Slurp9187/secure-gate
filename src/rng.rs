// src/rng.rs
//! Cryptographically secure random generation for fixed-size secrets.
//!
//! This module provides the [`SecureRandomExt`] trait, which adds a `.new()`
//! method to all `RandomBytes<N>` types (including those created via [`random_alias!`]).
//!
//! The implementation uses a **thread-local** `rand::rngs::OsRng` that is lazily
//! initialized on first use. It is:
//! - Zero heap allocation after first use
//! - Fully `no_std`-compatible
//! - Panics on RNG failure (standard practice in high-assurance crypto code)
//!
//! Requires the `rand` feature.
//!
//! # Examples
//!
//! ```
/// use secure_gate::{random_alias, SecureRandomExt};
///
/// random_alias!(Aes256Key, 32);
/// random_alias!(XChaCha20Nonce, 24);
///
/// let key: Aes256Key = Aes256Key::new();        // cryptographically secure
/// let nonce: XChaCha20Nonce = XChaCha20Nonce::new();
///
/// assert_eq!(key.len(), 32);
/// assert_eq!(nonce.len(), 24);
/// ```
use rand::{rngs::OsRng, TryRngCore};
use std::cell::RefCell;

thread_local! {
    static OS_RNG: RefCell<OsRng> = const { RefCell::new(OsRng) };
}

/// Extension trait for generating cryptographically secure random values.
///
/// Implemented for all `RandomBytes<N>` types (including `random_alias!` types).
///
/// # Panics
///
/// Panics if the OS RNG fails to fill the buffer. This is exceedingly rare and
/// considered fatal in cryptographic contexts.
pub trait SecureRandomExt {
    /// Generates a new random instance using the operating system's
    /// cryptographically secure PRNG.
    fn new() -> Self
    where
        Self: Sized;

    /// **Deprecated** — use `new()` instead.
    #[deprecated(
        since = "0.6.0",
        note = "use `new()` instead — idiomatic and avoids self-named constructor"
    )]
    fn random_bytes() -> Self
    where
        Self: Sized,
    {
        Self::new()
    }

    /// **Deprecated** — use `new()` instead.
    #[deprecated(since = "0.6.0", note = "use `new()` instead — clearer and idiomatic")]
    fn random() -> Self
    where
        Self: Sized,
    {
        Self::new()
    }

    /// Generate random bytes and return as RandomHex.
    #[cfg(all(feature = "rand", feature = "conversions"))]
    fn random_hex() -> crate::RandomHex
    where
        Self: Sized;
}

/// Fresh cryptographically-secure random bytes of exactly `N` length.
///
/// Construction is only possible through the RNG — you cannot build one manually.
/// This gives compile-time assurance that the value is truly random.
#[derive(Clone, Copy)]
pub struct RandomBytes<const N: usize>(crate::Fixed<[u8; N]>);

impl<const N: usize> RandomBytes<N> {
    /// Explicit access — required by secure-gate’s safety rules.
    #[inline(always)]
    pub fn expose_secret(&self) -> &[u8; N] {
        self.0.expose_secret()
    }

    /// Mutable access when you need to overwrite (rare, but useful for some protocols).
    #[inline(always)]
    pub fn expose_secret_mut(&mut self) -> &mut [u8; N] {
        self.0.expose_secret_mut()
    }
}

// Deref so you keep all the nice Fixed methods (len, as_slice, etc.)
impl<const N: usize> core::ops::Deref for RandomBytes<N> {
    type Target = crate::Fixed<[u8; N]>;
    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// Optional: Debug redaction
impl<const N: usize> core::fmt::Debug for RandomBytes<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED_RANDOM]")
    }
}

// Impl the trait on the newtype
impl<const N: usize> SecureRandomExt for RandomBytes<N> {
    #[inline(always)]
    fn new() -> Self
    where
        Self: Sized,
    {
        let mut bytes = [0u8; N];
        OS_RNG.with(|rng| {
            rng.borrow_mut()
                .try_fill_bytes(&mut bytes)
                .expect("OsRng failed — this should never happen");
        });
        RandomBytes(crate::Fixed::new(bytes))
    }

    #[cfg(all(feature = "rand", feature = "conversions"))]
    #[inline(always)]
    fn random_hex() -> crate::RandomHex
    where
        Self: Sized,
    {
        use crate::conversions::SecureConversionsExt; // Import for to_hex
        let secret = Self::new();
        let hex_str = secret.expose_secret().to_hex();
        let hex = crate::conversions::HexString::new(hex_str).expect("Generated hex is valid");
        crate::conversions::RandomHex(hex)
    }
}
