//! # Secret Exposure Traits
//!
//! This module defines the core traits for polymorphic secret access with controlled mutability.
//! These traits enable writing generic code that works across different secret wrapper types
//! while enforcing security guarantees.
//!
//! ## Key Traits
//!
//! - [`ExposeSecret`]: Read-only access to secret values
//! - [`ExposeSecretMut`]: Mutable access to secret values (full control)
//!
//! ## Security Model
//!
//! - **Full access**: Core wrappers ([`Fixed`], [`Dynamic`]) implement both traits
//! - **Read-only**: Random ([`FixedRandom`], [`DynamicRandom`]) and encoding wrappers
//!   only implement [`ExposeSecret`] to prevent mutation
//! - **Zero-cost**: All implementations use `#[inline(always)]`
//!
//! ## Usage
//!
//! ```
//! use secure_gate::{Fixed, Dynamic, ExposeSecret, ExposeSecretMut};
//!
//! // Full access wrappers
//! let mut secret = Fixed::new(42);
//! *secret.expose_secret_mut() = 100;
//!
//! // Read-only access
//! let value = secret.expose_secret();
//! assert_eq!(*value, 100);
//! ```

use crate::{Dynamic, Fixed};

#[cfg(feature = "rand")]
use crate::random::{DynamicRandom, FixedRandom};

#[cfg(feature = "encoding-hex")]
use crate::encoding::hex::HexString;

#[cfg(feature = "encoding-base64")]
use crate::encoding::base64::Base64String;

#[cfg(feature = "encoding-bech32")]
use crate::encoding::bech32::Bech32String;

/// Read-only access to secret values.
///
/// This trait provides polymorphic access to the inner secret value with read-only guarantees.
/// Types implementing only this trait (like random and encoding wrappers) prevent mutation
/// to maintain security invariants.
///
/// ## Type Safety
///
/// The associated `Inner` type specifies what the secret contains (e.g., `str` for encoding types,
/// `[u8]` for random types).
///
/// ## Security
///
/// - Does not provide mutation capabilities
/// - Enables secure polymorphic operations on secrets
/// - Used by random and encoding wrappers to prevent invalidation
pub trait ExposeSecret {
    /// The inner secret type being exposed.
    ///
    /// This can be a sized type (like `[u8; N]`) or unsized (like `str` or `[u8]`).
    type Inner: ?Sized;

    /// Expose the secret value for read-only access.
    ///
    /// This method provides controlled access to the inner secret. The returned reference
    /// is valid for the lifetime of `self`.
    ///
    /// # Security Note
    ///
    /// Callers should minimize the time they hold references to exposed secrets to reduce
    /// the attack surface for side-channel attacks or accidental logging.
    fn expose_secret(&self) -> &Self::Inner;
}

/// Mutable access to secret values.
///
/// This trait extends [`ExposeSecret`] with mutation capabilities. Only core secret
/// wrappers (like [`Fixed`] and [`Dynamic`]) implement this trait, ensuring that mutable
/// access is explicitly controlled and auditable.
///
/// ## Security
///
/// - Extends read-only access with mutation
/// - Only implemented by trusted core wrapper types
/// - All mutations are explicit and traceable
pub trait ExposeSecretMut: ExposeSecret {
    /// Expose the secret value for mutable access.
    ///
    /// This method provides controlled mutable access to the inner secret. The returned
    /// reference is valid for the lifetime of `self`.
    ///
    /// # Security Note
    ///
    /// Mutations to secrets should be carefully audited. Consider if the change maintains
    /// the secret's security invariants and doesn't compromise cryptographic properties.
    fn expose_secret_mut(&mut self) -> &mut Self::Inner;
}

// ============================================================================
// Core Wrapper Implementations
// ============================================================================

/// Implementation for [`Fixed<T>`] - provides full read/write access.
///
/// [`Fixed<T>`] is a core wrapper that allows both reading and mutation of secrets.
/// This implementation delegates to the wrapper's own methods.
impl<T> ExposeSecret for Fixed<T> {
    type Inner = T;

    #[inline(always)]
    fn expose_secret(&self) -> &T {
        self.expose_secret()
    }
}

/// Implementation for [`Fixed<T>`] - provides mutable access.
///
/// Extends the read-only implementation with mutation capabilities.
impl<T> ExposeSecretMut for Fixed<T> {
    #[inline(always)]
    fn expose_secret_mut(&mut self) -> &mut T {
        self.expose_secret_mut()
    }
}

/// Implementation for [`Dynamic<T>`] - provides full read/write access.
///
/// [`Dynamic<T>`] is a core wrapper that allows both reading and mutation of secrets.
/// This implementation delegates to the wrapper's own methods.
impl<T: ?Sized> ExposeSecret for Dynamic<T> {
    type Inner = T;

    #[inline(always)]
    fn expose_secret(&self) -> &T {
        self.expose_secret()
    }
}

/// Implementation for [`Dynamic<T>`] - provides mutable access.
///
/// Extends the read-only implementation with mutation capabilities.
impl<T: ?Sized> ExposeSecretMut for Dynamic<T> {
    #[inline(always)]
    fn expose_secret_mut(&mut self) -> &mut T {
        self.expose_secret_mut()
    }
}

// ============================================================================
// Random Wrapper Implementations (Read-Only Only)
// ============================================================================

/// Implementation for [`FixedRandom<N>`] - read-only access.
///
/// Random wrappers only provide read-only access to prevent invalidation of the
/// randomly generated secret. The `Inner` type is `[u8]` (slice) for compatibility
/// with `SecureRandom` trait bounds.
#[cfg(feature = "rand")]
impl<const N: usize> ExposeSecret for FixedRandom<N> {
    type Inner = [u8];

    #[inline(always)]
    fn expose_secret(&self) -> &[u8] {
        self.expose_secret()
    }
}

/// Implementation for [`DynamicRandom`] - read-only access.
///
/// Random wrappers only provide read-only access to prevent invalidation of the
/// randomly generated secret. The `Inner` type is `[u8]` (slice) for compatibility
/// with `SecureRandom` trait bounds.
#[cfg(feature = "rand")]
impl ExposeSecret for DynamicRandom {
    type Inner = [u8];

    #[inline(always)]
    fn expose_secret(&self) -> &[u8] {
        self.expose_secret()
    }
}

// ============================================================================
// Encoding Wrapper Implementations (Read-Only Only)
// ============================================================================

/// Implementation for [`HexString`] - read-only access.
///
/// Encoding wrappers only provide read-only access to prevent invalidation of
/// validation invariants. The `Inner` type is `str` since encoded strings are
/// always valid UTF-8.
#[cfg(feature = "encoding-hex")]
impl ExposeSecret for HexString {
    type Inner = str;

    #[inline(always)]
    fn expose_secret(&self) -> &str {
        self.expose_secret().0.as_str()
    }
}

/// Implementation for [`Base64String`] - read-only access.
///
/// Encoding wrappers only provide read-only access to prevent invalidation of
/// validation invariants. The `Inner` type is `str` since encoded strings are
/// always valid UTF-8.
#[cfg(feature = "encoding-base64")]
impl ExposeSecret for Base64String {
    type Inner = str;

    #[inline(always)]
    fn expose_secret(&self) -> &str {
        self.expose_secret().0.as_str()
    }
}

/// Implementation for [`Bech32String`] - read-only access.
///
/// Encoding wrappers only provide read-only access to prevent invalidation of
/// validation invariants. The `Inner` type is `str` since encoded strings are
/// always valid UTF-8.
#[cfg(feature = "encoding-bech32")]
impl ExposeSecret for Bech32String {
    type Inner = str;

    #[inline(always)]
    fn expose_secret(&self) -> &str {
        self.expose_secret().0.as_str()
    }
}
