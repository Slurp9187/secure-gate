#[cfg(feature = "rand")]
use super::{ExposeSecretExt, SecureMetadataExt, SecureRandom};

/// Extension trait for ergonomic access to secure random values.
///
/// Since [`SecureRandom`] combines [`ExposeSecret`] and [`SecureMetadata`],
/// this ext trait brings in their extension methods for concrete usage.
///
/// Import this (along with the other exts) to use `.expose_secret()`, `.len()`,
/// and `.is_empty()` on random wrappers like [`FixedRandom`] or [`DynamicRandom`].
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "rand")]
/// # {
/// use secure_gate::{random::FixedRandom, SecureRandomExt};
///
/// let random = FixedRandom::<32>::generate();
/// assert_eq!(random.len(), 32);
/// let bytes = random.expose_secret();
/// # }
/// ```
#[cfg(feature = "rand")]
pub trait SecureRandomExt: SecureRandom + ExposeSecretExt + SecureMetadataExt {}

// Blanket impl for all types satisfying SecureRandom (automatically gets the supers' exts)
#[cfg(feature = "rand")]
impl<T: SecureRandom + ?Sized> SecureRandomExt for T {}
