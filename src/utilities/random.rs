#[cfg(feature = "rand")]
use rand::{rngs::OsRng, TryRngCore};

/// Fills a mutable byte slice with cryptographically secure random bytes
/// using the OS-provided RNG.
///
/// # Panics
/// Panics on RNG failure (fail-fast behavior suitable for cryptographic code).
///
/// # Example
/// ```
/// # #[cfg(feature = "rand")]
/// # {
/// use secure_gate::utilities::fill_random_bytes_mut;
/// let mut key = [0u8; 32];
/// fill_random_bytes_mut(&mut key);
/// # }
/// ```
#[cfg(feature = "rand")]
pub fn fill_random_bytes_mut(bytes: &mut [u8]) {
    OsRng
        .try_fill_bytes(bytes)
        .expect("OsRng failure is a program error");
}