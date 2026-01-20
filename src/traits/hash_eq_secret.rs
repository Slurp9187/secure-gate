//! Sealed marker trait for on-demand hash-based equality.

#[cfg(feature = "hash-eq")]
pub trait Sealed {}

/// Sealed marker trait for on-demand hash-based equality.
#[cfg(feature = "hash-eq")]
pub trait HashEqSecret: Sealed {
    fn hash_digest(&self) -> [u8; 32];
}
