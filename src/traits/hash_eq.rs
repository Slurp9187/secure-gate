//! Internal hash-based equality support (gated behind `hash-eq`).
//!
//! This module defines a sealed trait that allows all secure-gate wrappers
//! to share the same `PartialEq` / `Eq` / `Hash` implementations without
//! duplication or macros.
//!
//! The trait provides safe access to the precomputed BLAKE3-256 digest.
//! Only secure-gate wrapper types may implement it (enforced by sealing).

#[cfg(feature = "hash-eq")]
use core::hash::Hash;
#[cfg(feature = "hash-eq")]
use subtle::ConstantTimeEq;

#[cfg(feature = "hash-eq")]
/// Sealed trait for wrappers that support hash-based equality.
///
/// Provides read access to the fixed-size BLAKE3 digest.
/// Sealed so only crate-internal types can implement it.
pub trait HashEqSecret: sealed::Sealed {
    /// Borrow the precomputed BLAKE3-256 digest.
    fn eq_hash(&self) -> &[u8; 32];
}

// Specific implementations for each wrapper type

/// Sealing module — prevents external crates from implementing the trait.
#[cfg(feature = "hash-eq")]
mod sealed {
    pub trait Sealed {}
}

// --------------------------------------------------------------------
// Per-wrapper impls go here (or in each wrapper's file — your choice)
// --------------------------------------------------------------------

// Fixed wrappers
#[cfg(feature = "hash-eq")]
use crate::Fixed;
#[cfg(feature = "hash-eq")]
impl<T> sealed::Sealed for Fixed<T> {}
#[cfg(feature = "hash-eq")]
impl<T> HashEqSecret for Fixed<T> {
    #[inline(always)]
    fn eq_hash(&self) -> &[u8; 32] {
        &self.eq_hash
    }
}
#[cfg(feature = "hash-eq")]
impl<T> PartialEq for Fixed<T> {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        self.eq_hash().ct_eq(other.eq_hash()).into()
    }
}
#[cfg(feature = "hash-eq")]
impl<T> Eq for Fixed<T> {}
#[cfg(feature = "hash-eq")]
impl<T> Hash for Fixed<T> {
    #[inline(always)]
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        state.write(self.eq_hash());
    }
}

// Dynamic wrappers
#[cfg(feature = "hash-eq")]
use crate::Dynamic;
#[cfg(feature = "hash-eq")]
impl<T: ?Sized> sealed::Sealed for Dynamic<T> {}
#[cfg(feature = "hash-eq")]
impl<T: ?Sized> HashEqSecret for Dynamic<T> {
    #[inline(always)]
    fn eq_hash(&self) -> &[u8; 32] {
        &self.eq_hash
    }
}
#[cfg(feature = "hash-eq")]
impl<T: ?Sized> PartialEq for Dynamic<T> {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        self.eq_hash().ct_eq(other.eq_hash()).into()
    }
}
#[cfg(feature = "hash-eq")]
impl<T: ?Sized> Eq for Dynamic<T> {}
#[cfg(feature = "hash-eq")]
impl<T: ?Sized> Hash for Dynamic<T> {
    #[inline(always)]
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        state.write(self.eq_hash());
    }
}

// Cloneable wrappers (covered by Fixed/Dynamic impls, no need for separate)

// Encoding wrappers
#[cfg(all(feature = "hash-eq", feature = "encoding-hex"))]
use crate::HexString;
#[cfg(all(feature = "hash-eq", feature = "encoding-hex"))]
impl sealed::Sealed for HexString {}
#[cfg(all(feature = "hash-eq", feature = "encoding-hex"))]
impl HashEqSecret for HexString {
    #[inline(always)]
    fn eq_hash(&self) -> &[u8; 32] {
        &self.0.eq_hash
    }
}
#[cfg(all(feature = "hash-eq", feature = "encoding-hex"))]
impl PartialEq for HexString {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        self.eq_hash().ct_eq(other.eq_hash()).into()
    }
}
#[cfg(all(feature = "hash-eq", feature = "encoding-hex"))]
impl Eq for HexString {}
#[cfg(all(feature = "hash-eq", feature = "encoding-hex"))]
impl Hash for HexString {
    #[inline(always)]
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        state.write(self.eq_hash());
    }
}

#[cfg(all(feature = "hash-eq", feature = "encoding-base64"))]
use crate::Base64String;
#[cfg(all(feature = "hash-eq", feature = "encoding-base64"))]
impl sealed::Sealed for Base64String {}
#[cfg(all(feature = "hash-eq", feature = "encoding-base64"))]
impl HashEqSecret for Base64String {
    #[inline(always)]
    fn eq_hash(&self) -> &[u8; 32] {
        &self.0.eq_hash
    }
}
#[cfg(all(feature = "hash-eq", feature = "encoding-base64"))]
impl PartialEq for Base64String {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        self.eq_hash().ct_eq(other.eq_hash()).into()
    }
}
#[cfg(all(feature = "hash-eq", feature = "encoding-base64"))]
impl Eq for Base64String {}
#[cfg(all(feature = "hash-eq", feature = "encoding-base64"))]
impl Hash for Base64String {
    #[inline(always)]
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        state.write(self.eq_hash());
    }
}

#[cfg(all(feature = "hash-eq", feature = "encoding-bech32"))]
use crate::Bech32String;
#[cfg(all(feature = "hash-eq", feature = "encoding-bech32"))]
impl sealed::Sealed for Bech32String {}
#[cfg(all(feature = "hash-eq", feature = "encoding-bech32"))]
impl HashEqSecret for Bech32String {
    #[inline(always)]
    fn eq_hash(&self) -> &[u8; 32] {
        &self.inner.eq_hash
    }
}
#[cfg(all(feature = "hash-eq", feature = "encoding-bech32"))]
impl PartialEq for Bech32String {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        if self.variant != other.variant {
            return false;
        }
        self.eq_hash().ct_eq(other.eq_hash()).into()
    }
}
#[cfg(all(feature = "hash-eq", feature = "encoding-bech32"))]
impl Eq for Bech32String {}
#[cfg(all(feature = "hash-eq", feature = "encoding-bech32"))]
impl Hash for Bech32String {
    #[inline(always)]
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        state.write(self.eq_hash());
    }
}

// Exportable wrappers (covered by Fixed/Dynamic impls, no need for separate)
