// ==========================================================================
// src/lib.rs
// ==========================================================================

// Allow unsafe_code when encoding or zeroize is enabled (encoding needs it for hex validation)
#![cfg_attr(
    not(any(
        feature = "zeroize",
        any(feature = "encoding-hex", feature = "encoding-base64")
    )),
    forbid(unsafe_code)
)]
#![doc = include_str!("../README.md")]

extern crate alloc;

// ── Core secret types (always available) ─────────────────────────────
mod dynamic;
mod fixed;

pub use dynamic::Dynamic;
pub use fixed::Fixed;

// ── Cloneable secret marker (opt-in for safe duplication) ────────────
#[cfg(feature = "zeroize")]
pub use cloneable::CloneableSecretMarker;
#[cfg(feature = "zeroize")]
pub mod cloneable;
#[cfg(feature = "zeroize")]
pub use cloneable::{CloneableArray, CloneableString, CloneableVec};

// ── Macros (always available) ────────────────────────────────────────
mod macros;

// ── Feature-gated modules (zero compile-time cost when disabled) ─────
#[cfg(feature = "rand")]
pub mod random;

#[cfg(feature = "ct-eq")]
pub mod eq;

pub mod encoding;

// ── Feature-gated re-exports ─────────────────────────────────────────
#[cfg(feature = "rand")]
pub use random::{DynamicRng, FixedRng};

#[cfg(feature = "encoding-hex")]
pub use encoding::hex::HexString;

#[cfg(feature = "encoding-base64")]
pub use encoding::base64::Base64String;

#[cfg(feature = "encoding-bech32")]
pub use encoding::bech32::Bech32String;

#[cfg(any(feature = "encoding-hex", feature = "encoding-base64"))]
pub use encoding::SecureEncodingExt;

pub use fixed::FromSliceError;
