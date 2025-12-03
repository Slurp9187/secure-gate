// src/lib.rs
//! # secure-gate: Zero-cost secure wrappers for secrets
//!
//! This crate provides safe, ergonomic wrappers for handling sensitive data in memory
//! with zero runtime overhead. It supports both stack-allocated fixed-size secrets
//! and heap-allocated dynamic secrets, with optional automatic zeroing on drop.
//!
//! Key components:
//! - [`Fixed<T>`]: Stack-allocated for fixed-size secrets (e.g., keys, nonces).
//! - [`Dynamic<T>`]: Heap-allocated for dynamic secrets (e.g., passwords, vectors).
//! - Zeroizing variants: [`FixedZeroizing<T>`] and [`DynamicZeroizing<T>`] for auto-wiping (with `zeroize` feature).
//! - Macros: [`fixed_alias!`], [`dynamic_alias!`], [`secure!`], [`secure_zeroizing!`] for ergonomic usage.
//!
//! # Features
//!
//! - `zeroize`: Enables automatic memory wiping on drop via `zeroize` and `secrecy`.
//! - `rand`: Enables `SecureRandomExt::random()` for generating fixed-size secrets.
//! - `conversions`: **Optional** — adds `.to_hex()`, `.to_hex_upper()`, `.to_base64url()`, and `.ct_eq()` to all fixed-size secrets.
//! - `serde`: Optional serialization support (deserialization disabled for `Dynamic<T>` for security).
//! - Works in `no_std` + `alloc` environments.
//!
//! # Quick Start
//!
//! ```
//! use secure_gate::{fixed_alias, dynamic_alias};
//!
//! #[cfg(feature = "rand")]
//! use secure_gate::{random_alias, SecureRandomExt};
//!
//! fixed_alias!(Aes256Key, 32);
//! dynamic_alias!(Password, String);
//!
//! #[cfg(feature = "rand")]
//! {
//!     random_alias!(RandomAes256Key, 32);
//!     let key = RandomAes256Key::new();
//!     let _ = key.expose_secret();
//! }
//!
//! #[cfg(all(feature = "rand", feature = "conversions"))]
//! {
//!     use secure_gate::{SecureConversionsExt};
//!     random_alias!(RandomAes256Key, 32);
//!     let key = RandomAes256Key::new();
//!     let hex = key.expose_secret().to_hex();
//!     let b64 = key.expose_secret().to_base64url();
//!     assert!(key.expose_secret().ct_eq(key.expose_secret()));
//! }
//!
//! let pw: Password = "hunter2".into();
//! assert_eq!(pw.expose_secret(), "hunter2");
//! ```
//!
//! See individual modules for detailed documentation.

#![cfg_attr(not(feature = "zeroize"), forbid(unsafe_code))]
extern crate alloc;

// Core modules
mod dynamic;
mod fixed;
mod macros;

// Feature-gated modules
#[cfg(feature = "zeroize")]
mod zeroize;

#[cfg(feature = "serde")]
mod serde;

#[cfg(feature = "conversions")]
pub mod conversions;

// Public API
pub use dynamic::Dynamic;
pub use fixed::Fixed;

// Zeroize integration (opt-in)
#[cfg(feature = "zeroize")]
pub use zeroize::{DynamicZeroizing, FixedZeroizing};

// Re-export Zeroizing cleanly — no privacy conflict
#[cfg(feature = "zeroize")]
pub type Zeroizing<T> = ::zeroize::Zeroizing<T>;

#[cfg(feature = "zeroize")]
pub use ::zeroize::{Zeroize, ZeroizeOnDrop};

// RNG integration (opt-in)
#[cfg(feature = "rand")]
pub mod rng;

#[cfg(feature = "rand")]
pub use rng::{RandomBytes, SecureRandomExt};

// Conversions integration (opt-in)
#[cfg(feature = "conversions")]
pub use conversions::SecureConversionsExt;

#[cfg(all(feature = "rand", feature = "conversions"))]
pub use conversions::RandomHex;
