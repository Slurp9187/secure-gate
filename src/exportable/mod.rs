//! Exportable secret primitives for opt-in serialization of raw secrets.
//!
//! This module provides types that wrap sensitive data (arrays, vectors, and strings)
//! in a way that allows controlled, opt-in serialization while ensuring the data is
//! properly zeroized when dropped. These types are only available when the
//! "serde-serialize" feature is enabled.
//!
//! The types in this module implement the [`ExportableType`] trait, enabling
//! serialization of raw bytes or text without automatic leakage. This is designed
//! for deliberate export in secure contexts (e.g., config files), not for encoding
//! or random generation—use conversions or macros for those.
//!
//! # Security Warning
//!
//! Using these types serializes raw secrets, which can lead to permanent exposure.
//! Only use in trusted, controlled environments, prefer encoded forms, and audit
//! all usages. Serialization is fully opt-in via the "serde-serialize" feature.

#[cfg(feature = "serde-serialize")]
pub mod array;

#[cfg(feature = "serde-serialize")]
pub mod string;

#[cfg(feature = "serde-serialize")]
pub mod vec;

#[cfg(feature = "serde-serialize")]
pub use array::ExportableArray;

#[cfg(feature = "serde-serialize")]
pub use string::ExportableString;

#[cfg(feature = "serde-serialize")]
pub use vec::ExportableVec;
