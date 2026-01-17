//! Cloneable secret primitives for handling sensitive data that can be safely duplicated.
//!
//! This module provides types that wrap sensitive data (arrays, vectors, and strings)
//! in a way that allows controlled cloning while ensuring the data is properly zeroized
//! when dropped. These types are only available when the "zeroize" feature is enabled.
//!
//! The types in this module implement the [`CloneSafe`] trait (from the `traits` module), which ensures
//! that only types safe for secret duplication are used. This prevents accidental leaks
//! of sensitive data through unsafe cloning operations.
#[cfg(feature = "zeroize")]
pub mod array;

#[cfg(feature = "zeroize")]
pub mod string;
#[cfg(feature = "zeroize")]
pub mod vec;

#[cfg(feature = "zeroize")]
pub use array::CloneableArray;

#[cfg(feature = "zeroize")]
pub use string::CloneableString;
#[cfg(feature = "zeroize")]
pub use vec::CloneableVec;
