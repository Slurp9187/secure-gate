//! Cloneable secret primitives (gated behind "zeroize").
#[cfg(feature = "zeroize")]
pub mod array;
#[cfg(feature = "zeroize")]
pub mod secret_marker;
#[cfg(feature = "zeroize")]
pub mod string;
#[cfg(feature = "zeroize")]
pub mod vec;

#[cfg(feature = "zeroize")]
pub use array::CloneableArray;
#[cfg(feature = "zeroize")]
pub use secret_marker::CloneableSecretMarker;
#[cfg(feature = "zeroize")]
pub use string::CloneableString;
#[cfg(feature = "zeroize")]
pub use vec::CloneableVec;
