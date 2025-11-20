// src/deprecated.rs
//
// Legacy public API for secure-gate 0.3.x – re-exports everything so old code keeps compiling

#![cfg_attr(feature = "zeroize", allow(deprecated))]

#[cfg(feature = "zeroize")]
#[deprecated(since = "0.4.0", note = "use SecureGate<T> instead")]
pub type Secure<T: zeroize::Zeroize> = crate::secure_gate::SecureGate<T>;

#[cfg(feature = "zeroize")]
#[deprecated(since = "0.4.0", note = "use SecureGate<T> instead")]
pub type HeapSecure<T: zeroize::Zeroize> = crate::secure_gate::SecureGate<T>;

#[cfg(feature = "zeroize")]
#[deprecated(
    since = "0.4.0",
    note = "use the secure! macro or SecureGate::new instead"
)]
pub fn secure_new<T: zeroize::Zeroize>(value: T) -> crate::secure_gate::SecureGate<T> {
    crate::secure_gate::SecureGate::new(value)
}

// ---------------------------------------------------------------------
// Active aliases (re-exported for backward compatibility)
// ---------------------------------------------------------------------

#[cfg(feature = "zeroize")]
pub use crate::aliases::{
    SecureBytes, SecureIv16, SecureKey32, SecureKey64, SecureNonce12, SecureNonce128,
    SecureNonce16, SecureNonce24, SecureNonce96, SecurePassword, SecurePasswordBuilder,
    SecureSalt16, SecureStr,
};

// ---------------------------------------------------------------------
// Deprecated aliases (proper warnings)
// ---------------------------------------------------------------------

#[cfg(feature = "zeroize")]
#[deprecated(since = "0.4.1", note = "use SecureIv16 instead")]
pub type SecureIv = SecureIv16;

#[cfg(feature = "zeroize")]
#[deprecated(since = "0.4.1", note = "use SecureSalt16 instead")]
pub type SecureSalt = SecureSalt16;
