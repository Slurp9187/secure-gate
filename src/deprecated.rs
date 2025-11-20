// src/deprecated.rs
//
// Legacy public API for secure-gate 0.3.x – re-exports everything so old code keeps compiling

#![allow(deprecated)]

// Old unified name – users wrote `Secure<T>`
#[deprecated(since = "0.4.0", note = "use SecureGate<T> instead")]
pub type Secure<T: zeroize::Zeroize> = crate::secure_gate::SecureGate<T>;

// Old heap wrapper name
#[deprecated(since = "0.4.0", note = "use SecureGate<T> instead")]
pub type HeapSecure<T: zeroize::Zeroize> = crate::secure_gate::SecureGate<T>;

// Old constructor function
#[deprecated(
    since = "0.4.0",
    note = "use the secure! macro or SecureGate::new instead"
)]
pub fn secure_new<T: zeroize::Zeroize>(value: T) -> crate::secure_gate::SecureGate<T> {
    crate::secure_gate::SecureGate::new(value)
}

// All old aliases – keep them alive
pub use crate::aliases::{
    SecureBytes, SecureIv, SecureKey32, SecureKey64, SecureNonce12, SecureNonce16, SecureNonce24,
    SecurePassword, SecurePasswordBuilder, SecureSalt, SecureStr,
};
