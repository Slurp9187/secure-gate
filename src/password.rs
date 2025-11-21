// src/password.rs
//
// Provide ergonomic direct accessors for SecurePassword and SecurePasswordBuilder

use secrecy::{ExposeSecret, ExposeSecretMut};

#[cfg(feature = "alloc")]
use alloc::string::String;

/// Zero-overhead inherent methods restoring the pre-0.4 single-call API
/// plus commonly needed byte-slice helpers used by password hashing crates.
impl crate::SecurePassword {
    #[inline(always)]
    pub fn expose_secret(&self) -> &str {
        self.expose().expose_secret()
    }

    #[inline(always)]
    pub fn expose_secret_mut(&mut self) -> &mut str {
        self.expose_mut().expose_secret_mut()
    }

    #[inline(always)]
    pub fn expose_secret_bytes(&self) -> &[u8] {
        self.expose_secret().as_bytes()
    }

    #[cfg(feature = "unsafe-wipe")]
    #[inline(always)]
    pub unsafe fn expose_secret_bytes_mut(&mut self) -> &mut [u8] {
        self.expose_secret_mut().as_bytes_mut()
    }

    #[cfg(not(feature = "unsafe-wipe"))]
    #[inline(always)]
    pub fn expose_secret_bytes_mut(&mut self) -> &mut [u8] {
        panic!("mutable byte access requires the `unsafe-wipe` feature")
    }
}

#[cfg(feature = "alloc")]
impl crate::SecurePasswordBuilder {
    #[inline(always)]
    pub fn expose_secret_mut(&mut self) -> &mut String {
        self.expose_mut().expose_secret_mut()
    }

    #[cfg(feature = "unsafe-wipe")]
    #[inline(always)]
    pub unsafe fn expose_secret_bytes_mut(&mut self) -> &mut [u8] {
        self.expose_secret_mut().as_bytes_mut()
    }

    #[cfg(not(feature = "unsafe-wipe"))]
    #[inline(always)]
    pub fn expose_secret_bytes_mut(&mut self) -> &mut [u8] {
        panic!("mutable byte access requires the `unsafe-wipe` feature")
    }
}
