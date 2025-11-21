// src/password.rs
//
// Provide ergonomic direct accessors for SecurePassword and SecurePasswordBuilder

#[cfg(feature = "zeroize")]
use secrecy::{ExposeSecret, ExposeSecretMut};

impl crate::SecurePassword {
    #[inline(always)]
    pub fn expose_secret(&self) -> &str {
        #[cfg(feature = "zeroize")]
        {
            self.expose().expose_secret()
        }
        #[cfg(not(feature = "zeroize"))]
        {
            self.expose().as_str()
        }
    }

    #[inline(always)]
    pub fn expose_secret_mut(&mut self) -> &mut str {
        #[cfg(feature = "zeroize")]
        {
            self.expose_mut().expose_secret_mut()
        }
        #[cfg(not(feature = "zeroize"))]
        {
            self.expose_mut().as_mut_str()
        }
    }

    #[inline(always)]
    pub fn expose_secret_bytes(&self) -> &[u8] {
        self.expose_secret().as_bytes()
    }

    /// # Safety
    ///
    /// Returns a raw mutable byte slice of the secret password.
    /// The caller **must not** create invalid UTF-8 data in the underlying string.
    #[cfg(feature = "unsafe-wipe")]
    #[inline(always)]
    pub unsafe fn expose_secret_bytes_mut(&mut self) -> &mut [u8] {
        #[cfg(feature = "zeroize")]
        {
            self.expose_secret_mut().as_bytes_mut()
        }
        #[cfg(not(feature = "zeroize"))]
        {
            // SAFETY: `String::as_mut_vec` is unsafe, but we only expose it when the
            // user has explicitly enabled the `unsafe-wipe` feature.
            self.expose_mut().as_mut_vec().as_mut_slice()
        }
    }

    #[cfg(not(feature = "unsafe-wipe"))]
    #[inline(always)]
    pub fn expose_secret_bytes_mut(&mut self) -> &mut [u8] {
        panic!("`expose_secret_bytes_mut` requires the `unsafe-wipe` feature")
    }
}

#[cfg(feature = "alloc")]
impl crate::SecurePasswordBuilder {
    #[cfg(feature = "zeroize")]
    #[inline(always)]
    pub fn expose_secret_mut(&mut self) -> &mut alloc::string::String {
        self.expose_mut().expose_secret_mut()
    }

    /// # Safety
    ///
    /// Returns a raw mutable byte slice of the secret password being built.
    /// The caller **must not** create invalid UTF-8 data.
    #[cfg(all(feature = "zeroize", feature = "unsafe-wipe"))]
    #[inline(always)]
    pub unsafe fn expose_secret_bytes_mut(&mut self) -> &mut [u8] {
        self.expose_secret_mut().as_bytes_mut()
    }

    #[cfg(not(all(feature = "zeroize", feature = "unsafe-wipe")))]
    #[inline(always)]
    pub fn expose_secret_bytes_mut(&mut self) -> &mut [u8] {
        panic!("`expose_secret_bytes_mut` requires the `unsafe-wipe` feature")
    }

    #[cfg(not(feature = "zeroize"))]
    #[inline(always)]
    pub fn expose_secret_mut(&mut self) -> &mut alloc::string::String {
        self.expose_mut()
    }
}
