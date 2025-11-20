// src/traits.rs

#[cfg(feature = "zeroize")]
use crate::secure_gate::SecureGate;
#[cfg(feature = "zeroize")]
use secrecy::{ExposeSecret, ExposeSecretMut};

/// For SecurePassword: SecureGate<SecretBox<str>>
#[cfg(feature = "zeroize")]
impl ExposeSecret<str> for SecureGate<secrecy::SecretBox<str>> {
    #[inline(always)]
    fn expose_secret(&self) -> &str {
        self.expose().expose_secret()
    }
}

#[cfg(feature = "zeroize")]
impl ExposeSecretMut<str> for SecureGate<secrecy::SecretBox<str>> {
    #[inline(always)]
    fn expose_secret_mut(&mut self) -> &mut str {
        self.expose_mut().expose_secret_mut()
    }
}

/// For SecurePasswordBuilder: SecureGate<SecretBox<String>>
#[cfg(feature = "zeroize")]
impl ExposeSecret<alloc::string::String> for SecureGate<secrecy::SecretBox<alloc::string::String>> {
    #[inline(always)]
    fn expose_secret(&self) -> &alloc::string::String {
        self.expose().expose_secret()
    }
}

#[cfg(feature = "zeroize")]
impl ExposeSecretMut<alloc::string::String>
    for SecureGate<secrecy::SecretBox<alloc::string::String>>
{
    #[inline(always)]
    fn expose_secret_mut(&mut self) -> &mut alloc::string::String {
        self.expose_mut().expose_secret_mut()
    }
}
