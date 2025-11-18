// src/traits.rs – ONLY THE TWO CASES WE ACTUALLY USE

#[cfg(feature = "zeroize")]
use crate::heap::HeapSecure;
#[cfg(feature = "zeroize")]
use secrecy::{ExposeSecret, ExposeSecretMut};

/// For SecurePassword: HeapSecure<SecretBox<str>>
#[cfg(feature = "zeroize")]
impl ExposeSecret<str> for HeapSecure<secrecy::SecretBox<str>> {
    #[inline(always)]
    fn expose_secret(&self) -> &str {
        self.expose().expose_secret()
    }
}

#[cfg(feature = "zeroize")]
impl ExposeSecretMut<str> for HeapSecure<secrecy::SecretBox<str>> {
    #[inline(always)]
    fn expose_secret_mut(&mut self) -> &mut str {
        self.expose_mut().expose_secret_mut()
    }
}

/// For SecurePasswordBuilder: HeapSecure<SecretBox<String>>
#[cfg(feature = "zeroize")]
impl ExposeSecret<alloc::string::String> for HeapSecure<secrecy::SecretBox<alloc::string::String>> {
    #[inline(always)]
    fn expose_secret(&self) -> &alloc::string::String {
        self.expose().expose_secret()
    }
}

#[cfg(feature = "zeroize")]
impl ExposeSecretMut<alloc::string::String>
    for HeapSecure<secrecy::SecretBox<alloc::string::String>>
{
    #[inline(always)]
    fn expose_secret_mut(&mut self) -> &mut alloc::string::String {
        self.expose_mut().expose_secret_mut()
    }
}
