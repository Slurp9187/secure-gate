// src/lib.rs
//
// Crate root with re-exports and trait definitions

#![no_std]
#![cfg_attr(not(feature = "unsafe-wipe"), forbid(unsafe_code))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;

pub mod aliases;
pub mod heap;
pub mod macros;
pub mod stack;

pub use aliases::*;
pub use heap::HeapSecure as Secure;
#[cfg(feature = "stack")]
pub use stack::*;

// Re-export secrecy traits when zeroize is enabled
#[cfg(feature = "zeroize")]
pub use secrecy::{ExposeSecret, ExposeSecretMut};

// Fallback traits when zeroize disabled
#[cfg(not(feature = "zeroize"))]
pub trait ExposeSecret<T: ?Sized> {
    fn expose_secret(&self) -> &T;
}

#[cfg(not(feature = "zeroize"))]
pub trait ExposeSecretMut<T: ?Sized> {
    fn expose_secret_mut(&mut self) -> &mut T;
}
