//! Scoped access shared by plain and sealed secrets. Requires the `sealed` feature.
//!
//! [`RevealScoped`] is the part of [`RevealSecret`] that a sealed type can also offer:
//! access through a closure, with no reference that outlives it. It is implemented for
//! every [`RevealSecret`] type by a blanket impl, and directly for
//! [`SealedFixed`](crate::SealedFixed) and [`SealedDynamic`](crate::SealedDynamic), so
//! generic code that only reads through a closure can take either.
//!
//! ```rust
//! use secure_gate::scoped::RevealScoped;
//! use secure_gate::{Fixed, Prekey, SealedFixed};
//!
//! fn first_byte<S: RevealScoped<Inner = [u8; 32]>>(s: &S) -> u8 {
//!     s.with_secret(|b| b[0])
//! }
//!
//! let prekey = Prekey::new();
//! assert_eq!(first_byte(&Fixed::new([1u8; 32])), 1);
//! assert_eq!(first_byte(&SealedFixed::seal(Fixed::new([2u8; 32]), &prekey)), 2);
//! ```
//!
//! # Why this trait is not at the crate root
//!
//! Its method is named `with_secret`, like [`RevealSecret`]'s. If both were re-exported
//! from the root, `use secure_gate::*;` would put both in scope and every
//! `fixed.with_secret(..)` would fail with `E0034` (multiple applicable items). Import it
//! by path, as above. Sealed types also have `with_secret` as an inherent method, so
//! calling it on them needs no import at all.
//!
//! The same collision happens in any scope that imports both traits by name. There, call
//! the one you mean with a qualified path: `RevealScoped::with_secret(&s, |b| ..)`.

use crate::RevealSecret;

/// Read access through a closure only. See the [module docs](self).
pub trait RevealScoped {
    /// The secret's type as the closure sees it.
    type Inner: ?Sized;

    /// Calls `f` with a reference to the secret that cannot outlive the call.
    fn with_secret<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&Self::Inner) -> R;
}

impl<T: RevealSecret + ?Sized> RevealScoped for T {
    type Inner = <T as RevealSecret>::Inner;

    #[inline(always)]
    fn with_secret<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&Self::Inner) -> R,
    {
        RevealSecret::with_secret(self, f)
    }
}
