//! The byte shapes a [`Dynamic`](crate::Dynamic) can be built from directly.
//!
//! `Dynamic<Vec<u8>>` and `Dynamic<[u8]>` share one set of constructors (`new_with`,
//! `try_new_with`, `from_random`), decoders (`try_from_hex` and the rest) and encoders
//! (`ToHex` and the rest). Each is written once, generic over [`DynamicBytes`], so the
//! type a caller names picks the shape:
//!
//! ```rust
//! use secure_gate::Dynamic;
//!
//! // A growable buffer, as before.
//! let v: Dynamic<Vec<u8>> = Dynamic::new_with(4, |b| b.copy_from_slice(&[1, 2, 3, 4]));
//! // A boxed slice of exactly 4 bytes, which can never grow.
//! let s: Dynamic<[u8]> = Dynamic::new_with(4, |b| b.copy_from_slice(&[1, 2, 3, 4]));
//! ```
//!
//! **Name the shape.** Both shapes have these methods, so a call that gives the compiler
//! no way to tell which one is meant does not compile (E0282 or E0283). A type on the
//! binding, the field or the turbofish (`Dynamic::<Vec<u8>>::new_with`) settles it.
//!
//! ```rust,compile_fail
//! use secure_gate::Dynamic;
//! let unnamed = Dynamic::new_with(4, |b| b.fill(1)); // Vec<u8> or [u8]?
//! ```
//!
//! The trait is sealed: it is implemented for `Vec<u8>` and `[u8]` and cannot be
//! implemented outside this crate. Outside this crate it has no methods: the buffer
//! operations the crate uses are on a private supertrait, and each takes a token only
//! this crate can build. Neither the token nor the supertrait can be named outside it:
//!
//! ```rust,compile_fail,E0603
//! fn make() -> secure_gate::traits::dynamic_bytes::Token { todo!() }
//! ```
//!
//! ```rust,compile_fail,E0603
//! struct Mine;
//! impl secure_gate::traits::dynamic_bytes::Ops for Mine {}
//! ```

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;
use zeroize::Zeroizing;

mod private {
    use super::{Box, Vec, Zeroizing};

    /// Proof that a call comes from inside this crate. Outside code can neither name nor
    /// build it, so the operations below cannot be called from outside, not even through
    /// a `DynamicBytes` bound, which does bring them into scope.
    pub struct Token(());

    /// The only value of [`Token`].
    pub(crate) const TOKEN: Token = Token(());

    /// The buffer operations behind [`DynamicBytes`](super::DynamicBytes). Sealed: the
    /// trait cannot be named outside this crate, so it cannot be implemented there, and
    /// every method takes a [`Token`], so none can be called there.
    pub trait Ops {
        /// A buffer of exactly `len` zero bytes, built before any secret is written to it.
        fn zeroed(len: usize, _: Token) -> Box<Self>;

        /// The buffer's bytes, for filling a buffer `zeroed` made.
        fn bytes_mut(&mut self, _: Token) -> &mut [u8];

        /// The buffer's bytes, for encoding.
        fn bytes(&self, _: Token) -> &[u8];

        /// Moves or copies `protected` into a new buffer. `protected` stays wrapped until
        /// the new buffer is built, so a failed allocation still wipes it.
        fn from_protected(protected: Zeroizing<Vec<u8>>, _: Token) -> Box<Self>;
    }
}

pub(crate) use private::{Ops, TOKEN};

/// A byte buffer [`Dynamic`](crate::Dynamic) builds in place: `Vec<u8>` or `[u8]`.
///
/// See the [module docs](self) for what it unifies and why a call must name the shape.
/// Sealed; not implementable outside this crate. It has no methods outside this crate:
/// the buffer operations it needs are on a private supertrait, and each takes a token
/// only this crate can build.
pub trait DynamicBytes: private::Ops + zeroize::Zeroize {}

impl DynamicBytes for Vec<u8> {}
impl DynamicBytes for [u8] {}

impl Ops for Vec<u8> {
    #[inline(always)]
    fn zeroed(len: usize, _: private::Token) -> Box<Self> {
        Box::new(alloc::vec![0u8; len])
    }

    #[inline(always)]
    fn bytes_mut(&mut self, _: private::Token) -> &mut [u8] {
        self
    }

    #[inline(always)]
    fn bytes(&self, _: private::Token) -> &[u8] {
        self
    }

    #[inline(always)]
    fn from_protected(mut protected: Zeroizing<Vec<u8>>, _: private::Token) -> Box<Self> {
        // The 24-byte header is the only allocation; `protected` stays live across it.
        let mut boxed = Box::<Vec<u8>>::default();
        core::mem::swap(&mut *boxed, &mut *protected);
        boxed
    }
}

impl Ops for [u8] {
    #[inline(always)]
    fn zeroed(len: usize, _: private::Token) -> Box<Self> {
        // `vec![0; len]` has capacity `len`, so turning it into a box does not reallocate.
        alloc::vec![0u8; len].into_boxed_slice()
    }

    #[inline(always)]
    fn bytes_mut(&mut self, _: private::Token) -> &mut [u8] {
        self
    }

    #[inline(always)]
    fn bytes(&self, _: private::Token) -> &[u8] {
        self
    }

    #[inline(always)]
    fn from_protected(protected: Zeroizing<Vec<u8>>, _: private::Token) -> Box<Self> {
        // Copied into a box of exactly its length; `protected` may have spare capacity,
        // and shrinking it in place could reallocate and free its buffer unwiped. It is
        // wiped when it drops at the end of this call.
        let mut boxed = Self::zeroed(protected.len(), TOKEN);
        boxed.copy_from_slice(&protected);
        boxed
    }
}
