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
//! implemented outside this crate. It has no methods of its own; the buffer operations
//! the crate uses live on a supertrait under `__private`, outside the public API.

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;
use zeroize::Zeroizing;

mod private {
    pub trait Sealed {}
    impl Sealed for alloc::vec::Vec<u8> {}
    impl Sealed for [u8] {}
}

/// A byte buffer [`Dynamic`](crate::Dynamic) builds in place: `Vec<u8>` or `[u8]`.
///
/// See the [module docs](self) for what it unifies and why a call must name the shape.
/// Sealed; not implementable outside this crate. It has no methods of its own: what the
/// generic constructors and encoders need lives on a supertrait under `__private`, which
/// is not part of the public API.
pub trait DynamicBytes: private::Sealed + zeroize::Zeroize + DynamicBytesImpl {}

impl DynamicBytes for Vec<u8> {}
impl DynamicBytes for [u8] {}

/// The buffer operations behind [`DynamicBytes`]. Reached only as
/// `secure_gate::__private::DynamicBytesImpl`, so it is semver-exempt like the rest of
/// `__private`. Each method acts on a plain buffer the crate builds and reaches nothing
/// inside a `Dynamic`.
#[doc(hidden)]
pub trait DynamicBytesImpl {
    /// A buffer of exactly `len` zero bytes, built before any secret is written to it.
    fn __zeroed(len: usize) -> Box<Self>;

    /// The buffer's bytes, for filling a buffer `__zeroed` made.
    fn __bytes_mut(&mut self) -> &mut [u8];

    /// The buffer's bytes, for encoding.
    fn __bytes(&self) -> &[u8];

    /// Moves or copies `protected` into a new buffer. `protected` stays wrapped until the
    /// new buffer is built, so a failed allocation still wipes it.
    fn __from_protected(protected: Zeroizing<Vec<u8>>) -> Box<Self>;
}

impl DynamicBytesImpl for Vec<u8> {
    #[inline(always)]
    fn __zeroed(len: usize) -> Box<Self> {
        Box::new(alloc::vec![0u8; len])
    }

    #[inline(always)]
    fn __bytes_mut(&mut self) -> &mut [u8] {
        self
    }

    #[inline(always)]
    fn __bytes(&self) -> &[u8] {
        self
    }

    #[inline(always)]
    fn __from_protected(mut protected: Zeroizing<Vec<u8>>) -> Box<Self> {
        // The 24-byte header is the only allocation; `protected` stays live across it.
        let mut boxed = Box::<Vec<u8>>::default();
        core::mem::swap(&mut *boxed, &mut *protected);
        boxed
    }
}

impl DynamicBytesImpl for [u8] {
    #[inline(always)]
    fn __zeroed(len: usize) -> Box<Self> {
        // `vec![0; len]` has capacity `len`, so turning it into a box does not reallocate.
        alloc::vec![0u8; len].into_boxed_slice()
    }

    #[inline(always)]
    fn __bytes_mut(&mut self) -> &mut [u8] {
        self
    }

    #[inline(always)]
    fn __bytes(&self) -> &[u8] {
        self
    }

    #[inline(always)]
    fn __from_protected(protected: Zeroizing<Vec<u8>>) -> Box<Self> {
        // Copied into a box of exactly its length; `protected` may have spare capacity,
        // and shrinking it in place could reallocate and free its buffer unwiped. It is
        // wiped when it drops at the end of this call.
        let mut boxed = Self::__zeroed(protected.len());
        boxed.copy_from_slice(&protected);
        boxed
    }
}
