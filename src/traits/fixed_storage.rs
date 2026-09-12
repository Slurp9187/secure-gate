//! Marker trait asserting that a secret's storage cannot be reallocated.
//!
//! [`Fixed<T>`](crate::Fixed) is documented as having no reallocation surface, which is
//! what lets `SECURITY.md` exempt it from the heap-residue weakness that
//! [`Dynamic<T>`](crate::Dynamic) carries. That exemption was a claim about the *shape*
//! people were expected to use, not something the type system checked: `Fixed<T>` is
//! bounded only by `Zeroize`, so `Fixed<Vec<u8>>` and `Fixed<String>` compiled, and
//! `fixed_newtype!(pub Name, generic Vec<u8>)` was a documented path straight to them.
//! Measured, they leak exactly as much as the `Dynamic` equivalent — and worse, because
//! `Dynamic<Vec<u8>>` has a safe-growth `std::io::Write` impl and `Fixed<Vec<u8>>` has
//! nothing.
//!
//! [`FixedStorage`] is what makes the exemption true. [`Fixed::new`](crate::Fixed::new)
//! requires it, so the compiler now rejects an inner type whose capacity can change.
//!
//! # The contract
//!
//! Implementing `FixedStorage` for a type asserts that **the type owns no heap
//! allocation**. Nothing else, and note that this is stricter than "cannot be resized".
//!
//! The first version of this trait asked only for a fixed capacity, and blessed `Box<[T]>`
//! on the reasoning that a boxed slice has its length fixed at construction. That was
//! wrong, and measurably so: the residue never needed a capacity change. Whole-value
//! replacement abandons the allocation just as well, and the wrapper wipes whatever it
//! holds at drop, not what it used to hold. On a `Fixed<Box<[u8]>>` carrying a 1024-byte
//! secret, `with_secret_mut(|slot| *slot = other_boxed_slice)` released the original block
//! with **1024 of 1024** bytes intact, and so did the same assignment through
//! `expose_secret_mut`. The inline contrast, `Fixed<[u8; 1024]>` assigned the same way,
//! freed nothing at all — there is no allocation to abandon. So `Box<[T]>` is no longer
//! implemented, and the predicate is heap ownership rather than resizability.
//!
//! The test to apply to your own type: *does `Self` own a heap allocation?* If yes, do not
//! implement this — reach for [`Dynamic`](crate::Dynamic), which documents the residue.
//!
//! # This is an assertion, not an enforcement
//!
//! Like [`CloneableSecret`](crate::CloneableSecret), the compiler checks that you wrote
//! the impl, not that the claim is true. A type with a `Vec` field that implements
//! `FixedStorage` anyway will compile and will leak, which is measured and deliberate:
//! the alternative is a closed set of blessed types, and that would break the one thing
//! the `generic` arm of [`fixed_newtype!`](crate::fixed_newtype) exists for — holding a
//! custom secret on a target with no allocator.
//!
//! What the marker buys is that the claim is now *written down at a greppable line* in
//! the crate making it, rather than being an unstated assumption. That is the same trade
//! the other opt-in markers in this crate make.
//!
//! # What is implemented for you
//!
//! - the integer, floating-point, `bool`, `char` and `()` primitives;
//! - `[T; N]` for any `N`, when `T: FixedStorage` — which covers `[u8; 32]` and the
//!   non-byte arrays the `generic` arm exists for, such as `[i16; 256]`;
//! - tuples up to four elements of `FixedStorage` types;
//! - `Option<T>` when `T: FixedStorage` — a discriminant adds no heap storage.
//!
//! Nothing heap-owning is implemented, deliberately. `Box<[T]>` was and is not: see the
//! contract above for the measurement that removed it. `Box<[u8; N]>` never arises anyway,
//! because `zeroize` does not implement `Zeroize` for a `Box` of a sized type. For a
//! heap-only secret of fixed size, the supported shape is `Dynamic<[u8; N]>`.
//!
//! A custom inner type needs one line:
//!
//! ```rust
//! use secure_gate::{FixedStorage, Fixed, RevealSecret, SentinelValue};
//! use zeroize::Zeroize;
//!
//! struct Poly([i16; 256]);
//!
//! impl Zeroize for Poly {
//!     fn zeroize(&mut self) {
//!         self.0.zeroize();
//!     }
//! }
//! impl SentinelValue for Poly {
//!     fn sentinel_value() -> Self {
//!         Poly([0i16; 256])
//!     }
//! }
//! // Asserted here: `Poly` owns no buffer whose capacity can change.
//! impl FixedStorage for Poly {}
//!
//! let p = Fixed::new(Poly([7i16; 256]));
//! assert_eq!(p.with_secret(|poly| poly.0[0]), 7);
//! ```
//!
//! # Naming the type still compiles
//!
//! The bound is on [`Fixed::new`](crate::Fixed::new), not on the struct, which keeps the
//! property the zero-size guard already documents: `type Bad = Fixed<Vec<u8>>;` is a
//! legal type expression and no guard in the type could make it otherwise. What the bound
//! removes is every *value* of it.

/// Marker trait asserting that a type owns no buffer whose capacity can change.
///
/// Required by [`Fixed::new`](crate::Fixed::new). See the
/// [module documentation](self) for the contract, for what is already implemented,
/// and for why this is an assertion rather than an enforcement.
///
/// No methods — its only purpose is to gate construction of a
/// [`Fixed<T>`](crate::Fixed).
pub trait FixedStorage {}

macro_rules! __sg_fixed_storage_prims {
    ($($t:ty),* $(,)?) => {
        $(
            impl FixedStorage for $t {}
        )*
    };
}

__sg_fixed_storage_prims!(
    u8,
    u16,
    u32,
    u64,
    u128,
    usize,
    i8,
    i16,
    i32,
    i64,
    i128,
    isize,
    bool,
    char,
    f32,
    f64,
    ()
);

/// An array never reallocates, whatever its length, so it is `FixedStorage` exactly when
/// its element type is. This is the impl that covers `[u8; N]` and the non-byte arrays the
/// `generic` arm of [`fixed_newtype!`](crate::fixed_newtype) exists for.
impl<T: FixedStorage, const N: usize> FixedStorage for [T; N] {}

macro_rules! __sg_fixed_storage_tuples {
    ($(($($name:ident),+);)*) => {
        $(
            impl<$($name: FixedStorage),+> FixedStorage for ($($name,)+) {}
        )*
    };
}

__sg_fixed_storage_tuples! {
    (A);
    (A, B);
    (A, B, C);
    (A, B, C, D);
}

/// An `Option` adds a discriminant and no heap storage, so it qualifies exactly when its
/// payload does. `Option<[u8; 32]>` is a legitimate fixed-size secret; `Option<Vec<u8>>`
/// and `Option<Box<[u8]>>` are both rejected, which is the point.
impl<T: FixedStorage> FixedStorage for Option<T> {}
