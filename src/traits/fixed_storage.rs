//! Marker trait asserting that a secret's storage owns no heap allocation.
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
//! requires it, so the compiler now rejects an inner type that owns a heap allocation.
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
//! - the twelve `NonZero` integers;
//! - `[T; N]` for any `N`, when `T: FixedStorage` — which covers `[u8; 32]` and the
//!   non-byte arrays the `generic` arm exists for, such as `[i16; 256]`;
//! - tuples up to ten elements of `FixedStorage` types, matching `zeroize`'s own ceiling;
//! - `Option<T>` when `T: FixedStorage` — a discriminant adds no heap storage;
//! - `Wrapping<T>` and `MaybeUninit<T>` when `T: FixedStorage` — both are `T`'s own storage;
//! - `zeroize::Zeroizing<T>` when `T: FixedStorage`;
//! - `Fixed<T>` itself when `T: FixedStorage`, so the wrapper nests.
//!
//! # Why that list has to be this long
//!
//! The bound is an allow-list, which means it fails closed: a type is refused both when it
//! owns a heap allocation and when nothing has asserted that it does not. For a type you
//! define, the second case costs one line. For a type you do **not** own it costs nothing,
//! because you cannot pay it — `impl FixedStorage for NonZeroU32` in your crate is E0117,
//! the orphan rule, and no amount of effort downstream changes that.
//!
//! So every heap-free type reachable through `zeroize`'s own `Zeroize` impls has to be
//! blessed here or it is simply unavailable as a `Fixed` inner type, with the caller's only
//! escape being to change their own type. That is the reason for the `NonZero`, `Wrapping`,
//! `MaybeUninit` and `Zeroizing` impls above, and for tuples reaching ten rather than four:
//! each was a shape that compiled before this bound existed and that no downstream crate
//! could have restored. Ten is not arbitrary — `zeroize` implements `Zeroize` for tuples up
//! to ten elements and no further, so an eleventh element fails the `Zeroize` bound before
//! this one is ever consulted.
//!
//! The deny-list alternative — accept everything except a known set of heap owners — was
//! rejected deliberately. It has no false rejections, but it fails **open**: a custom type
//! wrapping a `Vec` would be accepted in silence, which is the exact weakness this trait
//! exists to close.
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
//! // Asserted here: `Poly` owns no heap allocation.
//! impl FixedStorage for Poly {}
//!
//! let p = Fixed::new(Poly([7i16; 256]));
//! assert_eq!(p.with_secret(|poly| poly.0[0]), 7);
//! ```
//!
//! # If the bound rejects your type
//!
//! The error is the bare unsatisfied-bound form, `E0277` naming the inner type and the
//! unsatisfied `FixedStorage` bound, followed by the list of implementors. `main` improves it
//! with
//! `#[diagnostic::on_unimplemented]`, which needs Rust 1.78 and so cannot be used on this
//! line's MSRV 1.70. The guidance that attribute carries is therefore written out here:
//!
//! - If the inner type owns a heap allocation, reach for [`Dynamic`](crate::Dynamic), which
//!   documents the residue and offers one safe growth path.
//! - `Dynamic` needs this crate's `alloc` feature. If you are seeing this error with `alloc`
//!   off while still able to name `Vec` or `String` — which happens when `zeroize`'s own
//!   `alloc` feature is enabled elsewhere in the dependency graph — then enabling this crate's
//!   `alloc` is the fix. In that configuration `Fixed<Vec<u8>>` is nameable while
//!   `secure_gate::Dynamic` does not exist at all, which is the one corner where the two
//!   wrappers do not simply substitute for each other.
//! - If the type genuinely owns no heap allocation, it is only missing the assertion. For a
//!   type you define, write an empty `impl FixedStorage` block for it. That is an assertion
//!   the compiler cannot check, so only write it if it is true.
//! - If it is a type you do **not** own, you cannot write that impl at all: the orphan rule
//!   rejects it with `E0117`. Wrap it in a newtype of your own and implement the marker for
//!   that, or ask for an impl upstream. The heap-free types `zeroize` supports are blessed
//!   here already, for exactly this reason — see "Why that list has to be this long" above.
//!
//! # Naming the type still compiles
//!
//! The bound is on [`Fixed::new`](crate::Fixed::new), not on the struct, which keeps the
//! property the zero-size guard already documents: `type Bad = Fixed<Vec<u8>>;` is a
//! legal type expression and no guard in the type could make it otherwise. What the bound
//! removes is every *value* of it.

/// Marker trait asserting that a type owns no heap allocation.
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

// The twelve `NonZero` integers `zeroize` implements `Zeroize` for. Each is a single integer
// with a niche, so there is no allocation to abandon.
//
// These are foreign types, so a downstream crate cannot assert this itself: `impl
// FixedStorage for NonZeroU32` is E0117. That is why the impls live here -- without them,
// `Fixed<NonZeroU32>` would be refused with no fix available to the caller.
__sg_fixed_storage_prims!(
    core::num::NonZeroU8,
    core::num::NonZeroU16,
    core::num::NonZeroU32,
    core::num::NonZeroU64,
    core::num::NonZeroU128,
    core::num::NonZeroUsize,
    core::num::NonZeroI8,
    core::num::NonZeroI16,
    core::num::NonZeroI32,
    core::num::NonZeroI64,
    core::num::NonZeroI128,
    core::num::NonZeroIsize,
);

/// An array never reallocates, whatever its length, so it is `FixedStorage` exactly when
/// its element type is. This is the impl that covers `[u8; N]` and the non-byte arrays the
/// `generic` arm of [`fixed_newtype!`](crate::fixed_newtype) exists for.
impl<T: FixedStorage, const N: usize> FixedStorage for [T; N] {}

/// `Wrapping` is a transparent arithmetic wrapper: same storage as its payload.
impl<T: FixedStorage> FixedStorage for core::num::Wrapping<T> {}

/// `MaybeUninit<T>` is `T`'s storage, initialised or not. No allocation either way.
impl<T: FixedStorage> FixedStorage for core::mem::MaybeUninit<T> {}

/// `zeroize::Zeroizing<T>` holds `T` inline and wipes it on drop, so it qualifies exactly
/// when `T` does.
///
/// This one matters out of proportion to its size. `Zeroizing` is the idiomatic "wipe this
/// on drop" wrapper from this crate's only non-optional dependency, so
/// `Fixed<Zeroizing<[u8; 32]>>` is a shape people reach for -- and because both the trait and
/// the type are foreign to the caller, the orphan rule leaves them no way to assert it. It
/// has to be here or it is unavailable.
impl<T: FixedStorage + zeroize::Zeroize> FixedStorage for zeroize::Zeroizing<T> {}

/// A `Fixed<T>` holds `T` inline, so the wrapper nests: `Fixed<Fixed<[u8; 32]>>` is legal
/// exactly when the payload qualifies. Without this impl the crate's own wrapper could not
/// be used as its own inner type.
impl<T: zeroize::Zeroize + FixedStorage> FixedStorage for crate::Fixed<T> {}

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
    (A, B, C, D, E);
    (A, B, C, D, E, F);
    (A, B, C, D, E, F, G);
    (A, B, C, D, E, F, G, H);
    (A, B, C, D, E, F, G, H, I);
    (A, B, C, D, E, F, G, H, I, J);
}

/// An `Option` adds a discriminant and no heap storage, so it qualifies exactly when its
/// payload does. `Option<[u8; 32]>` is a legitimate fixed-size secret; `Option<Vec<u8>>`
/// and `Option<Box<[u8]>>` are both rejected, which is the point.
impl<T: FixedStorage> FixedStorage for Option<T> {}
