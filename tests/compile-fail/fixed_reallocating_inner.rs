//! `Fixed<T>` must reject an inner type whose capacity can change.
//!
//! `SECURITY.md` exempts `Fixed<T>` from the heap-reallocation residue that `Dynamic`
//! carries, on the grounds that it "has no realloc surface". Nothing enforced that: the
//! only bounds were `Zeroize` plus a non-zero size, so every construction below used to
//! compile, and measured, each abandoned an unwiped buffer holding the whole secret on any
//! capacity change — the same weakness, minus `Dynamic`'s safe-growth `io::Write` path.
//!
//! `FixedStorage` on `Fixed::new` is what closes it. Unlike the zero-size guard, this is a
//! real trait bound rather than a post-monomorphization `const` assertion, so `cargo check`
//! reports it, and for the macro forms it lands on the declaration rather than at the first
//! construction.
//!
//! The nested case is the one worth keeping: an array is `FixedStorage` only when its
//! element type is, so a growable container hidden inside the array shape the documentation
//! calls exempt is rejected too.
use secure_gate::{Fixed, fixed_newtype};

fixed_newtype!(pub LeakyBytes, generic Vec<u8>);
fixed_newtype!(pub LeakyText, generic String);

fn main() {
    let _ = Fixed::new(vec![1u8, 2, 3]);
    let _ = Fixed::new(String::from("secret"));
    let _ = Fixed::new([vec![1u8], vec![2u8]]);
    let _ = Fixed::new(Some(vec![1u8]));
    let _ = Fixed::new(([0u8; 32], vec![1u8]));

    // A boxed slice cannot be resized, which is why the first version of `FixedStorage`
    // accepted it. It still owns a heap allocation, and replacing the whole value abandons
    // that allocation unwiped — measured at 1024 of 1024 bytes surviving. The predicate is
    // heap ownership, not resizability, so all three of these are refused.
    let boxed: Box<[u8]> = vec![1u8, 2, 3].into_boxed_slice();
    let _ = Fixed::new(boxed);
    let _ = Fixed::new(Some(vec![1u8].into_boxed_slice()));
    let _ = Fixed::new([vec![1u8].into_boxed_slice(), vec![2u8].into_boxed_slice()]);
}
