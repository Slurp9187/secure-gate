/// Creates a type alias for [`Fixed<[u8; N]>`](crate::Fixed).
///
/// Generates a named, optionally-documented type alias with a compile-time zero-size guard.
/// The generated type inherits all `Fixed<[u8; N]>` methods including `expose_secret()`,
/// `with_secret()`, `to_hex()`, etc.
///
/// # Syntax
///
/// ```text
/// fixed_alias!(pub Name, N);                // public, auto-generated doc
/// fixed_alias!(pub(crate) Name, N);         // crate-visible
/// fixed_alias!(Name, N);                    // private
/// fixed_alias!(pub Name, N, "doc string");  // with custom doc
/// ```
///
/// # Examples
///
/// All three visibility forms:
///
/// ```rust
/// use secure_gate::{fixed_alias, RevealSecret};
///
/// fixed_alias!(pub Aes256Key, 32);           // public
/// fixed_alias!(pub(crate) HmacKey, 32);      // crate-visible
/// fixed_alias!(private_nonce, 12);           // private (no modifier)
///
/// let key: Aes256Key = [42u8; 32].into();
/// key.with_secret(|b| assert_eq!(b.len(), 32));
/// ```
///
/// With a custom doc string:
///
/// ```rust
/// use secure_gate::{fixed_alias, RevealSecret};
///
/// fixed_alias!(pub ApiKey, 32, "32-byte API authentication key.");
/// let key: ApiKey = [0u8; 32].into();
/// assert_eq!(key.expose_secret(), &[0u8; 32]);
/// ```
///
/// Zero-size is a **compile error** (caught by the zero-size guard):
///
/// ```rust,compile_fail
/// use secure_gate::fixed_alias;
/// fixed_alias!(pub Bad, 0); // compile-time error: index out of bounds
/// ```
///
/// # Implementation Notes
///
/// Each expansion emits `const _: () = { let _ = [(); N][0]; };` — a zero-cost
/// compile-time guard that rejects `N = 0` with a const-evaluation panic.
/// This is the **only** size check performed at compile time; there are no
/// runtime checks for other size constraints. Validate expected sizes in unit tests:
///
/// ```rust
/// use secure_gate::{fixed_alias, RevealSecret};
///
/// fixed_alias!(pub ChaChaKey, 32);
/// // In your tests:
/// assert_eq!(core::mem::size_of::<ChaChaKey>(), 32);
/// ```
#[macro_export]
macro_rules! fixed_alias {
    ($vis:vis $name:ident, $size:literal, $doc:literal) => {
        #[doc = $doc]
        const _: () = { let _ = [(); $size][0]; };
        $vis type $name = $crate::Fixed<[u8; $size]>;
    };
    ($vis:vis $name:ident, $size:literal) => {
        #[doc = concat!("Fixed-size secure secret (", stringify!($size), " bytes)")]
        const _: () = { let _ = [(); $size][0]; };
        $vis type $name = $crate::Fixed<[u8; $size]>;
    };
    ($name:ident, $size:literal, $doc:literal) => {
        #[doc = $doc]
        const _: () = { let _ = [(); $size][0]; };
        type $name = $crate::Fixed<[u8; $size]>;
    };
    ($name:ident, $size:literal) => {
        #[doc = concat!("Fixed-size secure secret (", stringify!($size), " bytes)")]
        const _: () = { let _ = [(); $size][0]; };
        type $name = $crate::Fixed<[u8; $size]>;
    };
}
