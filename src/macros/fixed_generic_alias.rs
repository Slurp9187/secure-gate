/// Creates a const-generic type alias `Name<const N: usize>` for [`Fixed<[u8; N]>`](crate::Fixed).
///
/// Useful when you need a single reusable name for fixed-size secrets across multiple sizes.
///
/// # Syntax
///
/// ```text
/// fixed_generic_alias!(pub Name, "doc string"); // public with custom doc
/// fixed_generic_alias!(pub(crate) Name);        // crate-visible, auto-generated doc
/// ```
///
/// # Examples
///
/// ```rust
/// use secure_gate::{fixed_generic_alias, ExposeSecret};
///
/// fixed_generic_alias!(pub SecretBuffer, "Generic fixed-size secret buffer.");
///
/// let key: SecretBuffer<32> = [0u8; 32].into();
/// key.with_secret(|b| assert_eq!(b.len(), 32));
///
/// let nonce: SecretBuffer<12> = [0u8; 12].into();
/// nonce.with_secret(|b| assert_eq!(b.len(), 12));
/// ```
///
/// # Implementation Notes
///
/// Unlike [`fixed_alias!`](crate::fixed_alias), which rejects `N = 0` at the call site
/// via a compile-time index-out-of-bounds trick, `fixed_generic_alias!` cannot apply
/// that guard because `N` is a const generic parameter not known at macro-invocation
/// time. As a result, `SecretBuffer::<0>` compiles successfully and produces a
/// zero-byte `Fixed<[u8; 0]>`. Such a type is valid Rust but has no cryptographic
/// utility and should never appear in production code.
/// Unlike the non-generic `fixed_alias!` macro, which rejects `N = 0` at compile time,
/// this generic version cannot perform that check because `N` is a const generic parameter resolved later.
/// Validate that `N > 0` in your
/// tests (e.g. `assert!(core::mem::size_of::<SecretBuffer<32>>() == 32);`).
#[macro_export]
macro_rules! fixed_generic_alias {
    ($vis:vis $name:ident, $doc:literal) => {
        #[doc = $doc]
        $vis type $name<const N: usize> = $crate::Fixed<[u8; N]>;
    };
    ($vis:vis $name:ident) => {
        #[doc = "Fixed-size secure byte buffer"]
        $vis type $name<const N: usize> = $crate::Fixed<[u8; N]>;
    };
}
