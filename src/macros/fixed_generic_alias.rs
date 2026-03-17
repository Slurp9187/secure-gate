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
/// Macro-generated generic aliases lack runtime size checks beyond the compile-time
/// zero-size guard inherited from `Fixed<[u8; N]>`. Validate expected sizes in tests.
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
