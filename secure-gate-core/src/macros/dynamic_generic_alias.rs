/// Creates a generic type alias `Name<T>` for [`Dynamic<T>`](crate::Dynamic).
///
/// Useful when you need a single reusable name for heap-allocated secrets of varying types.
///
/// *Requires feature `alloc`.*
///
/// # Syntax
///
/// ```text
/// dynamic_generic_alias!(pub Name, "doc string"); // public with custom doc
/// dynamic_generic_alias!(pub(crate) Name);        // crate-visible, auto-generated doc
/// ```
///
/// # Examples
///
/// ```rust
/// use secure_gate::{dynamic_generic_alias, RevealSecret};
///
/// dynamic_generic_alias!(pub SecureBox, "Generic heap-allocated secret wrapper.");
///
/// let key: SecureBox<Vec<u8>> = vec![0u8; 32].into();
/// key.with_secret(|b| assert_eq!(b.len(), 32));
/// ```
///
/// # Implementation Notes
///
/// Macro-generated generic aliases lack runtime size checks. Validate expected
/// inner types and sizes in unit tests. As with `dynamic_alias!`, zero-sized or
/// empty inner types are permitted; validate non-zero size in tests.
///
/// The inner type `T` must implement `Zeroize` — this is enforced by `Dynamic<T>`,
/// not the macro.
///
/// # See also
///
/// - [`dynamic_alias!`](crate::dynamic_alias) — preferred when the inner type is known
/// - [`fixed_generic_alias!`](crate::fixed_generic_alias) — stack-allocated alternative
#[cfg(feature = "alloc")]
#[macro_export]
macro_rules! dynamic_generic_alias {
    ($vis:vis $name:ident, $doc:literal) => {
        #[doc = $doc]
        $vis type $name<T> = $crate::Dynamic<T>;
    };
    ($vis:vis $name:ident) => {
        #[doc = "Generic secure heap wrapper"]
        $vis type $name<T> = $crate::Dynamic<T>;
    };
}
