/// Creates a type alias for [`Dynamic<T>`](crate::Dynamic).
///
/// Generates a named, optionally-documented type alias. The generated type inherits
/// all `Dynamic<T>` methods including `expose_secret()`, `with_secret()`, `to_hex()`, etc.
///
/// *Requires feature `alloc`.*
///
/// # Syntax
///
/// ```text
/// dynamic_alias!(pub Name, T);                // public, auto-generated doc
/// dynamic_alias!(pub(crate) Name, T);         // crate-visible
/// dynamic_alias!(Name, T);                    // private
/// dynamic_alias!(pub Name, T, "doc string");  // with custom doc
/// ```
///
/// # Examples
///
/// All three visibility forms:
///
/// ```rust
/// use secure_gate::{dynamic_alias, ExposeSecret};
///
/// dynamic_alias!(pub Password, String);            // public
/// dynamic_alias!(pub(crate) SessionToken, Vec<u8>); // crate-visible
/// dynamic_alias!(private_key_bytes, Vec<u8>);      // private
///
/// let pw: Password = "hunter2".into();
/// pw.with_secret(|s| assert!(!s.is_empty()));
/// ```
///
/// With a custom doc string:
///
/// ```rust
/// use secure_gate::{dynamic_alias, ExposeSecret};
///
/// dynamic_alias!(pub Token, Vec<u8>, "OAuth 2.0 bearer token.");
/// let token: Token = vec![1u8, 2, 3].into();
/// assert_eq!(token.expose_secret(), &[1, 2, 3]);
/// ```
///
/// # Implementation Notes
///
/// `dynamic_alias!` has **no zero-size or type-level guard** — any `T` is accepted.
/// Macro-generated aliases lack runtime size checks beyond what `Dynamic<T>` itself provides.
/// Validate expected inner types and sizes in unit tests:
///
/// ```rust
/// use secure_gate::dynamic_alias;
///
/// dynamic_alias!(pub ApiToken, Vec<u8>);
/// // In your tests: assert!(token.len() > 0);
/// ```
#[cfg(feature = "alloc")]
#[macro_export]
macro_rules! dynamic_alias {
    ($vis:vis $name:ident, $inner:ty, $doc:literal) => {
        #[doc = $doc]
        $vis type $name = $crate::Dynamic<$inner>;
    };
    ($vis:vis $name:ident, $inner:ty) => {
        #[doc = concat!("Secure heap-allocated ", stringify!($inner))]
        $vis type $name = $crate::Dynamic<$inner>;
    };
    ($name:ident, $inner:ty, $doc:literal) => {
        #[doc = $doc]
        type $name = $crate::Dynamic<$inner>;
    };
    ($name:ident, $inner:ty) => {
        #[doc = concat!("Secure heap-allocated ", stringify!($inner))]
        type $name = $crate::Dynamic<$inner>;
    };
}
