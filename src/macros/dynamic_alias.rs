// <file_path>
// secure-gate\src\macros\dynamic_alias.rs
// </file_path>
// <edit_description>
// Fix the macro file and add cfg
// </edit_description>

/// Creates a type alias for a dynamic-sized heap-allocated secure secret.
///
/// This macro generates a type alias to `Dynamic<T>` with optional visibility and custom documentation.
/// The generated type inherits all methods from `Dynamic`, including `.expose_secret()`.
///
/// # Syntax
///
/// - `dynamic_alias!(vis Name, Type);` — visibility required (e.g., `pub`, `pub(crate)`, or omit for private)
/// - `dynamic_alias!(vis Name, Type, doc);` — with optional custom doc string
///
/// # Examples
///
/// Public alias:
/// ```
/// use secure_gate::{dynamic_alias, ExposeSecret};
/// dynamic_alias!(pub Password, String);
/// let pw: Password = "hunter2".into();
/// assert_eq!(pw.expose_secret(), "hunter2");
/// ```
///
/// Private alias:
/// ```
/// use secure_gate::{dynamic_alias, ExposeSecret};
/// dynamic_alias!(SecretString, String); // No visibility modifier = private
/// let secret: SecretString = "hidden".to_string().into();
/// assert_eq!(secret.expose_secret(), "hidden");
/// ```
///
/// With custom visibility:
/// ```
/// use secure_gate::dynamic_alias;
/// dynamic_alias!(pub(crate) InternalSecret, String); // Crate-visible
/// ```
///
/// With custom documentation:
/// ```
/// use secure_gate::{dynamic_alias, ExposeSecret};
/// dynamic_alias!(pub Token, Vec<u8>, "OAuth token for API access");
/// let token: Token = vec![1, 2, 3].into();
/// assert_eq!(token.expose_secret(), &[1, 2, 3]);
/// ```
///
/// The generated type is zero-cost and works with all features.
/// For random initialization, use `Type::from_random(n)` (requires 'rand' feature).
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
