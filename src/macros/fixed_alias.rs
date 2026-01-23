/// Creates a type alias for a fixed-size stack-allocated secure secret.
///
/// This macro generates a type alias to `Fixed<[u8; N]>` with optional visibility and custom documentation.
/// The generated type inherits all methods from `Fixed`, including `.expose_secret()`.
///
/// # Syntax
///
/// - `fixed_alias!(vis Name, size);` — visibility required (e.g., `pub`, `pub(crate)`, or omit for private)
/// - `fixed_alias!(vis Name, size, doc);` — with optional custom doc string
///
/// # Examples
///
/// Public alias:
/// ```
/// use secure_gate::{fixed_alias, ExposeSecret};
/// fixed_alias!(pub Aes256Key, 32);
/// let key: Aes256Key = [42u8; 32].into();
/// assert_eq!(key.expose_secret(), &[42u8; 32]);
/// ```
///
/// Private alias:
/// ```
/// use secure_gate::{fixed_alias, ExposeSecret};
/// fixed_alias!(private_key, 32); // No visibility modifier = private
/// let key: private_key = [0u8; 32].into();
/// assert_eq!(key.expose_secret(), &[0u8; 32]);
/// ```
///
/// With custom visibility:
/// ```
/// use secure_gate::fixed_alias;
/// fixed_alias!(pub(crate) InternalKey, 64); // Crate-visible
/// ```
///
/// With custom documentation:
/// ```
/// use secure_gate::{fixed_alias, ExposeSecret};
/// fixed_alias!(pub ApiKey, 32, "API key for external service");
/// let key: ApiKey = [0u8; 32].into();
/// assert_eq!(key.expose_secret(), &[0u8; 32]);
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
