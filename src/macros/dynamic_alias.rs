/// Creates a type alias for a heap-allocated secure secret with optional custom documentation.
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
/// let secret = SecretString::new("hidden".to_string());
/// ```
///
/// With custom documentation:
/// ```
/// use secure_gate::{dynamic_alias, ExposeSecret};
/// dynamic_alias!(pub Token, Vec<u8>, "OAuth token for API access");
/// let token: Token = vec![1, 2, 3].into();
/// ```
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

/// Creates a generic heap-allocated secure secret type alias.
///
/// # Examples
///
/// ```
/// use secure_gate::{dynamic_generic_alias, ExposeSecret};
/// dynamic_generic_alias!(pub SecureVec, "Secure dynamic byte vector");
/// let vec = SecureVec::<Vec<u8>>::new(vec![1, 2, 3]);
/// assert_eq!(vec.len(), 3);
/// ```
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
