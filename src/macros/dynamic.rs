// secure-gate/src/macros/dynamic_macros.rs

/// Creates a type alias for a heap-allocated secure secret.
///
/// # Examples
///
/// Public alias:
/// ```
/// #[cfg(feature = "std")]
/// {
/// use secure_gate::dynamic_alias;
/// dynamic_alias!(pub Password, String);
/// let pw: Password = "hunter2".into();
/// assert_eq!(pw.expose_secret(), "hunter2");
/// # }
/// ```
///
/// Private alias:
/// ```
/// #[cfg(feature = "std")]
/// {
/// use secure_gate::dynamic_alias;
/// dynamic_alias!(SecretString, String); // No visibility modifier = private
/// let secret = SecretString::new("hidden".to_string());
/// # }
/// ```
#[macro_export]
macro_rules! dynamic_alias {
    ($vis:vis $name:ident, $inner:ty) => {
        #[doc = concat!("Secure heap-allocated ", stringify!($inner))]
        $vis type $name = $crate::Dynamic<$inner>;
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
/// #[cfg(feature = "std")]
/// {
/// use secure_gate::dynamic_generic_alias;
/// dynamic_generic_alias!(pub SecureVec, Vec<u8>, "Secure dynamic byte vector");
/// let vec = SecureVec::new(vec![1, 2, 3]);
/// assert_eq!(vec.len(), 3);
/// # }
/// ```
#[macro_export]
macro_rules! dynamic_generic_alias {
    ($vis:vis $name:ident, $inner:ty, $doc:literal) => {
        #[doc = $doc]
        $vis type $name = $crate::Dynamic<$inner>;
    };
    ($vis:vis $name:ident, $inner:ty) => {
        #[doc = concat!("Secure heap-allocated ", stringify!($inner))]
        $vis type $name = $crate::Dynamic<$inner>;
    };
}
