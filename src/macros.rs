// ==========================================================================
// src/macros.rs
// ==========================================================================

/// Creates a type alias for a fixed-size secure secret.
///
/// This macro generates a type alias to `Fixed<[u8; N]>` with optional visibility.
/// The generated type inherits all methods from `Fixed`, including `.expose_secret()`.
///
/// # Syntax
///
/// - `fixed_alias!(vis Name, size);` — visibility required (e.g., `pub`, `pub(crate)`, or omit for private)
///
/// # Examples
///
/// Public alias:
/// ```
/// use secure_gate::fixed_alias;
/// fixed_alias!(pub Aes256Key, 32);
/// let key = Aes256Key::new([0u8; 32]);
/// assert_eq!(key.len(), 32);
/// ```
///
/// Private alias:
/// ```
/// use secure_gate::fixed_alias;
/// fixed_alias!(private_key, 32); // No visibility modifier = private
/// ```
///
/// With custom visibility:
/// ```
/// use secure_gate::fixed_alias;
/// fixed_alias!(pub(crate) InternalKey, 64); // Crate-visible
/// ```
///
/// The generated type is zero-cost and works with all features.
#[macro_export]
macro_rules! fixed_alias {
    ($vis:vis $name:ident, $size:literal) => {
        #[doc = concat!("Fixed-size secure secret (", $size, " bytes)")]
        $vis type $name = $crate::Fixed<[u8; $size]>;
    };
    ($name:ident, $size:literal) => {
        #[doc = concat!("Fixed-size secure secret (", $size, " bytes)")]
        type $name = $crate::Fixed<[u8; $size]>;
    };
}

/// Creates a generic (const-sized) fixed secure buffer type.
///
/// This macro generates a type alias to `Fixed<[u8; N]>` with a custom doc string.
/// Useful for libraries providing generic secret buffers.
///
/// # Examples
///
/// With custom doc:
/// ```
/// use secure_gate::fixed_generic_alias;
/// fixed_generic_alias!(pub GenericKey, "Generic secure key buffer");
/// let key: GenericKey<32> = GenericKey::new([0u8; 32]);
/// ```
///
/// With default doc:
/// ```
/// use secure_gate::fixed_generic_alias;
/// fixed_generic_alias!(pub(crate) Buffer);
/// let buf: Buffer<16> = Buffer::new([0u8; 16]);
/// ```
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

/// Creates a type alias for a random-only fixed-size secret.
///
/// This macro generates a type alias to `FixedRng<N>`, which can only be
/// instantiated via `.generate()` (requires the "rand" feature).
///
/// # Examples
///
/// Public alias:
/// ```
/// # #[cfg(feature = "rand")]
/// # {
/// use secure_gate::fixed_alias_rng;
/// fixed_alias_rng!(pub MasterKey, 32);
/// let key = MasterKey::generate();
/// assert_eq!(key.len(), 32);
/// # }
/// ```
///
/// Private alias:
/// ```
/// # #[cfg(feature = "rand")]
/// # {
/// use secure_gate::fixed_alias_rng;
/// fixed_alias_rng!(PrivateKey, 32); // No visibility modifier = private
/// let key = PrivateKey::generate();
/// # }
/// ```
#[macro_export]
macro_rules! fixed_alias_rng {
    ($vis:vis $name:ident, $size:literal) => {
        #[doc = concat!("Random-only fixed-size secret (", $size, " bytes)")]
        $vis type $name = $crate::rng::FixedRng<$size>;
    };
    ($name:ident, $size:literal) => {
        #[doc = concat!("Random-only fixed-size secret (", $size, " bytes)")]
        type $name = $crate::rng::FixedRng<$size>;
    };
}

/// Creates a type alias for a heap-allocated secure secret.
///
/// # Examples
///
/// Public alias:
/// ```
/// use secure_gate::dynamic_alias;
/// dynamic_alias!(pub Password, String);
/// let pw: Password = "hunter2".into();
/// assert_eq!(pw.expose_secret(), "hunter2");
/// ```
///
/// Private alias:
/// ```
/// use secure_gate::dynamic_alias;
/// dynamic_alias!(SecretString, String); // No visibility modifier = private
/// let secret = SecretString::new("hidden".to_string());
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
/// use secure_gate::dynamic_generic_alias;
/// dynamic_generic_alias!(pub SecureVec, Vec<u8>, "Secure dynamic byte vector");
/// let vec = SecureVec::new(vec![1, 2, 3]);
/// assert_eq!(vec.len(), 3);
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
