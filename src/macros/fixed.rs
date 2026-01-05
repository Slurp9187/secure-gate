// secure-gate/src/macros/fixed_macros.rs

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
/// For random initialization, use Type::generate() (requires 'rand' feature).
#[macro_export]
macro_rules! fixed_alias {
    ($vis:vis $name:ident, $size:literal) => {
        #[doc = concat!("Fixed-size secure secret (", stringify!($size), " bytes)")]
        const _: () = { let _ = [(); $size][0]; };
        $vis type $name = $crate::Fixed<[u8; $size]>;
    };
    ($name:ident, $size:literal) => {
        #[doc = concat!("Fixed-size secure secret (", stringify!($size), " bytes)")]
        const _: () = { let _ = [(); $size][0]; };
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
/// fixed_generic_alias!(pub GenericBuffer, "Generic secure byte buffer");
/// ```
///
/// With default doc:
/// ```
/// use secure_gate::fixed_generic_alias;
/// fixed_generic_alias!(pub(crate) Buffer);
/// ```
/// For random initialization, use `Type::<N>::generate()` (requires 'rand' feature).
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
/// #[cfg(feature = "rand")]
/// {
/// use secure_gate::fixed_alias_rng;
/// fixed_alias_rng!(pub MasterKey, 32);
/// # }
/// ```
///
/// Private alias:
/// ```
/// #[cfg(feature = "rand")]
/// {
/// use secure_gate::fixed_alias_rng;
/// fixed_alias_rng!(PrivateKey, 32); // No visibility modifier = private
/// # }
/// ```
/// Instantiate with Type::generate() (requires 'rand' feature).
#[macro_export]
macro_rules! fixed_alias_rng {
    ($vis:vis $name:ident, $size:literal) => {
        #[doc = concat!("Random-only fixed-size secret (", stringify!($size), " bytes)")]
        const _: () = { let _ = [(); $size][0]; };
        $vis type $name = $crate::random::FixedRng<$size>;
    };
    ($name:ident, $size:literal) => {
        #[doc = concat!("Random-only fixed-size secret (", stringify!($size), " bytes)")]
        const _: () = { let _ = [(); $size][0]; };
        type $name = $crate::random::FixedRng<$size>;
    };
}
