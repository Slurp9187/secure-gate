/// Creates a type alias for a fixed-size secure secret.
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
/// With custom documentation:
/// ```
/// use secure_gate::fixed_alias;
/// fixed_alias!(pub ApiKey, 32, "API key for external service");
/// ```
///
/// The generated type is zero-cost and works with all features.
/// For random initialization, use Type::generate() (requires 'rand' feature).
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
/// This macro generates a type alias to `FixedRandom<N>`, which can only be
/// instantiated via `.generate()` (requires the "rand" feature).
///
/// # Examples
///
/// Public alias:
/// ```
/// #[cfg(feature = "rand")]
/// {
/// use secure_gate::fixed_alias_random;
/// fixed_alias_random!(pub MasterKey, 32);
/// # }
/// ```
///
/// Private alias:
/// ```
/// #[cfg(feature = "rand")]
/// {
/// use secure_gate::fixed_alias_random;
/// fixed_alias_random!(PrivateKey, 32); // No visibility modifier = private
/// # }
/// ```
///
/// With custom documentation:
/// ```
/// #[cfg(feature = "rand")]
/// {
/// use secure_gate::fixed_alias_random;
/// fixed_alias_random!(pub SessionKey, 32, "Random session key for authentication");
/// # }
/// ```
/// Instantiate with Type::generate() (requires 'rand' feature).
#[macro_export]
macro_rules! fixed_alias_random {
    ($vis:vis $name:ident, $size:literal, $doc:literal) => {
        #[doc = $doc]
        const _: () = { let _ = [(); $size][0]; };
        $vis type $name = $crate::random::FixedRandom<$size>;
    };
    ($vis:vis $name:ident, $size:literal) => {
        #[doc = concat!("Random-only fixed-size secret (", stringify!($size), " bytes)")]
        const _: () = { let _ = [(); $size][0]; };
        $vis type $name = $crate::random::FixedRandom<$size>;
    };
    ($name:ident, $size:literal, $doc:literal) => {
        #[doc = $doc]
        const _: () = { let _ = [(); $size][0]; };
        type $name = $crate::random::FixedRandom<$size>;
    };
    ($name:ident, $size:literal) => {
        #[doc = concat!("Random-only fixed-size secret (", stringify!($size), " bytes)")]
        const _: () = { let _ = [(); $size][0]; };
        type $name = $crate::random::FixedRandom<$size>;
    };
}

// Creates a type alias for a fixed-size exportable secret (opt-in serialization).
//
// This macro generates an inner newtype for raw byte arrays, implements ExportableType for opt-in serialization,
// and creates a type alias to `Fixed<Inner>`. Requires the "serde-serialize" feature to compile.
//
// The generated type allows deliberate serialization of raw secrets while maintaining security.
//
// # Syntax
//
// - `fixed_exportable_alias!(vis Name, size);` — visibility required
// - `fixed_exportable_alias!(vis Name, size, doc);` — with optional custom doc string
//
// # Examples
//
// Public alias:
// ```
// #[cfg(feature = "serde-serialize")]
// {
// use secure_gate::fixed_exportable_alias;
// fixed_exportable_alias!(pub Aes256Key, 32);
// let key: Aes256Key = [42u8; 32].into();
// // key can now be serialized
// # }
// ```
//
// With custom documentation:
// ```
// #[cfg(feature = "serde-serialize")]
// {
// use secure_gate::fixed_exportable_alias;
// fixed_exportable_alias!(pub ApiKey, 32, "Serializable API key");
// # }
// ```
//
// # Security Warning
//
// Only use for types where raw serialization is necessary and secure.
#[macro_export]
macro_rules! fixed_exportable_alias {
    ($vis:vis $name:ident, $size:literal, $doc:literal) => {
        #[doc = $doc]
        $vis struct $name {
            pub inner: [u8; $size],
        }

        #[cfg(feature = "serde-serialize")]
        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                self.inner.serialize(serializer)
            }
        }

        #[cfg(feature = "serde-serialize")]
        impl $crate::ExportableType for $name {}

        impl From<[u8; $size]> for $name {
            fn from(arr: [u8; $size]) -> Self {
                Self { inner: arr }
            }
        }
    };
    ($vis:vis $name:ident, $size:literal) => {
        $vis struct $name {
            pub inner: [u8; $size],
        }

        #[cfg(feature = "serde-serialize")]
        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                self.inner.serialize(serializer)
            }
        }

        #[cfg(feature = "serde-serialize")]
        impl $crate::ExportableType for $name {}

        impl From<[u8; $size]> for $name {
            fn from(arr: [u8; $size]) -> Self {
                Self { inner: arr }
            }
        }
    };
}
