// src/macros.rs
//! Ergonomic macros for creating and aliasing secrets.
//!
//! These macros provide concise syntax for instantiating [`Fixed`], [`Dynamic`],
//! and their zeroizing variants, as well as defining type aliases for common
//! secret types.
//!
//! # Examples
//!
//! ```
//! use secure_gate::{dynamic_alias, fixed_alias, secure};
//!
//! fixed_alias!(Aes256Key, 32);
//! dynamic_alias!(Password, String);
//!
//! let key = secure!([u8; 32], [42u8; 32]);
//! let pw = secure!(String, "hunter2".to_string());
//! ```

/// Creates a secret wrapper around the given value.
///
/// Supports fixed-size byte arrays and heap-allocated types like `String` and `Vec<u8>`.
///
/// # Examples
///
/// ```
/// use secure_gate::secure;
///
/// // Fixed-size secret
/// let key = secure!([u8; 32], [42u8; 32]);
/// assert_eq!(key.expose_secret(), &[42u8; 32]);
///
/// // Heap-allocated secret
/// let pw = secure!(String, "hunter2".to_string());
/// assert_eq!(pw.expose_secret(), "hunter2");
///
/// // Alternative heap syntax
/// let data: secure_gate::Dynamic<Vec<u8>> = secure!(heap Vec<u8>, vec![1u8, 2u8, 3u8]);
/// assert_eq!(data.as_slice(), &[1u8, 2u8, 3u8]);
/// ```
#[macro_export]
macro_rules! secure {
    ([u8; $N:literal], $expr:expr $(,)?) => {
        $crate::Fixed::new($expr)
    };
    ($ty:ty, $expr:expr $(,)?) => {
        $crate::Fixed::<$ty>::new($expr)
    };
    (String, $expr:expr $(,)?) => {
        $crate::Dynamic::new($expr)
    };
    (Vec<u8>, $expr:expr $(,)?) => {
        $crate::Dynamic::new($expr)
    };
    (heap $ty:ty, $expr:expr $(,)?) => {
        $crate::Dynamic::new($expr)
    };
}

/// Creates a zeroizing secret that automatically wipes itself on drop.
///
/// Requires the `zeroize` feature.
///
/// # Examples
///
/// ```
/// use secure_gate::secure_zeroizing;
///
/// #[cfg(feature = "zeroize")]
/// {
///     use zeroize::Zeroizing;
///     use secrecy::ExposeSecret;
///
///     // Fixed-size zeroizing secret (uses zeroize::Zeroizing directly)
///     let key: Zeroizing<[u8; 32]> = secure_zeroizing!([u8; 32], [42u8; 32]);
///     assert_eq!(key[..], [42u8; 32]);
///
///     // Heap-allocated zeroizing secret
///     let pw = secure_zeroizing!(heap String, "hunter2".to_string().into_boxed_str());
///     assert_eq!(pw.expose_secret(), "hunter2");
/// }
/// ```
#[macro_export]
macro_rules! secure_zeroizing {
    ($ty:ty, $expr:expr $(,)?) => {
        $crate::FixedZeroizing::new($expr)
    };
    (heap $ty:ty, $expr:expr $(,)?) => {
        $crate::DynamicZeroizing::new($expr)
    };
}

/// Defines a type alias for a fixed-size byte secret.
///
/// The resulting type inherits all methods from [`Fixed<[u8; N]>`], including
/// constructors like `from_slice` and `From<[u8; N]>`.
///
/// # Examples
///
/// ```
/// use secure_gate::fixed_alias;
///
/// fixed_alias!(Aes256Key, 32);
///
/// let key: Aes256Key = [42u8; 32].into();
/// assert_eq!(key.expose_secret(), &[42u8; 32]);
/// ```
#[macro_export]
macro_rules! fixed_alias {
    ($name:ident, $size:literal) => {
        /// Fixed-size secret of exactly `$size` bytes.
        pub type $name = $crate::Fixed<[u8; $size]>;
    };
}

/// Defines a type alias for a dynamic (heap-allocated) secret.
///
/// The resulting type inherits all methods and conversions from [`Dynamic<T>`].
///
/// # Examples
///
/// ```
/// use secure_gate::dynamic_alias;
///
/// dynamic_alias!(Password, String);
///
/// let pw: Password = "hunter2".into();
/// assert_eq!(pw.expose_secret(), "hunter2");
/// ```
#[macro_export]
macro_rules! dynamic_alias {
    ($name:ident, $ty:ty) => {
        pub type $name = $crate::Dynamic<$ty>;
    };
}

#[macro_export]
macro_rules! random_alias {
    ($name:ident, $size:literal) => {
        pub type $name = $crate::RandomBytes<$size>;
    };
}
