// src/macros.rs
//! Ergonomic secret-handling macros.

/// Create a secret — works for fixed-size arrays and heap types.
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

/// Create a zeroizing secret (auto-wiped on drop)
#[macro_export]
macro_rules! secure_zeroizing {
    ($ty:ty, $expr:expr $(,)?) => {
        $crate::FixedZeroizing::new($expr)
    };
    (heap $ty:ty, $expr:expr $(,)?) => {
        $crate::DynamicZeroizing::new($expr)
    };
}

/// Define a fixed-size secret alias with beautiful constructor syntax
///
/// The alias gets useful methods automatically because `Fixed` implements them
/// for all array sizes (see `src/fixed.rs`).
#[macro_export]
macro_rules! fixed_alias {
    ($name:ident, $size:literal) => {
        /// Fixed-size secret of exactly `$size` bytes.
        pub type $name = $crate::Fixed<[u8; $size]>;

        // Only the type alias — no impls!
        // All methods come from the generic impls in src/fixed.rs
    };
}

/// Define a dynamic (heap) secret alias.
#[macro_export]
macro_rules! dynamic_alias {
    ($name:ident, $ty:ty) => {
        pub type $name = $crate::Dynamic<$ty>;
    };
}
