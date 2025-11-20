// src/macros.rs
//
// Ergonomic constructor macro + From impls

use crate::secure_gate::SecureGate;

/// Ergonomic constructor macro.
#[macro_export]
macro_rules! secure {
    ($ty:ty, $expr:expr) => {
        $crate::SecureGate::<$ty>::new($expr)
    };
    ($ty:ty, [$($val:expr),+ $(,)?]) => {
        $crate::SecureGate::<$ty>::new([$($val),+])
    };
}

/// From array sugar.
macro_rules! impl_from_array {
    ($($N:literal),*) => {$(
        impl From<[u8; $N]> for SecureGate<[u8; $N]> {
            fn from(arr: [u8; $N]) -> Self { Self::new(arr) }
        }
    )*}
}
impl_from_array!(12, 16, 24, 32, 64);
