//! Internal macros for From implementations in secure-gate types.
//!
//! This module contains macros used to implement From traits
//! for Dynamic types without code duplication.

/// Macro to implement From traits for Dynamic types.
///
/// This generates various From impls for Dynamic, such as from slices, values, boxes, and strings.
#[macro_export(local_inner_macros)]
macro_rules! impl_from_dynamic {
    (slice) => {
        impl From<&[u8]> for Dynamic<Vec<u8>> {
            /// Wrap a byte slice in a [`Dynamic`] [`Vec<u8>`].
            #[inline(always)]
            fn from(slice: &[u8]) -> Self {
                Self::new(slice.to_vec())
            }
        }
    };
    (value) => {
        impl<T: 'static> From<T> for Dynamic<T> {
            /// Wrap a value in a [`Dynamic`] secret by boxing it.
            #[inline(always)]
            fn from(value: T) -> Self {
                Self {
                    inner: Box::new(value),
                }
            }
        }
    };
    (box) => {
        impl<T: ?Sized> From<Box<T>> for Dynamic<T> {
            /// Wrap a boxed value in a [`Dynamic`] secret.
            #[inline(always)]
            fn from(boxed: Box<T>) -> Self {
                Self { inner: boxed }
            }
        }
    };
    (str) => {
        impl From<&str> for Dynamic<String> {
            /// Wrap a string slice in a [`Dynamic`] [`String`].
            #[inline(always)]
            fn from(input: &str) -> Self {
                Self::new(input.to_string())
            }
        }
    };
}
