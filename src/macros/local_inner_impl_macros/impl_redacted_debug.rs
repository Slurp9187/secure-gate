//! Internal macros for secure-gate types.
//!
//! This module contains macros used to implement common traits
//! across Fixed and Dynamic types without code duplication.

/// Macro to implement redacted Debug for secret wrapper types.
///
/// This ensures that all secret types display as "[REDACTED]" in debug output,
/// preventing accidental logging of sensitive data.
#[doc(hidden)]
#[macro_export(local_inner_macros)] // Optional: allows inner macros if recursive
macro_rules! impl_redacted_debug {
    ($type:ty) => {
        /// Debug implementation (always redacted).
        impl<T> core::fmt::Debug for $type {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("[REDACTED]")
            }
        }
    };
    ($type:ty, ?Sized) => {
        /// Debug implementation (always redacted).
        impl<T: ?Sized> core::fmt::Debug for $type {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("[REDACTED]")
            }
        }
    };
}
