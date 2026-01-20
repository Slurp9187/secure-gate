//! Sealed marker trait for redacted Debug output.

/// Sealed marker trait for redacted Debug output.
pub trait Sealed {}

pub trait RedactedDebug: Sealed {}
