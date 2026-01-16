//! Cryptographically secure random value generation with encoding conveniences (gated behind `rand` and encoding features).
//!
//! Provides [`FixedRandom`] and [`DynamicRandom`] types for generating fresh random bytes.
//! Includes built-in methods for encoding to Hex, Base64, Bech32, and Bech32m strings
//! without exposing secret bytes.
//!
//! # Examples
//!
//! Generate and encode random bytes:
//! ```
//! # #[cfg(all(feature = "rand", feature = "encoding-hex"))]
//! # {
//! use secure_gate::random::FixedRandom;
//! let hex = FixedRandom::<32>::generate().into_hex();
//! # }
//! ```
//!
//! Use with Base64:
//! ```
//! # #[cfg(all(feature = "rand", feature = "encoding-base64"))]
//! # {
//! use secure_gate::random::FixedRandom;
//! let base64 = FixedRandom::<32>::generate().into_base64();
//! # }
//! ```
//!
//! Encode to Bech32 or Bech32m:
//! ```
//! # #[cfg(all(feature = "rand", feature = "encoding-bech32"))]
//! # {
//! use secure_gate::random::FixedRandom;
//! let bech32 = FixedRandom::<32>::generate().try_into_bech32("example").unwrap();
//! let bech32m = FixedRandom::<32>::generate().try_into_bech32m("example").unwrap();
//! # }
//! ```

/// Dynamic random bytes generation.
#[cfg(feature = "rand")]
pub mod dynamic_random;

/// Fixed-size random bytes generation.
#[cfg(feature = "rand")]
pub mod fixed_random;

// Re-export for API compatibility
/// Re-export of [`DynamicRandom`].
#[cfg(feature = "rand")]
pub use dynamic_random::DynamicRandom;
/// Re-export of [`FixedRandom`].
#[cfg(feature = "rand")]
pub use fixed_random::FixedRandom;
