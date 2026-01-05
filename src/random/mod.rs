// secure-gate/src/random/mod.rs
//! Cryptographically secure random value generation with encoding conveniences (gated behind “rand” and encoding features).
//!
//! Provides `FixedRng` and `DynamicRng` types for generating fresh random bytes.
//! Includes built-in methods for encoding to Hex, Base64, Bech32, and Bech32m strings
//! without exposing secret bytes.
//!
//! # Examples
//!
//! Generate and encode random bytes:
//! ```
//! # #[cfg(all(feature = "rand", feature = "encoding-hex"))]
//! # {
//! use secure_gate::random::FixedRng;
//! let hex = FixedRng::<32>::generate().into_hex();
//! # }
//! ```
//!
//! Use with Base64:
//! ```
//! # #[cfg(all(feature = "rand", feature = "encoding-base64"))]
//! # {
//! use secure_gate::random::FixedRng;
//! let base64 = FixedRng::<32>::generate().into_base64();
//! # }
//! ```
//!
//! Encode to Bech32 or Bech32m:
//! ```
//! # #[cfg(all(feature = "rand", feature = "encoding-bech32"))]
//! # {
//! use secure_gate::random::FixedRng;
//! let bech32 = FixedRng::<32>::generate().into_bech32("example");
//! let bech32m = FixedRng::<32>::generate().into_bech32m("example");
//! # }
//! ```

pub mod dynamic_rng;
pub mod fixed_rng;

// Re-export for API compatibility
pub use dynamic_rng::DynamicRng;
pub use fixed_rng::FixedRng;
