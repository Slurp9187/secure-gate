// uncomment for doctest runs
// #![doc = include_str!("../EXAMPLES.md")]
// #![doc = include_str!("../README.md")]
// Forbid unsafe code unconditionally
#![forbid(unsafe_code)]

//! Zero-cost secure wrappers for secrets — [`Dynamic<T>`] for heap-allocated variable-length data,
//! [`Fixed<T>`] for stack-allocated fixed-size data.
//!
//! This crate provides explicit, guarded wrappers for sensitive values (e.g. keys, tokens, ciphertexts)
//! with controlled exposure via [`ExposeSecret`] and [`ExposeSecretMut`].
//! No accidental leaks via `Deref`, `AsRef`, or implicit conversions. Secrets are zeroized on drop.
//!
//! Decoding errors are hardened for security: debug builds show detailed context (e.g., expected vs. actual lengths);
//! release builds show generic messages to prevent information leaks.
//!
//! # Examples
//!
//! Basic usage with [`Fixed`] for stack-allocated secrets (no features needed):
//!
//! ```rust
//! use secure_gate::{Fixed, ExposeSecret};
//!
//! // Wrap a fixed-size secret (e.g., a 32-byte key)
//! let secret = Fixed::<[u8; 32]>::new([42; 32]);
//!
//! // Expose temporarily for use
//! let first_byte = secret.expose_secret()[0];
//! assert_eq!(first_byte, 42);
//! ```
//!
//! With `alloc` feature for [`Dynamic`] heap-allocated secrets:
//!
//! ```rust
//! # #[cfg(feature = "alloc")]
//! use secure_gate::{Dynamic, ExposeSecret};
//!
//! # #[cfg(feature = "alloc")]
//! {
//! // Wrap variable-length data
//! let secret: Dynamic<Vec<u8>> = Dynamic::new(vec![1, 2, 3, 4]);
//!
//! // Scoped access with zeroize
//! let sum: u8 = secret.with_secret(|exposed| exposed.iter().sum());
//! assert_eq!(sum, 10);
//! # }
//! ```
//!
//! With encoding features for decoding:
//!
//! ```rust
//! # #[cfg(feature = "encoding-hex")]
//! use secure_gate::{Fixed, FromHexStr, ExposeSecret};
//!
//! # #[cfg(feature = "encoding-hex")]
//! {
//! // Decode hex string to fixed-size secret
//! let secret = Fixed::<[u8; 4]>::try_from_hex("01234567").unwrap();
//! assert_eq!(secret.expose_secret(), &[0x01, 0x23, 0x45, 0x67]);
//! # }
//! ```
//!
//! # Feature flags
//!
//! - `secure` (default): Enables `zeroize` and `alloc` for secure wiping and heap allocation.
//! - `ct-eq`: Enables [`ConstantTimeEq`] for direct constant-time equality.
//! - `ct-eq-hash`: Enables [`ConstantTimeEqExt`] for hash-based probabilistic equality.
//! - `encoding-hex`: Enables hex encoding/decoding traits.
//! - `encoding-base64`: Enables base64url encoding/decoding traits.
//! - `encoding-bech32`: Enables bech32 encoding/decoding traits.
//! - `encoding-bech32m`: Enables bech32m (BIP-350) encoding/decoding traits.
//! - `rand`: Enables random key generation.
//! - `cloneable`: Enables [`CloneableSecret`] for cloning secrets.
//! - `serde-serialize`: Enables [`SerializableSecret`] for Serde serialization.
//! - `full`: Enables all features except `no-alloc`.
//! - `no-alloc`: Disables heap allocation for `no_std` environments.
//!
//! # Security
//!
//! - Secrets are zeroized on drop using `zeroize`.
//! - Explicit access prevents accidental exposure.
//! - Timing-safe equality options available.
//! - No unsafe code.
//!
//! See [`SECURITY.md`](https://github.com/Slurp9187/secure-gate/blob/main/SECURITY.md) for details.
//!
//! # no_std and alloc
//!
//! This crate is `no_std` compatible. Enable `alloc` for heap-allocated [`Dynamic`] secrets.
//! Use `no-alloc` for pure stack allocation.

// Note: Enabling both 'alloc' and 'no-alloc' allows 'alloc' to take precedence.
// This is permitted for docs.rs compatibility (--all-features) but should be avoided in normal builds.
// Prefer using 'no-alloc' alone for true no-heap builds.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod dynamic;

/// Fixed-size secret wrapper types - always available with zero dependencies.
/// These provide fundamental secure storage abstractions for fixed-size data.
mod fixed;

/// Centralized error types - always available.
mod error;

/// Core traits for wrapper polymorphism - always available.
mod traits;

#[cfg(feature = "alloc")]
/// Zero-cost heap-allocated secret wrapper with explicit access and zeroize.
///
/// Provides secure storage for variable-length sensitive data (e.g., keys, tokens).
/// Requires `alloc` feature. See [`Dynamic`] for methods.
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "alloc")]
/// use secure_gate::{Dynamic, ExposeSecret};
///
/// # #[cfg(feature = "alloc")]
/// {
/// let secret: Dynamic<Vec<u8>> = Dynamic::new(vec![1, 2, 3]);
/// let len = secret.len();
/// assert_eq!(len, 3);
/// # }
/// ```
pub use dynamic::Dynamic;

/// Zero-cost stack-allocated secret wrapper with explicit access and zeroize.
///
/// Provides secure storage for fixed-size sensitive data (e.g., keys, nonces).
/// Always available. See [`Fixed`] for methods.
///
/// # Examples
///
/// ```rust
/// use secure_gate::{Fixed, ExposeSecret};
///
/// let secret = Fixed::<[u8; 32]>::new([0; 32]);
/// let len = secret.len();
/// assert_eq!(len, 32);
/// ```
pub use fixed::Fixed;

#[cfg(feature = "cloneable")]
/// Marker trait for secrets that can be cloned.
///
/// Enables cloning of wrapped secrets. Requires `cloneable` feature.
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "cloneable")]
/// use secure_gate::{Fixed, CloneableSecret};
///
/// # #[cfg(feature = "cloneable")]
/// {
/// #[derive(Clone)]
/// struct MyKey([u8; 4]);
///
/// impl CloneableSecret for MyKey {}
///
/// let secret = Fixed::new(MyKey([1, 2, 3, 4]));
/// let cloned = secret.clone();  // Cloning enabled for MyKey
/// # }
/// ```
pub use traits::CloneableSecret;

/// Constant-time equality for secrets.
///
/// Provides `ct_eq()` method for timing-safe comparison using `subtle`.
/// Best for small secrets (< 256 bytes). Requires `ct-eq` feature.
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "ct-eq")]
/// use secure_gate::{Fixed, ConstantTimeEq};
///
/// # #[cfg(feature = "ct-eq")]
/// {
/// let a = Fixed::<[u8; 4]>::new([1, 2, 3, 4]);
/// let b = Fixed::<[u8; 4]>::new([1, 2, 3, 4]);
/// assert!(a.ct_eq(&b));
/// # }
/// ```
#[cfg(feature = "ct-eq")]
pub use traits::ConstantTimeEq;

#[cfg(feature = "ct-eq-hash")]
/// Probabilistic constant-time equality using BLAKE3 hash.
///
/// Provides `ct_eq_hash()` method for large/variable secrets via hash comparison.
/// Faster than direct for > 256 bytes, with length hiding. Requires `ct-eq-hash` feature.
/// Optional keyed mode with `rand` feature.
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "ct-eq-hash")]
/// use secure_gate::{Fixed, ConstantTimeEqExt};
///
/// # #[cfg(feature = "ct-eq-hash")]
/// {
/// let a = Fixed::<[u8; 32]>::new([1; 32]);
/// let b = Fixed::<[u8; 32]>::new([1; 32]);
/// assert!(a.ct_eq_hash(&b));
/// # }
/// ```
pub use traits::ConstantTimeEqExt;

/// Explicit access to immutable secret contents.
///
/// Provides `expose_secret()` and `with_secret()` methods for controlled exposure.
/// Always available.
///
/// # Examples
///
/// ```rust
/// use secure_gate::{Fixed, ExposeSecret};
///
/// let secret = Fixed::<[u8; 4]>::new([1, 2, 3, 4]);
/// let first = secret.expose_secret()[0];
/// assert_eq!(first, 1);
///
/// let sum = secret.with_secret(|s| s.iter().sum::<u8>());
/// assert_eq!(sum, 10);
/// ```
pub use traits::ExposeSecret;

#[cfg(feature = "serde-serialize")]
/// Marker trait for secrets that can be serialized with Serde.
///
/// Enables serialization of wrapped secrets. Requires `serde-serialize` feature.
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "serde-serialize")]
/// use secure_gate::{Fixed, SerializableSecret};
/// # #[cfg(feature = "serde-serialize")]
/// use serde::{Serialize, Deserialize};
/// # #[cfg(feature = "serde-serialize")]
/// use serde_json;
///
/// # #[cfg(feature = "serde-serialize")]
/// {
/// #[derive(Serialize, Deserialize)]
/// struct MySecret([u8; 4]);
///
/// impl SerializableSecret for MySecret {}
///
/// let secret = Fixed::new(MySecret([1, 2, 3, 4]));
/// let json = serde_json::to_string(&secret).unwrap();
/// // Note: serialization exposes the secret
/// # }
/// ```
pub use traits::SerializableSecret;

/// Explicit access to mutable secret contents.
///
/// Provides `expose_secret_mut()` and `with_secret_mut()` methods for controlled mutable exposure.
/// Always available.
///
/// # Examples
///
/// ```rust
/// use secure_gate::{Fixed, ExposeSecretMut, ExposeSecret};
///
/// let mut secret = Fixed::<[u8; 4]>::new([1, 2, 3, 4]);
/// secret.with_secret_mut(|s| s[0] = 42);
/// assert_eq!(secret.expose_secret()[0], 42);
/// ```
pub use traits::ExposeSecretMut;

// Type alias macros (always available).
// Convenient macros for creating custom secret wrapper types.
mod macros;

#[cfg(feature = "encoding-base64")]
/// Base64url string decoding trait.
///
/// Provides `try_from_base64url()` method for decoding base64url strings to byte vectors.
/// Requires `encoding-base64` feature.
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "encoding-base64")]
/// use secure_gate::FromBase64UrlStr;
///
/// # #[cfg(feature = "encoding-base64")]
/// {
/// let bytes = "AQIDBA".try_from_base64url().unwrap();
/// assert_eq!(bytes, vec![1, 2, 3, 4]);
/// # }
/// ```
///
/// # Errors
///
/// Returns [`Base64Error`] on invalid base64 or length mismatches.
pub use traits::FromBase64UrlStr;

#[cfg(feature = "encoding-bech32")]
/// Bech32 string decoding trait.
///
/// Provides `try_from_bech32()` method for decoding bech32 strings.
/// Requires `encoding-bech32` feature.
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "encoding-bech32")]
/// use secure_gate::FromBech32Str;
///
/// # #[cfg(feature = "encoding-bech32")]
/// {
/// let result = "test1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty".try_from_bech32();
/// // result contains (hrp, data) if valid
/// # }
/// ```
///
/// # Errors
///
/// Returns [`Bech32Error`] on invalid bech32 or unexpected HRP.
pub use traits::FromBech32Str;

#[cfg(any(feature = "encoding-bech32", feature = "encoding-bech32m"))]
/// Bech32m (BIP-350) string decoding trait.
///
/// Provides `try_from_bech32m()` method for decoding bech32m strings.
/// Requires `encoding-bech32` or `encoding-bech32m` feature.
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "encoding-bech32m")]
/// use secure_gate::FromBech32mStr;
///
/// # #[cfg(feature = "encoding-bech32m")]
/// {
/// let (hrp, data) = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0".try_from_bech32m().unwrap();
/// assert_eq!(hrp, "bc");
/// # }
/// ```
///
/// # Errors
///
/// Returns [`Bech32Error`] on invalid bech32m or unexpected HRP.
pub use traits::FromBech32mStr;

#[cfg(feature = "encoding-hex")]
/// Hex string decoding trait.
///
/// Provides `try_from_hex()` method for decoding hex strings to byte vectors.
/// Requires `encoding-hex` feature.
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "encoding-hex")]
/// use secure_gate::FromHexStr;
///
/// # #[cfg(feature = "encoding-hex")]
/// {
/// let bytes = "01234567".try_from_hex().unwrap();
/// assert_eq!(bytes, vec![0x01, 0x23, 0x45, 0x67]);
/// # }
/// ```
///
/// # Errors
///
/// Returns [`HexError`] on invalid hex or length mismatches.
pub use traits::FromHexStr;

#[cfg(feature = "encoding-base64")]
/// Base64url encoding trait.
///
/// Provides `to_base64url()` method for encoding byte slices to base64url strings.
/// Requires `encoding-base64` feature.
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "encoding-base64")]
/// use secure_gate::ToBase64Url;
///
/// # #[cfg(feature = "encoding-base64")]
/// {
/// let b64 = [1, 2, 3, 4].to_base64url();
/// assert_eq!(b64, "AQIDBA");
/// # }
/// ```
pub use traits::ToBase64Url;

#[cfg(feature = "encoding-bech32")]
/// Bech32 encoding trait.
///
/// Provides `to_bech32()` method for encoding byte slices to bech32 strings.
/// Requires `encoding-bech32` feature.
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "encoding-bech32")]
/// use secure_gate::ToBech32;
///
/// # #[cfg(feature = "encoding-bech32")]
/// {
/// let bech32 = [0, 1, 2].to_bech32("bc");
/// assert!(bech32.starts_with("bc1"));
/// # }
/// ```
pub use traits::ToBech32;

#[cfg(any(feature = "encoding-bech32", feature = "encoding-bech32m"))]
/// Bech32m (BIP-350) encoding trait.
///
/// Provides `to_bech32m()` method for encoding byte slices to bech32m strings.
/// Requires `encoding-bech32` or `encoding-bech32m` feature.
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "encoding-bech32m")]
/// use secure_gate::ToBech32m;
///
/// # #[cfg(feature = "encoding-bech32m")]
/// {
/// let bech32m = [0, 1, 2].to_bech32m("bc");
/// // bech32m is a BIP-350 encoded string
/// # }
/// ```
pub use traits::ToBech32m;

#[cfg(feature = "encoding-hex")]
/// Hex encoding trait.
///
/// Provides `to_hex()` method for encoding byte slices to hex strings.
/// Requires `encoding-hex` feature.
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "encoding-hex")]
/// use secure_gate::ToHex;
///
/// # #[cfg(feature = "encoding-hex")]
/// {
/// let hex = [0x01, 0x23, 0x45, 0x67].to_hex();
/// assert_eq!(hex, "01234567");
/// # }
/// ```
pub use traits::ToHex;

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32",
    feature = "encoding-bech32m"
))]
/// Marker trait for types supporting secure decoding.
///
/// Combines decoding traits for convenience. Requires encoding features.
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "encoding-hex")]
/// use secure_gate::{SecureDecoding, FromHexStr};
///
/// # #[cfg(feature = "encoding-hex")]
/// {
/// // Vec<u8> implements SecureDecoding with hex
/// let bytes = "01234567".try_from_hex().unwrap();
/// assert_eq!(bytes, vec![0x01, 0x23, 0x45, 0x67]);
/// # }
/// ```
pub use traits::SecureDecoding;

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
/// Marker trait for types supporting secure encoding.
///
/// Combines encoding traits for convenience. Requires encoding features.
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "encoding-hex")]
/// use secure_gate::{SecureEncoding, ToHex};
///
/// # #[cfg(feature = "encoding-hex")]
/// {
/// // &[u8] implements SecureEncoding with hex
/// let hex = [0x01, 0x23, 0x45, 0x67].to_hex();
/// assert_eq!(hex, "01234567");
/// # }
/// ```
pub use traits::SecureEncoding;

/// Error type for bech32 and bech32m decoding failures.
///
/// Debug builds show details (e.g., expected HRP), release builds show generic messages.
/// Requires `encoding-bech32` or `encoding-bech32m` feature.
///
/// See [`Bech32Error`] for variants.
#[cfg(feature = "encoding-bech32")]
pub use error::Bech32Error;

/// Error type for base64url decoding failures.
///
/// Debug builds show details (e.g., expected length), release builds show generic messages.
/// Requires `encoding-base64` feature.
///
/// See [`Base64Error`] for variants.
#[cfg(feature = "encoding-base64")]
pub use error::Base64Error;

/// Error type for hex decoding failures.
///
/// Debug builds show details (e.g., expected length), release builds show generic messages.
/// Requires `encoding-hex` feature.
///
/// See [`HexError`] for variants.
#[cfg(feature = "encoding-hex")]
pub use error::HexError;

/// Error type for slice-to-array conversions.
///
/// Always available.
pub use error::FromSliceError;

/// Unified error type for decoding operations.
///
/// Debug builds show details, release builds show generic messages.
/// Always available.
///
/// See [`DecodingError`] for variants.
pub use error::DecodingError;
