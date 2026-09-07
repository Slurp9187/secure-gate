//! Base32 decoding trait (RFC 4648 §6, uppercase, unpadded).
//!
//! > **Import path:** `use secure_gate::FromBase32Str;`
//!
//! This trait provides secure, explicit decoding of Base32-encoded strings
//! (RFC 4648 §6 alphabet, uppercase, no padding) to byte vectors. It is designed for
//! handling untrusted input in cryptographic contexts, such as decoding `otpauth://`
//! TOTP/HOTP shared secrets or encoded keys.
//!
//! Requires the `encoding-base32` feature.
//!
//! # Security Notes
//!
//! - **Treat all input as untrusted**: validate Base32 strings upstream before
//!   wrapping in secrets. Invalid input may indicate tampering or injection attempts.
//! - **Heap allocation**: Returns `Vec<u8>` — wrap in [`Fixed`](crate::Fixed) or
//!   [`Dynamic`](crate::Dynamic) to store as a secret.
//! - **Strict validation**: uppercase RFC 4648 §6 alphabet (`A`–`Z`, `2`–`7`) only,
//!   no `=` padding, no whitespace, no non-ASCII, and the length must be ≡ 0, 2, 4, 5
//!   or 7 (mod 8) — the only lengths an unpadded Base32 string can have. Lowercase and
//!   mixed-case input is rejected; normalise upstream (`to_ascii_uppercase()`, ideally
//!   inside `zeroize::Zeroizing`, since it copies the encoded secret).
//! - **Lenient trailing bits**: non-zero bits in the final partial group are ignored
//!   rather than rejected (`"MZ"` decodes to the same byte as `"MY"`). Decoding is
//!   therefore not injective: two distinct strings can yield the same bytes. Only
//!   encoder-produced strings are canonical, so round-tripping
//!   `encode(decode(s)) == s` holds only for canonical `s`.
//!
//! # Example
//!
//! ```rust
//! # #[cfg(feature = "encoding-base32")]
//! use secure_gate::{FromBase32Str, Fixed};
//! # #[cfg(feature = "encoding-base32")]
//! {
//! // "NBSWY3DP" decodes to b"hello"
//! let bytes = "NBSWY3DP".try_from_base32().unwrap();
//! assert_eq!(bytes, b"hello");
//!
//! // Wrap result in a secret immediately
//! let secret: Fixed<[u8; 4]> = Fixed::try_from_base32("32W353Y").unwrap();
//!
//! // Error on invalid input
//! assert!("!!!!".try_from_base32().is_err());
//! }
//! ```
#[cfg(all(feature = "encoding-base32", feature = "alloc"))]
use crate::error::Base32Error;

/// Rejects encoded lengths that `base32ct` 0.2 cannot decode without panicking.
///
/// Unpadded Base32 packs 5 bytes into 8 characters, so the only trailing block
/// sizes a valid string can have are 0, 2, 4, 5 and 7 characters. `base32ct`
/// 0.2.2 sizes its output buffer from `decoded_len()` but indexes it from the
/// *input* remainder, so a remainder of 1, 3 or 6 writes past the end and panics
/// with "index out of bounds" (`base32ct-0.2.2/src/encoding.rs:105`). Upstream
/// 0.3 rejects those lengths up front, but 0.3 is edition 2024 / MSRV 1.85 and
/// cannot be used on the 0.8 line — so this crate performs the check instead.
///
/// A panic on attacker-supplied input would be a denial-of-service path in a
/// secrets crate, so this guard is a correctness requirement, not a nicety.
/// It branches only on the *encoded length*, which is public metadata already
/// observable from the input string — never on decoded secret content.
#[cfg(feature = "encoding-base32")]
#[must_use]
pub(crate) const fn encoded_len_is_decodable(len: usize) -> bool {
    matches!(len % 8, 0 | 2 | 4 | 5 | 7)
}

/// Extension trait for decoding uppercase, unpadded Base32 strings into byte vectors.
///
/// *Requires features `encoding-base32` and `alloc`.*
///
/// Blanket-implemented for all `AsRef<str>` types. Returns `Vec<u8>` — requires heap
/// allocation. For no-alloc targets, use `Fixed::try_from_base32` instead, which
/// decodes directly into a stack-allocated `[u8; N]` buffer.
///
/// Uses the RFC 4648 §6 alphabet (`A`–`Z`, `2`–`7`) without `=` padding.
///
/// **The returned `Vec<u8>` is plain heap memory and is not zeroized on drop.** Wrap
/// the result in [`Fixed`](crate::Fixed) or [`Dynamic`](crate::Dynamic) immediately
/// (or in [`zeroize::Zeroizing`]) if the decoded bytes are sensitive. Prefer
/// `Fixed::try_from_base32` / `Dynamic::try_from_base32`, which perform the
/// wrapping for you and zeroize their internal temporaries.
///
/// Treat all input as untrusted; validate lengths and content upstream before wrapping
/// decoded bytes in secrets.
#[cfg(all(feature = "encoding-base32", feature = "alloc"))]
pub trait FromBase32Str {
    /// Decodes an uppercase, unpadded Base32 string into a byte vector.
    ///
    /// # Errors
    ///
    /// - [`Base32Error::InvalidBase32`] — wrong alphabet or case, `=` padding,
    ///   whitespace, or a length that is impossible for unpadded Base32.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::FromBase32Str;
    ///
    /// // "NBSWY3DP" decodes to b"hello"
    /// let bytes = "NBSWY3DP".try_from_base32()?;
    /// assert_eq!(bytes, b"hello");
    ///
    /// assert!("nbswy3dp".try_from_base32().is_err()); // lowercase
    /// assert!("MY======".try_from_base32().is_err()); // padding
    /// assert!("!!!!".try_from_base32().is_err()); // invalid chars
    /// # Ok::<(), secure_gate::Base32Error>(())
    /// ```
    fn try_from_base32(&self) -> Result<alloc::vec::Vec<u8>, Base32Error>;
}

// Blanket impl to cover any AsRef<str> (e.g., &str, String, etc.)
// Returns Vec<u8> — alloc required.
#[cfg(all(feature = "encoding-base32", feature = "alloc"))]
impl<T: AsRef<str> + ?Sized> FromBase32Str for T {
    fn try_from_base32(&self) -> Result<alloc::vec::Vec<u8>, Base32Error> {
        use base32ct::{Base32UpperUnpadded, Encoding};
        let src = self.as_ref();
        if !encoded_len_is_decodable(src.len()) {
            return Err(Base32Error::InvalidBase32);
        }
        Base32UpperUnpadded::decode_vec(src).map_err(|_| Base32Error::InvalidBase32)
    }
}
