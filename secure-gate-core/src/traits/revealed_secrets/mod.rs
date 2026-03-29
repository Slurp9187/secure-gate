//! Owned wrapper types that complete the reveal model (Tier 3 owned consumption).
//!
//! These types provide strong zeroization guarantees for secrets that have been
//! intentionally extracted from a [`RevealSecret`] wrapper:
//!
//! - [`InnerSecret<T>`] — returned by [`RevealSecret::into_inner`] for raw secret values.
//! - [`EncodedSecret`] — returned by zeroizing encoding methods (`to_hex_zeroizing`,
//!   `to_base64url_zeroizing`, `try_to_bech32_zeroizing`, etc.) when the encoded form
//!   itself must remain sensitive.
//!
//! Both types wrap [`zeroize::Zeroizing`] internally, provide redacted `Debug`
//! (`[REDACTED]`), and offer an `into_zeroizing()` escape hatch. They are the
//! idiomatic way to transfer ownership while preserving the crate’s “secrets are
//! radioactive” guarantees.
//!
//! See the [3-Tier Access Model](https://github.com/Slurp9187/secure-gate/blob/main/secure-gate-core/SECURITY.md#3-tier-access-model)
//! and the [“What secure-gate does NOT protect against”](https://github.com/Slurp9187/secure-gate/blob/main/secure-gate-core/SECURITY.md#what-secure-gate-does-not-protect-against)
//! section in `SECURITY.md` for full guidance on when and how to use these types.

#[cfg(feature = "alloc")]
pub use self::encoded_secret::EncodedSecret;

mod encoded_secret;
