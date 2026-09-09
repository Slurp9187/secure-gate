//! The output wrapper for encoded secret material.
//!
//! > **Import path:** `use secure_gate::EncodedSecret;`
//!
//! [`RevealSecret::into_inner`](crate::RevealSecret::into_inner) hands back the plain
//! value and ends protection, because
//! the caller has decided to own it. Encoding is the one case that still needs a wrapper:
//! the encoded form is a *second full copy* of the secret in a different alphabet, and it
//! is worth keeping wiped until it drops.
//!
//! - [`EncodedSecret`] — returned by every encoding method: `to_hex`, `to_hex_upper`,
//!   `to_base32`, `to_base64url`, `try_to_bech32`, `try_to_bech32m`, and the
//!   `_sized::<N>` forms of the last two. Only bech32 and bech32m take a code length.
//!
//! It wraps [`zeroize::Zeroizing`] internally, provides redacted `Debug` (`[REDACTED]`),
//! and offers an `into_zeroizing()` escape hatch that keeps the wiping but not the
//! redaction. It is the idiomatic way to hand off
//! encoded output while preserving the crate’s “secrets are radioactive”
//! guarantees.
//!
//! See the [3-Tier Access Model](https://github.com/Slurp9187/secure-gate/blob/release/0.8/SECURITY.md#3-tier-access-model)
//! and the [“What secure-gate does NOT protect against”](https://github.com/Slurp9187/secure-gate/blob/release/0.8/SECURITY.md#what-secure-gate-does-not-protect-against)
//! section in `SECURITY.md` for full guidance on when and how to use this type.

#[cfg(feature = "alloc")]
pub use self::encoded_secret::EncodedSecret;

mod encoded_secret;
