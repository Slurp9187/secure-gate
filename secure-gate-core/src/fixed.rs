//! Stack-allocated wrapper for fixed-size secrets.
//!
//! [`Fixed<T>`] is a zero-cost wrapper that enforces explicit, auditable access to
//! sensitive data stored inline on the stack. It is the primary secret type for
//! fixed-length material such as cryptographic keys, nonces, and seeds.
//!
//! # Security invariants
//!
//! - **No `Deref`, `AsRef`, or `Copy`** — the inner value cannot leak through
//!   implicit conversions.
//! - **`Debug` always prints `[REDACTED]`** — secrets never appear in logs or
//!   panic messages.
//! - **Unconditional zeroization on drop** — the inner `T` is overwritten with
//!   zeroes when the wrapper is dropped, even on error paths.
//! - **Opt-in `Clone`** — requires `T: CloneableSecret` and the `cloneable` feature.
//! - **Opt-in `Serialize`/`Deserialize`** — requires marker traits and the
//!   `serde-serialize`/`serde-deserialize` features.
//! - **Avoid move-by-value for long-lived secrets.** Each move of a `Fixed<T>`
//!   bitwise-copies the bytes to a new location and leaves the original stack
//!   slot uncleared until a later frame overwrites it. Pass `&Fixed<T>` /
//!   `&mut Fixed<T>` by reference, keep the wrapper short-scope, or use
//!   [`Dynamic<T>`](crate::Dynamic) for long-lived material (heap-only — no
//!   stack residue surface). See `SECURITY.md` § "Inherent Rust Limitations".
//!
//! # Construction
//!
//! | Constructor | Notes |
//! |---|---|
//! | [`Fixed::new(value)`](Fixed::new) | Ergonomic default; `const fn`. |
//! | [`Fixed::new_with(f)`](Fixed::new_with) | Scoped — preferred for stack-residue minimization. |
//!
//! Prefer [`new_with`](Fixed::new_with) in high-assurance code: it writes directly
//! into the wrapper's storage, avoiding the intermediate stack copy that `new` may
//! produce.
//!
//! # 3-tier access model
//!
//! ```rust
//! use secure_gate::{Fixed, RevealSecret, RevealSecretMut};
//!
//! let mut secret = Fixed::new([1u8, 2, 3, 4]);
//!
//! // Tier 1 — scoped (preferred): borrow is confined to the closure.
//! let sum = secret.with_secret(|arr| arr.iter().sum::<u8>());
//! assert_eq!(sum, 10);
//!
//! // Tier 2 — direct: returns a reference. Use as an escape hatch.
//! let first: u8 = secret.expose_secret()[0];
//! assert_eq!(first, 1);
//!
//! // Tier 1 mutable — scoped mutation (preferred over Tier 2 mutable).
//! secret.with_secret_mut(|arr| arr[0] = 0xFF);
//!
//! // Tier 3 — owned: consumes the wrapper for final use.
//! let owned = secret.into_inner();
//! ```
//!
//! # Warning: no `static` secrets
//!
//! `Drop` does not run on `static` items. Placing a `Fixed` in a `static` or
//! `lazy_static!` will **skip zeroization**. Always use stack or heap allocation.
//!
//! Also ensure your profile sets `panic = "unwind"` — `panic = "abort"` skips
//! destructors and therefore skips zeroization.
//!
//! # Import path
//!
//! All public items are re-exported at the crate root. Use:
//!
//! ```rust
//! use secure_gate::Fixed;
//! ```
//!
//! Not `secure_gate::fixed::Fixed`.
//!
//! # See also
//!
//! - [`Dynamic<T>`](crate::Dynamic) — heap-allocated alternative for variable-length
//!   secrets (passwords, API keys, ciphertexts). Requires the `alloc` feature.
//!
//! # Examples
//!
//! ```rust
//! use secure_gate::{Fixed, RevealSecret};
//!
//! let secret = Fixed::new([1u8, 2, 3, 4]);
//! let sum = secret.with_secret(|arr| arr.iter().sum::<u8>());
//! assert_eq!(sum, 10);
//! ```

use crate::RevealSecret;
use crate::RevealSecretMut;

#[cfg(all(feature = "encoding-base64", feature = "alloc"))]
use crate::traits::encoding::base64_url::ToBase64Url;
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
use crate::traits::encoding::bech32::ToBech32;
#[cfg(all(feature = "encoding-bech32m", feature = "alloc"))]
use crate::traits::encoding::bech32m::ToBech32m;
#[cfg(all(feature = "encoding-hex", feature = "alloc"))]
use crate::traits::encoding::hex::ToHex;

#[cfg(feature = "rand")]
use rand::{TryCryptoRng, TryRng, rngs::SysRng};
use zeroize::Zeroize;

/// Drains a validated Bech32/Bech32m payload into a stack buffer.
///
/// Shared by the four `try_from_bech32*` constructors. Copies exactly `N`
/// payload bytes into a `Zeroizing<[u8; N]>`; keeps counting (without storing)
/// past `N` so the length-mismatch error reports the exact decoded length.
/// The iteration count is bounded by the checksum-validated input string, so
/// oversized inputs cost at most one bounded pass. Works without `alloc`.
#[cfg(any(feature = "encoding-bech32", feature = "encoding-bech32m"))]
fn drain_bech32_payload<const N: usize>(
    checked: &bech32::primitives::decode::CheckedHrpstring<'_>,
) -> Result<zeroize::Zeroizing<[u8; N]>, crate::error::Bech32Error> {
    let mut buf = zeroize::Zeroizing::new([0u8; N]);
    let mut count = 0usize;
    for byte in checked.byte_iter() {
        if count < N {
            buf[count] = byte;
        }
        count += 1;
    }
    if count != N {
        return Err(crate::error::Bech32Error::InvalidLength {
            expected: N,
            got: count,
        });
    }
    Ok(buf)
    // On the error path, buf is zeroized on drop.
}

/// Zero-cost stack-allocated wrapper for fixed-size secrets.
///
/// `Fixed<T>` stores a `T: Zeroize` value inline and unconditionally zeroizes it
/// on drop. There is no `Deref`, `AsRef`, or `Copy` — every access is explicit
/// through [`RevealSecret`] or [`RevealSecretMut`].
///
/// # Examples
///
/// ```rust
/// use secure_gate::{Fixed, RevealSecret};
///
/// // Create a secret key.
/// let key = Fixed::new([0xABu8; 32]);
///
/// // Scoped access — the borrow cannot escape the closure.
/// let first = key.with_secret(|k| k[0]);
/// assert_eq!(first, 0xAB);
///
/// // Debug is always redacted.
/// assert_eq!(format!("{:?}", key), "[REDACTED]");
/// ```
///
/// # Constructors
///
/// | Constructor | Feature | Notes |
/// |---|---|---|
/// | [`new(value)`](Self::new) | — | `const fn`, ergonomic default |
/// | [`new_with(f)`](Self::new_with) | — | Scoped; preferred for stack-residue minimization |
/// | [`From<[u8; N]>`](#impl-From<%5Bu8;+N%5D>-for-Fixed<%5Bu8;+N%5D>) | — | Equivalent to `new` |
/// | [`TryFrom<&[u8]>`](#impl-TryFrom<%26%5Bu8%5D>-for-Fixed<%5Bu8;+N%5D>) | — | Length-checked slice conversion |
/// | [`try_from_hex`](Self::try_from_hex) | `encoding-hex` | Constant-time hex decoding |
/// | [`try_from_base64url`](Self::try_from_base64url) | `encoding-base64` | Constant-time Base64url decoding |
/// | [`try_from_bech32`](Self::try_from_bech32) | `encoding-bech32` | HRP-validated Bech32 decoding |
/// | [`try_from_bech32_unchecked`](Self::try_from_bech32_unchecked) | `encoding-bech32` | Bech32 without HRP check |
/// | [`try_from_bech32m`](Self::try_from_bech32m) | `encoding-bech32m` | HRP-validated Bech32m decoding |
/// | [`try_from_bech32m_unchecked`](Self::try_from_bech32m_unchecked) | `encoding-bech32m` | Bech32m without HRP check |
/// | [`from_random()`](Self::from_random) | `rand` | System RNG |
/// | [`from_rng(rng)`](Self::from_rng) | `rand` | Custom RNG |
///
/// # See also
///
/// - [`RevealSecret`] / [`RevealSecretMut`] — the 3-tier access traits.
/// - [`new_with`](Self::new_with) — scoped constructor preferred over [`new`](Self::new).
///
/// # Note
///
/// `const fn new` compiles in `static` position, but **must not** be used there
/// because `Drop` does not run on statics, which means zeroization is skipped.
#[must_use = "Fixed<T> holds secret material; dropping it on the floor usually indicates a bug — bind with `let _name = ...` or chain a method call"]
pub struct Fixed<T: zeroize::Zeroize> {
    inner: T,
}

impl<T: zeroize::Zeroize> Fixed<T> {
    /// Creates a new [`Fixed<T>`] by wrapping a value.
    ///
    /// This is a `const fn`, so it can be evaluated at compile time. However,
    /// **do not** use it to initialize `static` items — `Drop` does not run on
    /// statics, so zeroization would be skipped.
    ///
    /// For `Fixed<[u8; N]>`, prefer [`new_with`](Fixed::new_with) when minimizing
    /// stack residue matters, as `new` may leave an intermediate copy of `value`
    /// on the caller's stack frame.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{Fixed, RevealSecret};
    ///
    /// let secret = Fixed::new([0u8; 32]);
    /// assert_eq!(secret.len(), 32);
    /// ```
    #[inline(always)]
    pub const fn new(value: T) -> Self {
        Fixed { inner: value }
    }
}

/// Converts a byte array into a [`Fixed`] wrapper (equivalent to [`Fixed::new`]).
///
/// # Examples
///
/// ```rust
/// use secure_gate::Fixed;
///
/// let secret: Fixed<[u8; 4]> = [1u8, 2, 3, 4].into();
/// ```
impl<const N: usize> From<[u8; N]> for Fixed<[u8; N]> {
    #[inline(always)]
    fn from(arr: [u8; N]) -> Self {
        Self::new(arr)
    }
}

/// Converts a byte slice into `Fixed<[u8; N]>`, failing if the length does not
/// match `N`.
///
/// Internally uses [`Fixed::new_with`] so the secret is written directly into
/// the wrapper's storage.
///
/// # Errors
///
/// Returns [`FromSliceError::InvalidLength`](crate::error::FromSliceError) when
/// `slice.len() != N`.
///
/// # Examples
///
/// ```rust
/// use secure_gate::{Fixed, RevealSecret};
///
/// // Success — exact length.
/// let data = [0xFFu8; 4];
/// let secret = Fixed::<[u8; 4]>::try_from(data.as_slice()).unwrap();
/// assert_eq!(secret.expose_secret()[0], 0xFF);
///
/// // Failure — wrong length.
/// let short = [0u8; 2];
/// assert!(Fixed::<[u8; 4]>::try_from(short.as_slice()).is_err());
/// ```
impl<const N: usize> core::convert::TryFrom<&[u8]> for Fixed<[u8; N]> {
    type Error = crate::error::FromSliceError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() != N {
            return Err(crate::error::FromSliceError::InvalidLength {
                expected: N,
                got: slice.len(),
            });
        }
        Ok(Self::new_with(|arr| arr.copy_from_slice(slice)))
    }
}

/// Construction and ergonomic encoding helpers for `Fixed<[u8; N]>`.
impl<const N: usize> Fixed<[u8; N]> {
    /// Writes directly into the wrapper's storage via a user-supplied closure,
    /// eliminating the intermediate stack copy that [`new`](Self::new) may produce.
    ///
    /// The array is zero-initialized before the closure runs. Prefer this over
    /// [`new(value)`](Self::new) when minimizing stack residue matters
    /// (long-lived keys, high-assurance environments).
    ///
    /// # Security rationale
    ///
    /// With [`Fixed::new(value)`](Self::new), the caller first builds `value` on
    /// its own stack frame, then moves it into the wrapper. The compiler *may*
    /// elide the copy, but this is not guaranteed — leaving a plaintext residue
    /// on the stack. `new_with` avoids this by giving the closure a mutable
    /// reference to the wrapper's *own* storage, so the secret is never placed
    /// anywhere else.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{Fixed, RevealSecret};
    ///
    /// // Fill from a closure — no intermediate stack copy.
    /// let secret = Fixed::<[u8; 4]>::new_with(|arr| arr.fill(0xAB));
    /// assert_eq!(secret.expose_secret(), &[0xAB; 4]);
    ///
    /// // Copy from an existing slice.
    /// let src = [1u8, 2, 3, 4];
    /// let secret = Fixed::<[u8; 4]>::new_with(|arr| arr.copy_from_slice(&src));
    /// ```
    ///
    /// # See also
    ///
    /// - [`Dynamic::new_with`](crate::Dynamic::new_with) — the heap-allocated
    ///   equivalent (requires `alloc`).
    ///
    /// If the secret will outlive the current function, prefer
    /// [`Dynamic<T>`](crate::Dynamic) over moving `Fixed<T>` around — each
    /// move-by-value leaves residue in the previous stack slot.
    #[inline(always)]
    pub fn new_with<F>(f: F) -> Self
    where
        F: FnOnce(&mut [u8; N]),
    {
        let mut this = Self { inner: [0u8; N] };
        f(&mut this.inner);
        this
    }
}

/// Hex encoding and decoding for `Fixed<[u8; N]>`.
///
/// Encoding uses a constant-time backend (`base16ct`). Decoding works with or without
/// the `alloc` feature — on no-alloc targets the bytes are decoded directly into a
/// `Zeroizing<[u8; N]>` stack buffer.
#[cfg(feature = "encoding-hex")]
impl<const N: usize> Fixed<[u8; N]> {
    /// Encodes the secret bytes as a lowercase hex string.
    ///
    /// Requires the `encoding-hex` and `alloc` features.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(all(feature = "encoding-hex", feature = "alloc"))]
    /// # {
    /// use secure_gate::Fixed;
    ///
    /// let secret = Fixed::new([0xDE, 0xAD]);
    /// assert_eq!(secret.to_hex(), "dead");
    /// # }
    /// ```
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn to_hex(&self) -> alloc::string::String {
        self.with_secret(|s: &[u8; N]| s.to_hex())
    }

    /// Encodes the secret bytes as an uppercase hex string.
    ///
    /// Requires the `encoding-hex` and `alloc` features.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(all(feature = "encoding-hex", feature = "alloc"))]
    /// # {
    /// use secure_gate::Fixed;
    ///
    /// let secret = Fixed::new([0xDE, 0xAD]);
    /// assert_eq!(secret.to_hex_upper(), "DEAD");
    /// # }
    /// ```
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn to_hex_upper(&self) -> alloc::string::String {
        self.with_secret(|s: &[u8; N]| s.to_hex_upper())
    }

    /// Encodes the secret bytes as a lowercase hex string, returning
    /// [`EncodedSecret`](crate::EncodedSecret) to preserve zeroization.
    ///
    /// Prefer this over [`to_hex`](Self::to_hex) when the encoded form should
    /// still be treated as sensitive (e.g. private keys). The returned
    /// [`EncodedSecret`](crate::EncodedSecret) is zeroized on drop.
    ///
    /// Requires the `encoding-hex` and `alloc` features.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(all(feature = "encoding-hex", feature = "alloc"))]
    /// # {
    /// use secure_gate::{Fixed, RevealSecret};
    ///
    /// let secret = Fixed::new([0xCA, 0xFE]);
    /// let encoded = secret.to_hex_zeroizing();
    /// assert_eq!(&*encoded, "cafe");
    /// // `encoded` is zeroized when it goes out of scope.
    /// # }
    /// ```
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn to_hex_zeroizing(&self) -> crate::EncodedSecret {
        self.with_secret(|s: &[u8; N]| s.to_hex_zeroizing())
    }

    /// Encodes the secret bytes as an uppercase hex string, returning
    /// [`EncodedSecret`](crate::EncodedSecret) to preserve zeroization.
    ///
    /// Requires the `encoding-hex` and `alloc` features.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(all(feature = "encoding-hex", feature = "alloc"))]
    /// # {
    /// use secure_gate::{Fixed, RevealSecret};
    ///
    /// let secret = Fixed::new([0xCA, 0xFE]);
    /// let encoded = secret.to_hex_upper_zeroizing();
    /// assert_eq!(&*encoded, "CAFE");
    /// # }
    /// ```
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn to_hex_upper_zeroizing(&self) -> crate::EncodedSecret {
        self.with_secret(|s: &[u8; N]| s.to_hex_upper_zeroizing())
    }

    /// Decodes a hex string (lowercase, uppercase, or mixed) into `Fixed<[u8; N]>`.
    ///
    /// Uses a constant-time backend (`base16ct`) for both paths.
    ///
    /// - **With `alloc`**: decodes into a `Zeroizing<Vec<u8>>` then copies onto the stack.
    ///   The temporary heap buffer is zeroed on drop even if an error occurs.
    /// - **Without `alloc`**: decodes directly into a `Zeroizing<[u8; N]>` stack buffer.
    ///   No heap allocation occurs.
    ///
    /// # Errors
    ///
    /// - [`HexError::InvalidHex`] — non-hex characters or odd-length input.
    /// - [`HexError::InvalidLength`] — decoded byte count does not equal `N`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "encoding-hex")]
    /// # {
    /// use secure_gate::{Fixed, RevealSecret};
    ///
    /// // Round-trip: encode then decode.
    /// let original = Fixed::new([0xDE, 0xAD, 0xBE, 0xEF]);
    /// # #[cfg(feature = "alloc")]
    /// # {
    /// let hex_str = original.to_hex();
    /// let decoded = Fixed::<[u8; 4]>::try_from_hex(&hex_str).unwrap();
    /// assert_eq!(decoded.expose_secret(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    /// # }
    ///
    /// // Wrong length fails.
    /// assert!(Fixed::<[u8; 2]>::try_from_hex("deadbeef").is_err());
    /// # }
    /// ```
    pub fn try_from_hex(hex: &str) -> Result<Self, crate::error::HexError> {
        #[cfg(feature = "alloc")]
        {
            use zeroize::Zeroizing;
            let bytes = Zeroizing::new(
                base16ct::mixed::decode_vec(hex.as_bytes())
                    .map_err(|_| crate::error::HexError::InvalidHex)?,
            );
            if bytes.len() != N {
                return Err(crate::error::HexError::InvalidLength {
                    expected: N,
                    got: bytes.len(),
                });
            }
            Ok(Self::new_with(|arr| arr.copy_from_slice(&bytes)))
        }
        #[cfg(not(feature = "alloc"))]
        {
            use zeroize::Zeroizing;
            // no-alloc path: decode directly into a stack buffer; no heap allocation
            // base16ct::mixed accepts upper, lower, and mixed-case hex
            let mut buf = Zeroizing::new([0u8; N]);
            let decoded = base16ct::mixed::decode(hex.as_bytes(), &mut *buf)
                .map_err(|_| crate::error::HexError::InvalidHex)?;
            if decoded.len() != N {
                return Err(crate::error::HexError::InvalidLength {
                    expected: N,
                    got: decoded.len(),
                });
            }
            Ok(Self::new_with(|arr| arr.copy_from_slice(decoded)))
            // buf is zeroized on drop (both success and error paths)
        }
    }
}

/// Base64url encoding and decoding for `Fixed<[u8; N]>`.
///
/// Encoding uses a constant-time backend (`base64ct`). Decoding works with or without
/// the `alloc` feature — on no-alloc targets the bytes are decoded directly into a
/// `Zeroizing<[u8; N]>` stack buffer.
#[cfg(feature = "encoding-base64")]
impl<const N: usize> Fixed<[u8; N]> {
    /// Encodes the secret bytes as an unpadded Base64url string (RFC 4648, URL-safe alphabet).
    ///
    /// Requires the `encoding-base64` and `alloc` features.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(all(feature = "encoding-base64", feature = "alloc"))]
    /// # {
    /// use secure_gate::Fixed;
    ///
    /// let secret = Fixed::new([0xDE, 0xAD, 0xBE, 0xEF]);
    /// let encoded = secret.to_base64url();
    /// assert_eq!(encoded, "3q2-7w");
    /// # }
    /// ```
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn to_base64url(&self) -> alloc::string::String {
        self.with_secret(|s: &[u8; N]| s.to_base64url())
    }

    /// Encodes the secret bytes as an unpadded Base64url string, returning
    /// [`EncodedSecret`](crate::EncodedSecret) to preserve zeroization.
    ///
    /// Prefer this over [`to_base64url`](Self::to_base64url) when the encoded
    /// form should still be treated as sensitive. The returned
    /// [`EncodedSecret`](crate::EncodedSecret) is zeroized on drop.
    ///
    /// Requires the `encoding-base64` and `alloc` features.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(all(feature = "encoding-base64", feature = "alloc"))]
    /// # {
    /// use secure_gate::{Fixed, RevealSecret};
    ///
    /// let secret = Fixed::new([0xDE, 0xAD, 0xBE, 0xEF]);
    /// let encoded = secret.to_base64url_zeroizing();
    /// assert_eq!(&*encoded, "3q2-7w");
    /// // `encoded` is zeroized when it goes out of scope.
    /// # }
    /// ```
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn to_base64url_zeroizing(&self) -> crate::EncodedSecret {
        self.with_secret(|s: &[u8; N]| s.to_base64url_zeroizing())
    }

    /// Decodes an unpadded Base64url string (RFC 4648, URL-safe alphabet) into
    /// `Fixed<[u8; N]>`.
    ///
    /// Uses a constant-time backend (`base64ct`) on both paths.
    ///
    /// - **With `alloc`**: decodes into a `Zeroizing<Vec<u8>>` then copies onto the stack.
    /// - **Without `alloc`**: decodes directly into a `Zeroizing<[u8; N]>` stack buffer.
    ///
    /// # Errors
    ///
    /// - [`Base64Error::InvalidBase64`] — non-base64 characters or invalid padding.
    /// - [`Base64Error::InvalidLength`] — decoded byte count does not equal `N`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "encoding-base64")]
    /// # {
    /// use secure_gate::{Fixed, RevealSecret};
    ///
    /// # #[cfg(feature = "alloc")]
    /// # {
    /// // Round-trip.
    /// let original = Fixed::new([0xDE, 0xAD, 0xBE, 0xEF]);
    /// let encoded = original.to_base64url();
    /// let decoded = Fixed::<[u8; 4]>::try_from_base64url(&encoded).unwrap();
    /// assert_eq!(decoded.expose_secret(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    /// # }
    /// # }
    /// ```
    pub fn try_from_base64url(s: &str) -> Result<Self, crate::error::Base64Error> {
        #[cfg(feature = "alloc")]
        {
            use base64ct::{Base64UrlUnpadded, Encoding};
            use zeroize::Zeroizing;
            let bytes = Zeroizing::new(
                Base64UrlUnpadded::decode_vec(s)
                    .map_err(|_| crate::error::Base64Error::InvalidBase64)?,
            );
            if bytes.len() != N {
                return Err(crate::error::Base64Error::InvalidLength {
                    expected: N,
                    got: bytes.len(),
                });
            }
            Ok(Self::new_with(|arr| arr.copy_from_slice(&bytes)))
        }
        #[cfg(not(feature = "alloc"))]
        {
            use base64ct::{Base64UrlUnpadded, Encoding};
            use zeroize::Zeroizing;
            let mut buf = Zeroizing::new([0u8; N]);
            let decoded = Base64UrlUnpadded::decode(s, &mut *buf)
                .map_err(|_| crate::error::Base64Error::InvalidBase64)?;
            if decoded.len() != N {
                return Err(crate::error::Base64Error::InvalidLength {
                    expected: N,
                    got: decoded.len(),
                });
            }
            Ok(Self::new_with(|arr| arr.copy_from_slice(decoded)))
            // buf is zeroized on drop (both success and error paths)
        }
    }
}

/// Bech32 (BIP-173) encoding and decoding for `Fixed<[u8; N]>`.
///
/// Uses the extended `Bech32Large` checksum variant (~5 KB payload limit) rather than
/// the 90-character standard limit. For Bitcoin address formats use `ToBech32m`.
#[cfg(feature = "encoding-bech32")]
impl<const N: usize> Fixed<[u8; N]> {
    /// Encodes the secret bytes as a Bech32 (BIP-173) string with the given HRP.
    ///
    /// Requires the `encoding-bech32` and `alloc` features.
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn try_to_bech32(
        &self,
        hrp: &str,
    ) -> Result<alloc::string::String, crate::error::Bech32Error> {
        self.with_secret(|s: &[u8; N]| s.try_to_bech32(hrp))
    }

    /// Encodes the secret bytes as a Bech32 string, returning
    /// [`EncodedSecret`](crate::EncodedSecret) to preserve zeroization.
    ///
    /// Requires the `encoding-bech32` and `alloc` features.
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn try_to_bech32_zeroizing(
        &self,
        hrp: &str,
    ) -> Result<crate::EncodedSecret, crate::error::Bech32Error> {
        self.with_secret(|s: &[u8; N]| s.try_to_bech32_zeroizing(hrp))
    }

    /// Decodes a Bech32 (BIP-173) string into `Fixed<[u8; N]>`, validating that the HRP
    /// matches `expected_hrp` (case-insensitive).
    ///
    /// HRP comparison is non-constant-time — this is intentional, as the HRP is public
    /// metadata, not secret material. Timing leaks on HRP mismatch are acceptable because
    /// the HRP is not secret. Prefer this over
    /// [`try_from_bech32_unchecked`](Self::try_from_bech32_unchecked) to prevent
    /// cross-protocol confusion attacks.
    ///
    /// Works without `alloc` — decodes into a stack-allocated `Zeroizing<[u8; N]>` buffer.
    pub fn try_from_bech32(s: &str, expected_hrp: &str) -> Result<Self, crate::error::Bech32Error> {
        use crate::traits::encoding::bech32::Bech32Large;
        use bech32::primitives::decode::CheckedHrpstring;
        let checked = CheckedHrpstring::new::<Bech32Large>(s)
            .map_err(|_| crate::error::Bech32Error::OperationFailed)?;
        // HRP check before any payload byte is materialized (case-insensitive
        // comparison — timing leak is acceptable since HRP is public metadata)
        if !checked.hrp().as_str().eq_ignore_ascii_case(expected_hrp) {
            return Err(crate::error::Bech32Error::UnexpectedHrp);
        }
        let buf = drain_bech32_payload::<N>(&checked)?;
        Ok(Self::new_with(|arr| arr.copy_from_slice(&*buf)))
        // buf is zeroized on drop
    }

    /// Decodes a Bech32 (BIP-173) string into `Fixed<[u8; N]>` without validating the HRP.
    ///
    /// Any valid HRP is accepted as long as the checksum is valid and the payload length
    /// equals `N`. Use [`try_from_bech32`](Self::try_from_bech32) in security-critical code
    /// to prevent cross-protocol confusion attacks.
    ///
    /// Works without `alloc` — decodes into a stack-allocated `Zeroizing<[u8; N]>` buffer.
    pub fn try_from_bech32_unchecked(s: &str) -> Result<Self, crate::error::Bech32Error> {
        use crate::traits::encoding::bech32::Bech32Large;
        use bech32::primitives::decode::CheckedHrpstring;
        let checked = CheckedHrpstring::new::<Bech32Large>(s)
            .map_err(|_| crate::error::Bech32Error::OperationFailed)?;
        let buf = drain_bech32_payload::<N>(&checked)?;
        Ok(Self::new_with(|arr| arr.copy_from_slice(&*buf)))
        // buf is zeroized on drop
    }
}

/// Bech32m (BIP-350) encoding and decoding for `Fixed<[u8; N]>`.
///
/// Uses the standard BIP-350 payload limit (~90 bytes). For large secrets
/// (ciphertexts, recipients) use `ToBech32` / `Bech32Large` instead.
#[cfg(feature = "encoding-bech32m")]
impl<const N: usize> Fixed<[u8; N]> {
    /// Encodes the secret bytes as a Bech32m (BIP-350) string with the given HRP.
    ///
    /// Requires the `encoding-bech32m` and `alloc` features.
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn try_to_bech32m(
        &self,
        hrp: &str,
    ) -> Result<alloc::string::String, crate::error::Bech32Error> {
        self.with_secret(|s: &[u8; N]| s.try_to_bech32m(hrp))
    }

    /// Encodes the secret bytes as a Bech32m string, returning
    /// [`EncodedSecret`](crate::EncodedSecret) to preserve zeroization.
    ///
    /// Requires the `encoding-bech32m` and `alloc` features.
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn try_to_bech32m_zeroizing(
        &self,
        hrp: &str,
    ) -> Result<crate::EncodedSecret, crate::error::Bech32Error> {
        self.with_secret(|s: &[u8; N]| s.try_to_bech32m_zeroizing(hrp))
    }

    /// Decodes a Bech32m (BIP-350) string into `Fixed<[u8; N]>`, validating that the HRP
    /// matches `expected_hrp` (case-insensitive).
    ///
    /// HRP comparison is non-constant-time — this is intentional, as the HRP is public
    /// metadata, not secret material. Timing leaks on HRP mismatch are acceptable because
    /// the HRP is not secret. Prefer this over
    /// [`try_from_bech32m_unchecked`](Self::try_from_bech32m_unchecked) to prevent
    /// cross-protocol confusion attacks.
    ///
    /// Works without `alloc` — decodes into a stack-allocated `Zeroizing<[u8; N]>` buffer.
    pub fn try_from_bech32m(
        s: &str,
        expected_hrp: &str,
    ) -> Result<Self, crate::error::Bech32Error> {
        use bech32::{Bech32m, primitives::decode::CheckedHrpstring};
        let checked = CheckedHrpstring::new::<Bech32m>(s)
            .map_err(|_| crate::error::Bech32Error::OperationFailed)?;
        // HRP check before any payload byte is materialized (case-insensitive
        // comparison — timing leak is acceptable since HRP is public metadata)
        if !checked.hrp().as_str().eq_ignore_ascii_case(expected_hrp) {
            return Err(crate::error::Bech32Error::UnexpectedHrp);
        }
        let buf = drain_bech32_payload::<N>(&checked)?;
        Ok(Self::new_with(|arr| arr.copy_from_slice(&*buf)))
        // buf is zeroized on drop
    }

    /// Decodes a Bech32m (BIP-350) string into `Fixed<[u8; N]>` without validating the HRP.
    ///
    /// Any valid HRP is accepted as long as the checksum is valid and the payload length
    /// equals `N`. Use [`try_from_bech32m`](Self::try_from_bech32m) in security-critical
    /// code to prevent cross-protocol confusion attacks.
    ///
    /// Works without `alloc` — decodes into a stack-allocated `Zeroizing<[u8; N]>` buffer.
    pub fn try_from_bech32m_unchecked(s: &str) -> Result<Self, crate::error::Bech32Error> {
        use bech32::{Bech32m, primitives::decode::CheckedHrpstring};
        let checked = CheckedHrpstring::new::<Bech32m>(s)
            .map_err(|_| crate::error::Bech32Error::OperationFailed)?;
        let buf = drain_bech32_payload::<N>(&checked)?;
        Ok(Self::new_with(|arr| arr.copy_from_slice(&*buf)))
        // buf is zeroized on drop
    }
}

/// Explicit access to immutable [`Fixed<[T; N]>`] contents.
impl<const N: usize, T: zeroize::Zeroize> RevealSecret for Fixed<[T; N]> {
    type Inner = [T; N];

    #[inline(always)]
    fn with_secret<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[T; N]) -> R,
    {
        f(&self.inner)
    }

    #[inline(always)]
    fn expose_secret(&self) -> &[T; N] {
        &self.inner
    }

    #[inline(always)]
    fn len(&self) -> usize {
        N
    }

    #[inline(always)]
    fn byte_len(&self) -> usize {
        N * core::mem::size_of::<T>()
    }

    /// Consumes `self` and returns the inner `[T; N]` wrapped in [`crate::InnerSecret`].
    ///
    /// Zero cost — no allocation. The sentinel placed in `self.inner` is
    /// `[T::default(); N]` via [`crate::SentinelValue`] (already zeroed for `u8`),
    /// so `Fixed::drop` zeroizes an already-zero array — a harmless no-op.
    /// Works for **any** array length `N` (not limited to 32 like `Default`).
    ///
    /// See [`RevealSecret::into_inner`] for full documentation including the
    /// `SentinelValue` bound rationale and redacted `Debug` behavior.
    #[inline(always)]
    fn into_inner(mut self) -> crate::InnerSecret<[T; N]>
    where
        Self: Sized,
        Self::Inner: Sized + crate::SentinelValue + zeroize::Zeroize,
    {
        // Replace inner with the sentinel so Fixed::drop zeroizes a harmless
        // placeholder while the caller receives the real secret.
        let inner = core::mem::replace(&mut self.inner, crate::SentinelValue::sentinel_value());
        crate::InnerSecret::new(inner)
    }
}

/// Explicit access to mutable [`Fixed<[T; N]>`] contents.
impl<const N: usize, T: zeroize::Zeroize> RevealSecretMut for Fixed<[T; N]> {
    #[inline(always)]
    fn with_secret_mut<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut [T; N]) -> R,
    {
        f(&mut self.inner)
    }

    #[inline(always)]
    fn expose_secret_mut(&mut self) -> &mut [T; N] {
        &mut self.inner
    }
}

#[cfg(feature = "rand")]
impl<const N: usize> Fixed<[u8; N]> {
    /// Fills a new `[u8; N]` with cryptographically secure random bytes and wraps it.
    ///
    /// Uses the system RNG ([`SysRng`](rand::rngs::SysRng)). Requires the `rand` feature.
    /// Heap-free and works in `no_std` / `no_alloc` builds.
    ///
    /// # Panics
    ///
    /// Panics if the system RNG fails to provide bytes ([`TryRng::try_fill_bytes`](rand::TryRng::try_fill_bytes)
    /// returns `Err`). This is treated as a fatal environment error.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "rand")]
    /// use secure_gate::{Fixed, RevealSecret};
    ///
    /// # #[cfg(feature = "rand")]
    /// # {
    /// let key: Fixed<[u8; 32]> = Fixed::from_random();
    /// assert_eq!(key.len(), 32);
    /// # }
    /// ```
    #[inline]
    pub fn from_random() -> Self {
        Self::new_with(|arr| {
            SysRng
                .try_fill_bytes(arr)
                .expect("SysRng failure is a program error");
        })
    }

    /// Fills a new `[u8; N]` from `rng` and wraps it.
    ///
    /// Accepts any [`TryCryptoRng`](rand::TryCryptoRng) + [`TryRng`](rand::TryRng) — for example,
    /// a seeded [`StdRng`](rand::rngs::StdRng) for deterministic tests. Requires the `rand`
    /// feature. Heap-free.
    ///
    /// # Errors
    ///
    /// Returns `R::Error` if [`try_fill_bytes`](rand::TryRng::try_fill_bytes) fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "rand")]
    /// # {
    /// use rand::rngs::StdRng;
    /// use rand::SeedableRng;
    /// use secure_gate::Fixed;
    ///
    /// let mut rng = StdRng::from_seed([1u8; 32]);
    /// let key: Fixed<[u8; 16]> = Fixed::from_rng(&mut rng).expect("rng fill");
    /// # }
    /// ```
    #[inline]
    pub fn from_rng<R: TryRng + TryCryptoRng>(rng: &mut R) -> Result<Self, R::Error> {
        let mut result = Ok(());
        let this = Self::new_with(|arr| {
            result = rng.try_fill_bytes(arr);
        });
        result.map(|_| this) // on Err, `this` drops → zeroizes any partial fill
    }
}

/// Constant-time equality for `Fixed<T>` — routes through [`expose_secret()`](crate::RevealSecret::expose_secret).
///
/// `==` is **deliberately not implemented** on `Fixed`. Always use `ct_eq`.
///
/// ```rust
/// # #[cfg(feature = "ct-eq")]
/// # {
/// use secure_gate::{Fixed, ConstantTimeEq};
///
/// let a = Fixed::new([1u8; 4]);
/// let b = Fixed::new([1u8; 4]);
/// let c = Fixed::new([2u8; 4]);
/// assert!(a.ct_eq(&b));
/// assert!(!a.ct_eq(&c));
/// # }
/// ```
#[cfg(feature = "ct-eq")]
impl<T: zeroize::Zeroize> crate::ConstantTimeEq for Fixed<T>
where
    T: crate::ConstantTimeEq,
    Self: crate::RevealSecret<Inner = T>,
{
    fn ct_eq(&self, other: &Self) -> bool {
        self.expose_secret().ct_eq(other.expose_secret())
    }
}

/// Always prints `[REDACTED]` — secrets never appear in debug output.
///
/// ```rust
/// use secure_gate::Fixed;
///
/// let key = Fixed::new([0xABu8; 32]);
/// assert_eq!(format!("{:?}", key), "[REDACTED]");
/// ```
impl<T: zeroize::Zeroize> core::fmt::Debug for Fixed<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Opt-in cloning — requires `cloneable` feature and [`CloneableSecret`](crate::CloneableSecret)
/// marker on the inner type. Each clone is independently zeroized on drop, but cloning
/// increases the in-memory exposure surface. Use sparingly.
#[cfg(feature = "cloneable")]
impl<T: zeroize::Zeroize + crate::CloneableSecret> Clone for Fixed<T> {
    fn clone(&self) -> Self {
        Self::new(self.inner.clone())
    }
}

/// Opt-in serialization — requires `serde-serialize` feature and
/// [`SerializableSecret`](crate::SerializableSecret) marker on the inner type.
/// Serialization exposes the full secret — audit every impl.
#[cfg(feature = "serde-serialize")]
impl<T: zeroize::Zeroize + crate::SerializableSecret> serde::Serialize for Fixed<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.inner.serialize(serializer)
    }
}

/// Deserialization uses `Zeroizing`-wrapped temporary buffers — zeroized even on rejection.
///
/// The sequence buffer is pre-allocated to exactly `N` bytes and **never grows**: an
/// input sequence longer than `N` is rejected before the element that would trigger a
/// reallocation is stored. This matters because a `Vec` reallocation frees the old
/// buffer — which would already hold `N` secret bytes — without zeroizing it.
///
/// The entry point is `deserialize_seq` (unchanged wire format for non-self-describing
/// formats such as bincode), but the visitor also accepts byte strings via
/// `visit_bytes` / `visit_byte_buf`, so self-describing formats that encode byte
/// arrays as byte strings (e.g. CBOR) round-trip too. Owned buffers handed over
/// through `visit_byte_buf` are zeroized after the copy.
#[cfg(feature = "serde-deserialize")]
impl<'de, const N: usize> serde::Deserialize<'de> for Fixed<[u8; N]> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use core::fmt;
        use serde::de::Visitor;
        struct FixedVisitor<const M: usize>;
        impl<'de, const M: usize> Visitor<'de> for FixedVisitor<M> {
            type Value = Fixed<[u8; M]>;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "a byte array of length {}", M)
            }
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut vec: zeroize::Zeroizing<alloc::vec::Vec<u8>> =
                    zeroize::Zeroizing::new(alloc::vec::Vec::with_capacity(M));
                while let Some(value) = seq.next_element()? {
                    // Reject over-length input *before* pushing past the reserved
                    // capacity: growing would realloc and free the old buffer
                    // (already holding M secret bytes) without zeroization.
                    if vec.len() == M {
                        return Err(serde::de::Error::invalid_length(M + 1, &self));
                    }
                    vec.push(value);
                }
                if vec.len() != M {
                    return Err(serde::de::Error::invalid_length(vec.len(), &self));
                }
                Ok(Fixed::new_with(|arr| arr.copy_from_slice(&vec)))
            }
            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() != M {
                    return Err(serde::de::Error::invalid_length(v.len(), &self));
                }
                Ok(Fixed::new_with(|arr| arr.copy_from_slice(v)))
            }
            fn visit_byte_buf<E>(self, v: alloc::vec::Vec<u8>) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                // Take ownership under Zeroizing so the deserializer-provided
                // buffer is wiped after the copy — the default forwarding impl
                // would drop it unzeroized.
                let v = zeroize::Zeroizing::new(v);
                self.visit_bytes(&v)
            }
        }
        deserializer.deserialize_seq(FixedVisitor::<N>)
    }
}

/// Zeroizes the inner value. Called automatically by [`Drop`].
///
/// **Warning:** zeroization does not run for `static` items or under `panic = "abort"`.
impl<T: zeroize::Zeroize> zeroize::Zeroize for Fixed<T> {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

/// Unconditionally zeroizes the inner value when the wrapper is dropped.
///
/// **Warning:** `Drop` does not run for `static` items or under `panic = "abort"`.
impl<T: zeroize::Zeroize> Drop for Fixed<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Marker confirming that `Fixed<T>` always zeroizes on drop.
impl<T: zeroize::Zeroize> zeroize::ZeroizeOnDrop for Fixed<T> {}
