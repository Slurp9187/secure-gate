//! Owned zeroizing wrapper for encoded secret strings.
//!
//! > **Import path:** `use secure_gate::EncodedSecret;`
//!
//! [`EncodedSecret`] wraps `Zeroizing<String>` with `Debug` → `[REDACTED]`. It is
//! returned by every encoding method (`to_hex`, `to_base32`, `to_base64url`,
//! `try_to_bech32`, `try_to_bech32m`, and the `_sized::<N>` forms of the last two —
//! only bech32 and bech32m take a code length).
//!
//! There is no unprotected encoder variant. An encoded secret is a second full copy of
//! the secret in a longer, human-readable alphabet, so it is wiped by default; public
//! encodings (addresses, transaction IDs) come back in the same wrapper. Name
//! [`into_inner`](EncodedSecret::into_inner) when you genuinely want a plain `String`.
//!
//! This is **not** a secret wrapper like [`Fixed`](crate::Fixed) / [`Dynamic`](crate::Dynamic)
//! — it is a zeroizing `String` wrapper for encoded output. Its only accessor is
//! `Deref<Target = str>`, plus the two named consumers [`into_inner`](EncodedSecret::into_inner)
//! and [`into_zeroizing`](EncodedSecret::into_zeroizing).
//!
//! # No `Display`
//!
//! `EncodedSecret` deliberately does **not** implement `Display`, so `{}` in a format
//! string is a compile error. `Debug` printing `[REDACTED]` teaches callers that the
//! type is safe to put in a log line; a transparent `Display` on the same type would
//! then punish exactly the callers who checked. `tracing::info!("token: {tok}")` and
//! `format!("{tok}")` are the accidents worth preventing, and they are the ones a
//! missing `Display` prevents.
//!
//! Writing the encoded value out is still one deref away, and deliberately explicit:
//!
//! ```rust
//! # #[cfg(all(feature = "encoding-hex", feature = "alloc"))] {
//! use secure_gate::{Fixed, ToHex};
//!
//! let encoded = Fixed::new([0xABu8; 4]).to_hex();
//!
//! // Intentional: name the deref.
//! let line = format!("{}", &*encoded);
//! assert_eq!(line, "abababab");
//!
//! // Accidental: does not compile.
//! // let line = format!("{}", encoded);
//! # }
//! ```
//!
//! This does **not** stop copying by convenience. `Deref<Target = str>` still gives you
//! `str::to_string()` and `.to_owned()`, both of which produce an ordinary unzeroized
//! `String`. They are not, however, the hand-off, and the difference is worth knowing:
//!
//! |                       | `.to_string()` / `.to_owned()` | [`into_inner()`](EncodedSecret::into_inner) |
//! |-----------------------|--------------------------------|---------------------------------------------|
//! | What happens          | Copies into a new `String`     | Moves *this* `String` out (`mem::take`)     |
//! | The wrapper afterwards| Still held, still wiped on drop| Consumed                                    |
//! | Copies of the secret  | Two, until the wrapper drops   | One, and it is yours                        |
//! | In an audit sweep     | Noisy — a `str` method         | A named exit                                |
//!
//! So reach for `into_inner()` when an API wants an owned `String`: it is the same
//! ownership transfer as [`RevealSecret::into_inner`](crate::RevealSecret::into_inner),
//! and it leaves one copy rather than two. Treat `.to_string()` as *I copied it on
//! purpose*, and sweep for it during an encoding audit. What the type is actually for
//! is `&*encoded` into the drivers that bind `&str`. See
//! [Where accident-prevention ends](crate#where-accident-prevention-ends).

#[cfg(feature = "alloc")]
/// Owned wrapper for encoded secret strings: zeroizes on drop, redacts `Debug`, and
/// has no `Display`.
///
/// Every encoding method returns this type — `to_hex`, `to_hex_upper`, `to_base32`,
/// `to_base64url`, `try_to_bech32`, `try_to_bech32m`, and the `_sized::<N>` forms of
/// the last two (only bech32 and bech32m take a code length) — on
/// [`Fixed`](crate::Fixed), [`Dynamic`](crate::Dynamic), and any byte-shaped input.
/// There is no unprotected variant to choose between: an encoded secret is a second
/// full copy of the secret, so it is wiped by default, and
/// [`into_inner`](EncodedSecret::into_inner) is the named call that ends that.
#[must_use = "dropping EncodedSecret may immediately zeroize encoded output"]
pub struct EncodedSecret(zeroize::Zeroizing<alloc::string::String>);

#[cfg(feature = "alloc")]
impl EncodedSecret {
    #[cfg(any(
        feature = "encoding-hex",
        feature = "encoding-base32",
        feature = "encoding-base64",
        feature = "encoding-bech32",
    ))]
    #[inline(always)]
    pub(crate) fn new(s: alloc::string::String) -> Self {
        Self(zeroize::Zeroizing::new(s))
    }

    /// Consumes self and returns the inner `String`.
    ///
    /// This ends zeroization protection for the encoded output.
    #[inline(always)]
    pub fn into_inner(mut self) -> alloc::string::String {
        core::mem::take(&mut self.0)
    }

    /// Consumes self and returns the underlying `Zeroizing<String>`.
    ///
    /// This is an explicit escape hatch for APIs that name `Zeroizing<String>`.
    ///
    /// # This downgrades `Debug`
    ///
    /// Zeroize-on-drop is preserved, but redaction is not: `Zeroizing<String>` derives
    /// `Debug` (`zeroize` 1.8/1.9; a future release may change the rendering), so `{:?}`
    /// on the returned value can print the encoded secret. This crate does not
    /// re-export `zeroize`, so naming the return type means depending on a compatible
    /// `zeroize` version directly.
    #[inline(always)]
    pub fn into_zeroizing(self) -> zeroize::Zeroizing<alloc::string::String> {
        self.0
    }
}

#[cfg(feature = "alloc")]
impl core::ops::Deref for EncodedSecret {
    type Target = str;

    #[inline(always)]
    fn deref(&self) -> &str {
        &self.0
    }
}

#[cfg(feature = "alloc")]
impl core::fmt::Debug for EncodedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

// No `AsRef<str>` / `AsRef<[u8]>`: `Deref<Target = str>` already yields `&str` by
// coercion, by `&*encoded`, and through method resolution, so both impls were doors
// onto a room `Deref` already opens.
//
// Removing them did not, on its own, close the accidental re-encode: method resolution
// derefs to `str`, and `str: AsRef<[u8]>` satisfied the old encoder blanket impls, so
// `encoded.to_hex()` compiled and hex-encoded the encoded text. That reachability comes
// from `Deref`, which is the type's primary accessor and stays. The bound closed it
// instead — the encoders now require `AsRef<[u8]> + EncodableBytes`, and `str` does not
// implement `EncodableBytes`, so the second encode is a compile error. Pinned by the
// `encoded_secret_no_reencode` compile-fail test. The surviving boundary is documented
// at [Where accident-prevention ends](crate#where-accident-prevention-ends).
