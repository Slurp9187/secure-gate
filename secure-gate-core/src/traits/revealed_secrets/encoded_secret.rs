//! Owned zeroizing wrapper for encoded secret strings.
//!
//! > **Import path:** `use secure_gate::EncodedSecret;`
//!
//! [`EncodedSecret`] wraps `Zeroizing<String>` with `Debug` → `[REDACTED]`. It is
//! returned by all `*_zeroizing` encoding methods (`to_hex_zeroizing`,
//! `to_base64url_zeroizing`, `try_to_bech32_zeroizing`, etc.).
//!
//! Prefer zeroizing variants when the encoded form is sensitive (private keys, tokens).
//! Use plain `String` variants for public encodings (addresses, transaction IDs).
//!
//! This is **not** a secret wrapper like [`Fixed`](crate::Fixed) / [`Dynamic`](crate::Dynamic)
//! — it is a zeroizing `String` wrapper for encoded output. It implements
//! `Deref<Target = str>` and `AsRef<str>` / `AsRef<[u8]>`.
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
//! use secure_gate::Fixed;
//!
//! let encoded = Fixed::new([0xABu8; 4]).to_hex_zeroizing();
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
//! This does **not** stop extraction by convenience. `Deref<Target = str>` still gives
//! you `str::to_string()` and `.to_owned()`, both of which produce an ordinary
//! unzeroized `String`. That is extraction, and it is what the type is for — see
//! [Where accident-prevention ends](crate#where-accident-prevention-ends).

#[cfg(feature = "alloc")]
/// Owned wrapper for encoded secret strings. Guarantees zeroization on drop
/// while redacting `Debug` output. Use this when the encoded form remains sensitive
/// (e.g. full PEM keys, long-lived Bech32 private keys, tokens).
///
/// See the zeroizing encoding methods on [`Fixed`] and [`Dynamic`] (e.g.
/// [`to_hex_zeroizing`](crate::Fixed::to_hex_zeroizing)).
#[must_use = "dropping EncodedSecret may immediately zeroize encoded output"]
pub struct EncodedSecret(zeroize::Zeroizing<alloc::string::String>);

#[cfg(feature = "alloc")]
impl EncodedSecret {
    #[cfg(any(
        feature = "encoding-hex",
        feature = "encoding-base64",
        feature = "encoding-bech32",
        feature = "encoding-bech32m",
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
    /// This is an explicit escape hatch consistent with `InnerSecret`.
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

#[cfg(feature = "alloc")]
impl core::convert::AsRef<str> for EncodedSecret {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(feature = "alloc")]
impl core::convert::AsRef<[u8]> for EncodedSecret {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
