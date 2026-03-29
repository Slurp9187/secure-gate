//! Owned zeroizing wrapper for encoded secret strings.
//!
//! This is part of the `revealed_secrets` module. See `mod.rs` for overview
//! and `SECURITY.md` for when to use it (sensitive encoded output).

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

#[cfg(feature = "alloc")]
impl core::fmt::Display for EncodedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&**self, f)
    }
}
