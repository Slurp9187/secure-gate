//! Owned zeroizing wrapper for secrets extracted via [`RevealSecret::into_inner`].
//!
//! This is part of the `revealed_secrets` module. See `mod.rs` for overview
//! and `SECURITY.md` for the 3-tier access model and audit guidance.

/// Owned, zeroizing secret extracted via [`RevealSecret::into_inner`].
///
/// `InnerSecret<T>` preserves the zeroization contract by wrapping
/// [`zeroize::Zeroizing<T>`], while restoring a strict redaction policy for `Debug`:
/// formatting this type always prints `[REDACTED]`, regardless of `T`.
///
/// This is **not** a secret wrapper like [`Fixed`](crate::Fixed) or
/// [`Dynamic`](crate::Dynamic) — it is the owned extraction result from
/// [`into_inner()`](crate::RevealSecret::into_inner). It implements
/// `Deref<Target = T>` (the **only** type in this crate that derefs to the secret).
///
/// Use [`into_zeroizing`](Self::into_zeroizing) only when an API explicitly requires
/// a `Zeroizing<T>` value.
///
/// # Examples
///
/// ```rust
/// use secure_gate::{Fixed, RevealSecret};
///
/// let key = Fixed::new([0xABu8; 4]);
/// let owned = key.into_inner();
///
/// // Deref access to the inner value.
/// assert_eq!(owned[0], 0xAB);
///
/// // Debug is redacted.
/// assert_eq!(format!("{:?}", owned), "[REDACTED]");
///
/// // Convert to Zeroizing<T> for interop.
/// let z = owned.into_zeroizing();
/// ```
///
/// See also [`EncodedSecret`](crate::EncodedSecret) — the encoded-string counterpart.
pub struct InnerSecret<T: zeroize::Zeroize>(zeroize::Zeroizing<T>);

impl<T: zeroize::Zeroize> InnerSecret<T> {
    #[inline(always)]
    pub(crate) fn new(inner: T) -> Self {
        Self(zeroize::Zeroizing::new(inner))
    }

    /// Unwraps and returns the underlying [`zeroize::Zeroizing<T>`].
    ///
    /// This is an explicit escape hatch for interoperability with APIs that accept
    /// `Zeroizing<T>` directly.
    #[inline(always)]
    pub fn into_zeroizing(self) -> zeroize::Zeroizing<T> {
        self.0
    }
}

impl<T: zeroize::Zeroize> core::fmt::Debug for InnerSecret<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Provides `&T` access via `*inner_secret`. This is the **only** type in the crate
/// that implements `Deref` to the secret — [`Fixed`](crate::Fixed) and
/// [`Dynamic`](crate::Dynamic) deliberately do not.
impl<T: zeroize::Zeroize> core::ops::Deref for InnerSecret<T> {
    type Target = T;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
