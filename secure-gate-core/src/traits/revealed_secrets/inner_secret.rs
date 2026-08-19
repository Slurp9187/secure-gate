/// Owned, zeroizing secret extracted via [`RevealSecret::into_inner`].
///
/// `InnerSecret<T>` preserves the zeroization contract by wrapping
/// [`zeroize::Zeroizing<T>`], while restoring a strict redaction policy for `Debug`:
/// formatting this type always prints `[REDACTED]`, regardless of `T`.
///
/// This is **not** a secret wrapper like [`Fixed`](crate::Fixed) or
/// [`Dynamic`](crate::Dynamic) — it is the owned extraction result from
/// [`into_inner()`](crate::RevealSecret::into_inner), and it implements
/// `Deref<Target = T>` by design. `Fixed` and `Dynamic` deliberately do not deref;
/// the other output wrapper, [`EncodedSecret`](crate::EncodedSecret), derefs to `str`.
///
/// # What this type does and does not protect
///
/// It zeroizes the buffer it owns on drop, and its `Debug` prints `[REDACTED]`. It does
/// **not** track copies made through `Deref`: `*inner` on a `Copy` type such as
/// `[u8; N]`, or `.to_owned()` on the derefed value, yields ordinary untracked
/// plaintext. That is the point of extraction — see
/// [Where accident-prevention ends](crate#where-accident-prevention-ends).
///
/// Note also that `Debug` redaction does not survive a deref:
/// `format!("{:?}", inner)` prints `[REDACTED]`, but `format!("{:?}", &*inner)` prints
/// the secret. Redaction is a property of this wrapper, not of `T`.
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
    ///
    /// # This downgrades `Debug`
    ///
    /// Zeroize-on-drop is preserved, but redaction is not: `Zeroizing<T>` derives
    /// `Debug` from `T` (`zeroize` 1.8/1.9; a future release may change the rendering),
    /// so `{:?}` on the returned value can print the secret. Prefer keeping the
    /// `InnerSecret` unless an API names `Zeroizing<T>` in its signature.
    ///
    /// This crate does not re-export `zeroize`, so naming the return type in your own
    /// code means depending on a compatible `zeroize` version directly.
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

/// Provides `&T` access via `*inner_secret`. Deref is the intended API for an output
/// wrapper; the secret wrappers [`Fixed`](crate::Fixed) and [`Dynamic`](crate::Dynamic)
/// deliberately do not implement it.
impl<T: zeroize::Zeroize> core::ops::Deref for InnerSecret<T> {
    type Target = T;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
