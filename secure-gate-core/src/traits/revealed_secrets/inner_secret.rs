/// Owned, zeroizing secret extracted via [`RevealSecret::into_inner`].
///
/// `InnerSecret<T>` preserves the zeroization contract by wrapping
/// [`zeroize::Zeroizing<T>`], while restoring a strict redaction policy for `Debug`:
/// formatting this type always prints `[REDACTED]`, regardless of `T`.
///
/// Use [`into_zeroizing`](Self::into_zeroizing) only when an API explicitly requires
/// a `Zeroizing<T>` value.
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

impl<T: zeroize::Zeroize> core::ops::Deref for InnerSecret<T> {
    type Target = T;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
