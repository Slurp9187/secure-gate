//! Internal trait for types that can be viewed as bytes.
//! Used for safe rehash() in hash-eq.

#[cfg(feature = "hash-eq")]
pub(crate) trait ByteView {
    fn as_bytes(&self) -> &[u8];
}

#[cfg(feature = "hash-eq")]
impl ByteView for Vec<u8> {
    #[inline(always)]
    fn as_bytes(&self) -> &[u8] {
        self.as_slice()
    }
}

#[cfg(feature = "hash-eq")]
impl ByteView for String {
    #[inline(always)]
    fn as_bytes(&self) -> &[u8] {
        self.as_bytes()
    }
}

// Add more if needed (e.g., &[u8], [u8; N] for Fixed)
// impl ByteView for [u8] { fn as_bytes(&self) -> &[u8] { self } }
// impl<const N: usize> ByteView for [u8; N] { fn as_bytes(&self) -> &[u8] { self } }
