//! Serde visitors that build a secret inside a buffer this crate wipes.
//!
//! `Vec<u8>`'s and `String`'s own `Deserialize` impls build an ordinary value and hand it
//! over when it is complete. Until then it is a plain allocation, and for a sequence the
//! `Vec` grows as elements arrive, freeing each outgrown buffer unwiped. These visitors
//! take the same input through the same serde entry points (`deserialize_seq`,
//! `deserialize_string`), so every format accepts and rejects what it did before, but the
//! buffer being filled is a `Zeroizing` one from its first byte, and growth is done by
//! hand: allocate the larger buffer, copy, wipe the old one.
//!
//! # Where this stops
//!
//! At the deserializer. Bytes it lends (`visit_str`, `visit_bytes`) sit in its own
//! buffers, which this crate never holds and cannot wipe: `serde_json`'s scratch buffer
//! for a string with escapes, the caller's input, a reader's block. Bytes it gives
//! (`visit_string`, `visit_byte_buf`) are taken over and wiped from then on.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use zeroize::Zeroizing;

/// The message both visitors, and the wrappers' `deserialize_with_limit`, reject an
/// over-long secret with.
pub(crate) const TOO_LARGE: &str = "deserialized secret exceeds maximum size";

/// The most a sequence's `size_hint` is allowed to pre-allocate. A hint comes from the
/// input, so it is a request, not a fact; serde caps its own `Vec` the same way.
const HINT_CEILING: usize = 4096;

/// The smallest buffer growth allocates, so short secrets do not grow byte by byte.
const FIRST_GROWTH: usize = 64;

/// Builds a `Zeroizing<Vec<u8>>` from a sequence of bytes, at most `limit` long.
pub(crate) struct BytesVisitor {
    pub(crate) limit: usize,
}

impl<'de> serde::de::Visitor<'de> for BytesVisitor {
    type Value = Zeroizing<Vec<u8>>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a sequence")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let hint = seq
            .size_hint()
            .unwrap_or(0)
            .min(self.limit)
            .min(HINT_CEILING);
        let mut buf = Zeroizing::new(Vec::with_capacity(hint));
        // An early return below drops `buf`, and `Zeroizing` wipes what was read so far.
        while let Some(byte) = seq.next_element::<u8>()? {
            if buf.len() >= self.limit {
                return Err(serde::de::Error::custom(TOO_LARGE));
            }
            if buf.len() == buf.capacity() {
                grow(&mut buf, self.limit);
            }
            buf.push(byte);
        }
        Ok(buf)
    }
}

/// Moves `buf` into a larger buffer and wipes the one it leaves.
///
/// `Vec`'s own growth frees the old block as it is. Called only when `buf.len() < limit`,
/// so the new capacity is always at least one byte more than the length.
fn grow(buf: &mut Zeroizing<Vec<u8>>, limit: usize) {
    let capacity = buf
        .capacity()
        .saturating_mul(2)
        .max(FIRST_GROWTH)
        .min(limit);
    let mut next = Zeroizing::new(Vec::with_capacity(capacity));
    next.extend_from_slice(buf);
    core::mem::swap(buf, &mut next);
    // `next` now holds the outgrown buffer; dropping it wipes that buffer whole.
}

/// Builds a `Zeroizing<String>` at most `limit` bytes long.
pub(crate) struct StringVisitor {
    pub(crate) limit: usize,
}

impl<'de> serde::de::Visitor<'de> for StringVisitor {
    type Value = Zeroizing<String>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string")
    }

    /// Lent text: copied once, into a buffer of exactly its length, after the limit check.
    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if v.len() > self.limit {
            return Err(E::custom(TOO_LARGE));
        }
        let mut out = Zeroizing::new(String::with_capacity(v.len()));
        out.push_str(v);
        Ok(out)
    }

    /// Given text: taken over as it is, so it is wiped on rejection too.
    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let v = Zeroizing::new(v);
        if v.len() > self.limit {
            return Err(E::custom(TOO_LARGE));
        }
        Ok(v)
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match core::str::from_utf8(v) {
            Ok(s) => self.visit_str(s),
            Err(_) => Err(E::invalid_value(serde::de::Unexpected::Bytes(v), &self)),
        }
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match String::from_utf8(v) {
            Ok(s) => self.visit_string(s),
            Err(e) => {
                // Not text, but still the bytes that were sent as the secret.
                let bytes = Zeroizing::new(e.into_bytes());
                Err(E::invalid_value(
                    serde::de::Unexpected::Bytes(&bytes),
                    &self,
                ))
            }
        }
    }
}
