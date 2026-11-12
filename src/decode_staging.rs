//! Heap staging buffers for the `alloc` decode paths of hex, Base32 and Base64url.
//!
//! The backends' own `decode_vec` allocates a plain `Vec<u8>`, decodes into it, and on an
//! error drops it unwiped. Their decoders are constant-time: they write every output byte
//! and report a bad character only at the end, so a string that is a valid encoding
//! followed by junk (a hex key with a CRLF line ending, Base64url with `=` padding) fails
//! with the whole decoded secret already in that buffer, and the buffer goes back to the
//! allocator holding it. Wrapping the *result* in `Zeroizing` covers the success path only.
//!
//! Each function here allocates the buffer itself, inside `Zeroizing` before the backend
//! writes a byte, and decodes through the backend's slice API. Every exit wipes it: `Ok`
//! (by whoever takes the bytes), `Err`, and unwind. Sizes and the trailing `truncate`
//! mirror the backend's `decode_vec`, so accepted inputs, error cases and the returned
//! buffer's length and capacity are unchanged.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use zeroize::Zeroizing;

/// The decode failed. The caller maps this to its format's error.
pub(crate) struct Invalid;

/// Hex (upper, lower or mixed case), as `base16ct::mixed::decode_vec`.
#[cfg(feature = "encoding-hex")]
pub(crate) fn hex(s: &str) -> Result<Zeroizing<Vec<u8>>, Invalid> {
    let len = base16ct::decoded_len(s.as_bytes()).map_err(|_| Invalid)?;
    let mut buf = Zeroizing::new(vec![0u8; len]);
    base16ct::mixed::decode(s.as_bytes(), &mut buf).map_err(|_| Invalid)?;
    Ok(buf)
}

/// Base32, RFC 4648 §6, uppercase and unpadded, as `Base32UpperUnpadded::decode_vec`.
#[cfg(feature = "encoding-base32")]
pub(crate) fn base32(s: &str) -> Result<Zeroizing<Vec<u8>>, Invalid> {
    use base32ct::{Base32UpperUnpadded, Encoding};
    // `base32ct`'s own bound for the decoded length. Its `decode` rejects a destination
    // that is too small, so a wrong bound here would be an error, never an overrun.
    let mut buf = Zeroizing::new(vec![0u8; s.len() / 8 * 5 + (s.len() % 8 * 5) / 8]);
    let len = Base32UpperUnpadded::decode(s, &mut buf)
        .map_err(|_| Invalid)?
        .len();
    buf.truncate(len);
    Ok(buf)
}

/// Base64url, unpadded, as `Base64UrlUnpadded::decode_vec`.
#[cfg(feature = "encoding-base64")]
pub(crate) fn base64url(s: &str) -> Result<Zeroizing<Vec<u8>>, Invalid> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    // `base64ct`'s own bound, `(3 * n) / 4` without the overflow. As above, its `decode`
    // rejects a destination that is too small.
    let mut buf = Zeroizing::new(vec![0u8; s.len() / 4 * 3 + (s.len() % 4 * 3) / 4]);
    let len = Base64UrlUnpadded::decode(s, &mut buf)
        .map_err(|_| Invalid)?
        .len();
    buf.truncate(len);
    Ok(buf)
}
