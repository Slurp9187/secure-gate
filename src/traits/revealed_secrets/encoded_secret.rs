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
//! `Deref` here is a deliberate exception to the crate's no-`Deref` rule, and the
//! alternative (drop it, add `as_str()`, and close `.to_string()`) was considered and
//! rejected. Design record:
//! [`docs/encoded_secret_deref.md`](https://github.com/Slurp9187/secure-gate/blob/main/docs/design/encoded_secret_deref.md)
//! — a repository file, not part of the published crate, so this is a link and not a path.
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
//!
//! # Every `str` method reached through `Deref` exits protection, not just `.to_string()`
//!
//! The table above singles out `.to_string()` / `.to_owned()` because those are the
//! obvious copies. They are not the only ones. `Deref<Target = str>` exposes *every*
//! method `str` has, and a good many of them — `to_ascii_uppercase`,
//! `to_ascii_lowercase`, `to_lowercase`, `to_uppercase`, `replace`, `repeat`, `trim()`
//! followed by an owning call, and more — return a freshly allocated, ordinary `String`.
//! Each one ends protection the instant it runs, and nothing at the call site marks the
//! exit:
//!
//! ```rust
//! # #[cfg(all(feature = "encoding-bech32", feature = "alloc"))] {
//! use secure_gate::{Fixed, ToBech32m, Case};
//!
//! let key = Fixed::new([0xABu8; 32]);
//! let encoded = key.try_to_bech32m("key", Case::Lower).unwrap(); // EncodedSecret -- protected
//! let shouted = encoded.to_ascii_uppercase();                    // plain String -- escaped, unwiped
//! # let _ = shouted;
//! # }
//! ```
//!
//! `shouted` is a second full copy of the key material: no zeroize-on-drop, no redacted
//! `Debug`, and the receiver reads exactly like the `EncodedSecret` it was called on one
//! line up. Nothing in the syntax distinguishes this call from one that stayed inside
//! protection.
//!
//! This is not hypothetical. A consumer of this crate hit it twice in one codebase, on
//! the same idiom, with opposite outcomes. One call site piped `try_to_bech32m(..)`
//! straight into `.to_ascii_uppercase()` and shipped it, leaking a database key twice
//! over — once as the lowercase encoding, once as the uppercased copy neither wrapper
//! ever touched. A second call site, reaching for the same encoder, re-wrapped the
//! result before using it: `Zeroizing::new(encoded.to_ascii_uppercase())`. Same crate,
//! same method chain, two different outcomes in one tree — which is what makes this a
//! trap and not carelessness. Both call sites compile. Both type-check. Only one of them
//! is safe, and nothing in the types says which.
//!
//! Two ways to stay inside protection:
//!
//! - **Do the transform inside the encoder, where one exists.**
//!   [`to_hex_upper`](crate::ToHex::to_hex_upper) exists precisely so callers never need
//!   `.to_hex().to_ascii_uppercase()`, and the bech32 / bech32m encoders take a
//!   [`Case`](crate::Case) argument for the same reason — ask the encoder for the case
//!   you want instead of asking `str` to convert it afterward.
//! - **Re-wrap the result yourself** when no such parameter exists:
//!   `Zeroizing::new(encoded.some_str_method())`. That is one allocation you chose and
//!   can account for, in place of one the type system quietly declined to track.
//!
//! This is the same shape of hole as the one already closed for this exact type in
//! [`EncodableBytes`](crate::EncodableBytes#why-the-extra-bound-exists): there, an
//! `AsRef<[u8]>`-only blanket let `encoded.to_hex()` compile on an `EncodedSecret` and
//! hex-encode the encoded *text* — a 32-byte key came back as 124 hex characters, with
//! nothing to flag it as wrong. That hole was closed with a trait bound, because the
//! encoders are this crate's own API and a bound can gate them. This one cannot close
//! the same way: `str`'s inherent methods are not a trait this crate can add a bound to,
//! so the deref stays reachable by construction — see
//! [No `Display`](crate::EncodedSecret#no-display) above for why the deref itself stays.
//! The boundary here is not a compile error; it is knowing it precisely — any `str`
//! method reached through this type's `Deref` produces unprotected output, full stop —
//! and giving every one of them the scrutiny the table above already asks for
//! `.to_string()`.

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
    ///
    /// # At a public API boundary
    ///
    /// Returning the `String` from your own public function hands callers a value
    /// with no zeroize-on-drop and no redacted `Debug`. Every later copy — a
    /// `format!`, a log line, a `Clone`, a `serde` round-trip — is an ordinary
    /// heap allocation this crate can no longer clear.
    ///
    /// Prefer returning [`EncodedSecret`] itself: it derefs to `str`, so callers
    /// that only read it need no change, and the protection travels with the value
    /// instead of stopping at your boundary. Call `into_inner()` at the point where
    /// a foreign API genuinely demands an owned `String`, and keep the result's
    /// lifetime as short as you can.
    ///
    /// ```
    /// # #[cfg(all(feature = "alloc", feature = "encoding-hex"))] {
    /// use secure_gate::{Fixed, ToHex, EncodedSecret};
    ///
    /// // Prefer this: protection crosses the boundary with the value.
    /// fn good(key: &Fixed<[u8; 4]>) -> EncodedSecret { key.to_hex() }
    ///
    /// // Only when a foreign API insists on an owned String.
    /// fn needs_string(key: &Fixed<[u8; 4]>) -> String { key.to_hex().into_inner() }
    ///
    /// let key = Fixed::from([0xde, 0xad, 0xbe, 0xef]);
    /// assert_eq!(&*good(&key), "deadbeef");
    /// assert_eq!(needs_string(&key), "deadbeef");
    /// # }
    /// ```
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

// No `AsRef<str>` / `AsRef<[u8]>`: `Deref<Target = str>` yields `&str` by coercion, by
// `&*encoded`, and through method resolution, so for those uses the impls were doors
// onto a room `Deref` already opens.
//
// They were not equivalent, though, and the difference is worth stating because it is
// the one thing removing them broke. Deref coercion applies at a coercion site; it does
// not satisfy a generic bound. So `fs::write(path, &encoded)` — or any
// `impl AsRef<[u8]>` parameter — no longer compiles, and the caller writes
// `encoded.as_bytes()` instead. That is a deliberate cost: a generic byte sink is
// exactly the call that should name the extraction rather than have it inferred.
//
// Removing them did not, on its own, close the accidental re-encode: method resolution
// derefs to `str`, and `str: AsRef<[u8]>` satisfied the old encoder blanket impls, so
// `encoded.to_hex()` compiled and hex-encoded the encoded text. That reachability comes
// from `Deref`, which is the type's primary accessor and stays. The bound closed it
// instead — the encoders now require `AsRef<[u8]> + EncodableBytes`, and `str` does not
// implement `EncodableBytes`, so the second encode is a compile error. Pinned by the
// `encoded_secret_no_reencode` compile-fail test. The surviving boundary is documented
// at [Where accident-prevention ends](crate#where-accident-prevention-ends).
