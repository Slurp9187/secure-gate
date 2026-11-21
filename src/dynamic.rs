//! Heap-allocated wrapper for variable-length secrets.
//!
//! > **Import path:** `use secure_gate::Dynamic;` (not `secure_gate::dynamic::Dynamic`)
//!
//! [`Dynamic<T>`] is a zero-cost wrapper that enforces explicit, auditable access to
//! sensitive data stored on the heap. It is the primary secret type for variable-length
//! material such as passwords, API keys, and ciphertexts. Requires the `alloc` feature.
//!
//! # Security invariants
//!
//! - **No `Deref`, `AsRef`, or `Copy`** — the inner value cannot leak through
//!   implicit conversions.
//! - **`Debug` always prints `[REDACTED]`** — secrets never appear in logs or
//!   panic messages.
//! - **Unconditional zeroization on drop** — includes `Vec`/`String` spare capacity.
//! - **Held on the heap** — the inner value is stored in `Box<T>`. `new_with`,
//!   `try_new_with` and `from_random` write the bytes there directly; `new` and `From`
//!   take an existing value, passed by value (see the type docs).
//! - **Opt-in `Clone`** — requires `T: CloneableSecret` and the `cloneable` feature.
//! - **Opt-in `Serialize`** — requires the `SerializableSecret` marker and the
//!   `serde-serialize`/`serde-deserialize` features.
//! - **Panic safety** — all decode constructors use the `from_protected_bytes` pattern:
//!   a `Zeroizing` wrapper survives OOM panics from `Box::new`.
//!
//! Guidance on choosing the inner type and the constructor, and the reallocation
//! warning, is on [`Dynamic`] itself; this module is private and its docs are not
//! rendered.
//!
//! # 3-tier access model
//!
//! ```rust
//! # #[cfg(feature = "alloc")]
//! # {
//! use secure_gate::{Dynamic, RevealSecret, RevealSecretMut, SecretLen};
//!
//! let mut pw: Dynamic<String> = Dynamic::new(String::from("hunter2"));
//!
//! // Tier 1 — scoped (preferred): borrow is confined to the closure.
//! let len = pw.with_secret(|s: &String| s.len());
//! assert_eq!(len, 7);
//!
//! // Tier 1 mutable — scoped mutation. Prefer capacity-stable mutations for
//! // Dynamic<String> / Dynamic<Vec<u8>>; see SECURITY.md for realloc notes.
//! pw.with_secret_mut(|s: &mut String| s.make_ascii_uppercase());
//!
//! // Tier 2 — direct reference (escape hatch).
//! assert_eq!(pw.expose_secret(), "HUNTER2");
//!
//! // Tier 3 — transfer ownership. Protection ends here.
//! let owned: String = pw.into_inner();
//! assert_eq!(owned, "HUNTER2");
//! # }
//! ```
//!
//! # See also
//!
//! - [`Fixed<T>`](crate::Fixed) — stack-allocated alternative for fixed-size secrets
//!   (always available, no `alloc` required).

#[cfg(feature = "alloc")]
extern crate alloc;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use zeroize::Zeroize;

#[cfg(any(feature = "ct-eq", feature = "std"))]
use crate::RevealSecret;

// Encoding traits
#[cfg(feature = "encoding-base32")]
use crate::traits::encoding::base32::ToBase32;
#[cfg(feature = "encoding-base64")]
use crate::traits::encoding::base64_url::ToBase64Url;
#[cfg(feature = "encoding-bech32")]
use crate::traits::encoding::bech32::ToBech32;
#[cfg(feature = "encoding-bech32")]
use crate::traits::encoding::bech32m::ToBech32m;
#[cfg(feature = "encoding-hex")]
use crate::traits::encoding::hex::ToHex;

#[cfg(feature = "rand")]
use rand::{TryRng, rngs::SysRng};

/// Zero-cost heap-allocated wrapper for variable-length secrets.
///
/// `Dynamic<T>` stores a `T: Zeroize` value in a `Box<T>` and unconditionally zeroizes
/// it on drop (including `Vec`/`String` spare capacity). There is no `Deref`, `AsRef`,
/// or `Copy` — every access is explicit through [`RevealSecret`](crate::RevealSecret)
/// or [`RevealSecretMut`](crate::RevealSecretMut).
///
/// This is **not** `Fixed<T>` — it is the heap-allocated alternative for variable-length
/// secrets. The wrapper holds its bytes on the heap. [`new`](Self::new) takes an existing
/// value by value: `Dynamic::new([0u8; 32])` copies the array over the stack, and that
/// source is not wiped, while `Dynamic::new(Box::new(…))` moves only the box.
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "alloc")]
/// # {
/// use secure_gate::{Dynamic, RevealSecret, SecretLen};
///
/// let pw: Dynamic<String> = Dynamic::new(String::from("hunter2"));
/// assert_eq!(pw.with_secret(|s: &String| s.len()), 7);
/// assert_eq!(format!("{:?}", pw), "[REDACTED]");
/// # }
/// ```
///
/// # Choosing the inner type for security
///
/// Different inner types have different reallocation-residue profiles:
///
/// | Inner type | Realloc surface | Use case |
/// |---|---|---|
/// | `Dynamic<[u8]>` (boxed slice) | **None** once built — the length is set at construction and cannot change | Known-size keys held on the heap, and secrets whose length is known only at runtime but never changes afterwards |
/// | `Dynamic<[u8; N]>` (boxed array) | **None** — fixed size | Rarely the right choice: it has no `new_with`, `from_random` or decoders. `new` of an array passes it by value, over the stack; `new` of a `Box` moves the box, which still had to be filled somewhere |
/// | `Dynamic<Vec<u8>>` pre-sized | None *if* you avoid capacity-growing mutations | Variable-length secrets with a known upper bound |
/// | `Dynamic<Vec<u8>>` growable | **Yes** — each realloc leaves the old buffer unzeroed | Convenient, but see realloc-residue warning below |
/// | `Dynamic<String>` | Same as `Dynamic<Vec<u8>>` | Passwords, API keys |
///
/// For **long-lived, known-size key material** on the heap, prefer `Dynamic<[u8]>`. Built
/// with `new_with(N, …)` or `from_random(N)`, the bytes are written straight into the heap
/// buffer; a decoder writes them into a wiped staging buffer and copies them in. Either
/// way the length cannot change. `Dynamic<[u8; N]>` has no realloc surface either, but
/// `new` of an array passes it by value, over the stack, and `new` of a `Box` moves a box
/// that had to be filled first. If you use it, build `Dynamic::new([0u8; N])` and fill it
/// through `with_secret_mut`.
/// See `SECURITY.md` § "Inherent Rust Limitations" for the broader discussion.
///
/// When the length is fixed but only known at runtime, `Dynamic<[u8]>` gives the same
/// guarantee by construction: `with_secret_mut` hands the closure a `&mut [u8]`, which has
/// no `push`, `extend` or `reserve`, so a reallocation is not expressible rather than merely
/// discouraged. Two things to know before choosing it:
///
/// - **Build it with `new_with`, `try_new_with`, `from_random` or a decoder.** Each
///   allocates exactly the length it needs before a byte is written. `Dynamic::<[u8]>::new(vec)`
///   instead converts through `Box<[u8]>::from(Vec)`, which shrinks a `Vec` with excess
///   capacity into a newly allocated buffer and frees the old one unwiped; `vec![0u8; len]`
///   is already exact, a `Vec` that was grown or truncated is not.
/// - **What it has.** Everything `Dynamic<Vec<u8>>` has for building, decoding and
///   encoding (since 0.10.0, written once over [`DynamicBytes`](crate::DynamicBytes):
///   name the shape on the binding or with a turbofish), scoped access,
///   [`Debug`](core::fmt::Debug) redaction, zeroize-on-drop, `ct_eq` (with `ct-eq`),
///   [`SecretLen`](crate::SecretLen), and serde `Deserialize` with the same limit as
///   `Dynamic<Vec<u8>>`.
/// - **What it does not have.** `into_inner` and `Clone`. Serde `Serialize` is unavailable for the reason it is unavailable for
///   `Dynamic<Vec<u8>>`: the opt-in marker [`SerializableSecret`](crate::SerializableSecret)
///   goes on an inner type you own, and `[u8]` is not yours to mark.
///
/// ```
/// use secure_gate::{Dynamic, RevealSecret, RevealSecretMut, SecretLen};
///
/// let len = 32; // known only at runtime
/// let mut key: Dynamic<[u8]> = Dynamic::new_with(len, |k| k.fill(0x42)); // exact length
/// key.with_secret_mut(|k: &mut [u8]| k[0] = 0x43); // `&mut [u8]` cannot grow
/// assert_eq!(key.len(), 32);
/// ```
///
/// # Construction
///
/// | Constructor | Notes |
/// |---|---|
/// | [`Dynamic::<Vec<u8>>::new_with(len, f)`](Dynamic::new_with) | **Preferred.** Writes into a sized, pre-zeroed slot inside the wrapper; growth is not expressible. `Dynamic::<[u8]>::new_with` is the same for a boxed slice |
/// | [`Dynamic::<Vec<u8>>::try_new_with(len, f)`](Dynamic::try_new_with) | The same, for a fill that can fail; wipes the partial write on `Err` |
/// | [`Dynamic::new(value)`](Dynamic::new) | **Moves** the buffer in — no copy. Only as safe as how you built the value |
/// | [`From<&str>`](Dynamic::from) / [`From<&[u8]>`](Dynamic::from) | **Copies**; your source buffer is left unwiped |
///
/// Choosing between them is about where the bytes are written, not convenience:
///
/// - **Length known before the fill** — use `new_with(len, …)`. That is two allocations,
///   not one: the slot, of exactly `len` bytes, plus the `Box<Vec<u8>>` header every
///   `Dynamic<Vec<u8>>` is built around. `tests/lifecycle_trace_heap.rs` measures
///   `from_random(len)` — this constructor with an RNG in the closure — at exactly two,
///   and `Dynamic::new(owned)` at exactly one, because a move brings its buffer with it.
///   So the recommendation is not about allocation count; it is about the slot's shape.
///   Capacity equals length, so the wrapper never holds slack, and the closure is handed a
///   slice, so growth is not expressible at all.
/// - **Length not known** — use `Dynamic::new(Vec::new())` and write through the
///   [`std::io::Write`] impl, which grows by hand and **zeroizes each abandoned buffer**
///   before releasing it. It is the one growth path here that does. Requires `std`.
/// - **You already own the value** — `new(owned)` moves the allocation rather than
///   copying it, so the buffer you filled becomes the buffer the wrapper protects. That
///   is necessary but not sufficient: if you *grew* the value to build it, those
///   reallocations already happened and the copies are already on the heap. Build without
///   growth — `with_capacity` at the exact final size, or one `resize` — then move it in.
///
/// `Dynamic<String>` has no closure constructor. It cannot: `String` must hold valid
/// UTF-8 and characters have variable byte widths, so a fixed byte window is not a place
/// you can write arbitrary text. Build a pre-sized `String` and move it in with
/// [`Dynamic::new`].
///
/// # Constructors for `Dynamic<Vec<u8>>`
///
/// | Constructor | Feature | Notes |
/// |---|---|---|
/// | [`new_with(len, f)`](Self::new_with) | — | **Preferred.** Sized, pre-zeroed slot inside the wrapper |
/// | [`try_new_with(len, f)`](Self::try_new_with) | — | The same, fallible; wipes the partial write on `Err` |
/// | [`new(value)`](Self::new) | — | **Moves** the buffer in. Accepts `Vec<u8>` or `Box<Vec<u8>>`; a `&[u8]` goes through `Dynamic::from`, which copies |
/// | [`try_from_hex(s)`](Self::try_from_hex) | `encoding-hex` | Constant-time hex decoding |
/// | [`try_from_base32(s)`](Self::try_from_base32) | `encoding-base32` | Constant-time Base32 decoding |
/// | [`try_from_base64url(s)`](Self::try_from_base64url) | `encoding-base64` | Constant-time Base64url decoding |
/// | [`try_from_bech32(s, hrp)`](Self::try_from_bech32) | `encoding-bech32` | HRP-validated Bech32 |
/// | [`try_from_bech32_unchecked(s)`](Self::try_from_bech32_unchecked) | `encoding-bech32` | Bech32 without HRP check |
/// | [`try_from_bech32m(s, hrp)`](Self::try_from_bech32m) | `encoding-bech32` | HRP-validated Bech32m |
/// | [`try_from_bech32m_unchecked(s)`](Self::try_from_bech32m_unchecked) | `encoding-bech32` | Bech32m without HRP check |
/// | The four `_sized::<C>` forms, such as [`try_from_bech32_sized`](Self::try_from_bech32_sized) | `encoding-bech32` | As above, for strings longer than [`BECH32_CODE_LENGTH`](crate::BECH32_CODE_LENGTH) |
/// | [`from_random(len)`](Self::from_random) | `rand` | System RNG |
///
/// # Warning
///
/// Ensure your profile sets `panic = "unwind"` — `panic = "abort"` skips destructors
/// and therefore skips zeroization. (`Dynamic` cannot be `static` since it requires
/// `Box` allocation, so the static-secret warning from `Fixed` does not apply.)
///
/// For `Dynamic<Vec<_>>` and `Dynamic<String>`, capacity-changing mutations can
/// cause the standard allocator to free the previous buffer without zeroizing it.
/// Pre-allocate to the maximum size, use capacity-stable mutations, prefer
/// `Dynamic<[u8]>` built with `new_with`, `from_random` or a decoder (no realloc
/// surface) for known-size heap secrets, or use
/// [`Fixed<T>`](crate::Fixed) for known-size stack secrets. See `SECURITY.md` for
/// the full threat-model discussion and deployment-level mitigations including
/// the [`zeroizing-alloc`](https://crates.io/crates/zeroizing-alloc) global
/// allocator.
///
/// # See also
///
/// - [`RevealSecret`](crate::RevealSecret) / [`RevealSecretMut`](crate::RevealSecretMut) — the 3-tier access traits.
/// - [`Fixed<T>`](crate::Fixed) — stack-allocated alternative.
#[must_use = "Dynamic<T> holds secret material; dropping it on the floor usually indicates a bug — bind with `let _name = ...` or chain a method call"]
pub struct Dynamic<T: ?Sized + zeroize::Zeroize> {
    inner: Box<T>,
}

impl<T: ?Sized + zeroize::Zeroize> Dynamic<T> {
    /// Wraps `value` in a `Box<T>` and returns a `Dynamic<T>`.
    ///
    /// Accepts any type that implements `Into<Box<T>>`: an owned `T` (a `String`, a
    /// `Vec<u8>`), which is boxed, or a `Box<T>`, which is moved in as it is. Either way
    /// the buffer is moved, not copied.
    ///
    /// For `Dynamic<String>` and `Dynamic<Vec<u8>>`, borrowed input is not accepted here.
    /// `&str` and `&[u8]` go through [`Dynamic::from`], which copies them and leaves the
    /// source unwiped. For the values `new` does accept, `Dynamic::from(value)` is the same
    /// call; `#[doc(alias = "from")]` is set so both names appear in docs.rs search.
    ///
    /// **The unsized shapes are the exception.** `Box<str>` implements `From<&str>` and
    /// `Box<[u8]>` implements `From<&[u8]>`, so `Dynamic::<str>::new("...")` and
    /// `Dynamic::<[u8]>::new(&bytes[..])` compile. Both **copy** the borrowed bytes into a
    /// new allocation and leave the source unwiped, exactly as `Dynamic::from(&str)` does.
    /// An owned `String` or `Vec` given to either is moved, but is first shrunk to its
    /// length: if it had spare capacity, that reallocates and frees the old buffer unwiped.
    ///
    /// Requires the `alloc` feature (which `Dynamic<T>` itself always requires).
    #[doc(alias = "from")]
    #[inline(always)]
    pub fn new<U>(value: U) -> Self
    where
        U: Into<Box<T>>,
    {
        let inner = value.into();
        Self { inner }
    }
}

/// Moves an already-boxed value in — zero-copy, no allocation at all. The box the caller
/// already owns becomes the box the wrapper owns, so whatever buffer sits behind `T` never
/// moves and never gets a second copy taken of it.
///
/// "Already boxed" describes the shape of the value at the moment it arrives here, not how
/// it was built. A `Vec<u8>` pushed onto in a loop and later turned into a `Box<[u8]>`, or a
/// `String` grown with `push_str` before being boxed, already paid for every one of those
/// reallocations before this impl runs — and each reallocation frees the old block without
/// zeroizing it, the same mechanism
/// `tests/lifecycle_trace_heap.rs::check_growth_orphan_retains_secret_vec` (and its
/// `_string` sibling) measures happening to a value already *inside* the wrapper. Nothing
/// this impl does can reach backward and clean that up; it only ever protects the buffer it
/// ends up holding. Build without growth — `with_capacity` at the exact final size, or one
/// `resize` — before boxing, then move the box in.
impl<T: ?Sized + zeroize::Zeroize> From<Box<T>> for Dynamic<T> {
    #[inline(always)]
    fn from(boxed: Box<T>) -> Self {
        Self { inner: boxed }
    }
}

/// Copies a byte slice to the heap and wraps the copy. The source slice is left exactly as
/// it was — this impl protects the copy it makes, not the memory it copied from, and leaving
/// that memory unwiped is the caller's problem to solve.
///
/// `tests/lifecycle_trace_heap.rs::check_str_and_slice_conversions_copy_then_wipe` measures
/// both halves of that: converting `&[u8]` costs two allocations (the fresh `Vec<u8>` buffer
/// plus the `Box<Vec<u8>>` header, against one for a move) and the source slice's bytes are
/// unchanged after the wrapper is built and dropped. If the bytes are already in an owned
/// `Vec<u8>` you control, [`Dynamic::new`] moves it in for one allocation and nothing of
/// yours left behind to wipe.
impl From<&[u8]> for Dynamic<Vec<u8>> {
    #[inline(always)]
    fn from(slice: &[u8]) -> Self {
        Self::new(slice.to_vec())
    }
}

/// Copies a string to the heap and wraps the copy, leaving the source `&str` exactly as it
/// was — measured the same way as the `&[u8]` conversion above, by
/// `tests/lifecycle_trace_heap.rs::check_str_and_slice_conversions_copy_then_wipe`: two
/// allocations (the copied `String` buffer plus the `Box<String>` header, against one for a
/// move) and a caller-side buffer whose bytes are provably unchanged once the wrapper is
/// built and dropped.
///
/// `Dynamic<String>` has no closure constructor, and an `&str` is usually what is on hand,
/// so this impl reads as the obvious way in. It is the **worse** one: whatever plaintext the `&str` borrows
/// from — a literal, an owned `String`, a line read off stdin — is untouched by this call and
/// stays live and unprotected for as long as its own scope does. If you own the `String`,
/// size it once — `String::with_capacity` at the exact final length — and move it in with
/// [`Dynamic::new`], which `check_string_new_moves_callers_buffer` measures as exactly one
/// allocation (the `Box<String>` header) with the secret staying at the caller's original
/// buffer address.
impl From<&str> for Dynamic<String> {
    #[inline(always)]
    fn from(input: &str) -> Self {
        Self::new(input.to_string())
    }
}

/// Moves an owned value onto the heap by boxing it — the impl behind [`Dynamic::new`]'s
/// "moves the buffer in, no copy" guarantee for `Vec<u8>`, `String`, and every other `Sized`
/// `T`. `Box::new(value)` only relocates `value`'s own stack representation (for a `Vec<u8>`,
/// the pointer/length/capacity triple); the heap buffer that pointer already points at is
/// never touched, so it lands inside the wrapper at the address it already had.
///
/// That is necessary for "no copy" to hold, but not sufficient for it to matter: if `value`
/// was grown to build it — pushed onto, extended, `push_str`'d past its original capacity —
/// each of those reallocations already ran *before* this impl ever sees the value, and each
/// one freed a heap block holding the secret, unwiped, somewhere this wrapper will never
/// look. `check_growth_orphan_retains_secret_vec` / `_string` in
/// `tests/lifecycle_trace_heap.rs` measure exactly that allocator behavior for growth
/// happening *after* the value is wrapped; the same allocator runs the same way one step
/// earlier when the growth happens during construction instead.
/// `check_string_new_moves_callers_buffer` measures the guarantee this impl does deliver
/// when construction is growth-free: one allocation (the `Box` header) and the secret
/// staying at the caller's original buffer address. Build without growth — `with_capacity`
/// at the exact final size, or one `resize` — then move the value in.
impl<T: 'static + zeroize::Zeroize> From<T> for Dynamic<T> {
    #[inline(always)]
    fn from(value: T) -> Self {
        Self {
            inner: Box::new(value),
        }
    }
}

// Hex encoding and decoding for Dynamic<Vec<u8>> and Dynamic<[u8]>.
// Dynamic is always heap-allocated, so no no-alloc split is needed.
#[cfg(feature = "encoding-hex")]
impl<B: crate::DynamicBytes + ?Sized> Dynamic<B> {
    /// Decodes a hex string (lowercase, uppercase, or mixed) into
    /// `Dynamic<Vec<u8>>` or `Dynamic<[u8]>`, whichever the caller names.
    ///
    /// The decode buffer is allocated inside `Zeroizing` before a byte is written to it, so
    /// it is wiped when the input is rejected as well as on success, and it stays in
    /// `Zeroizing` until after the `Box` allocation completes (an OOM panic wipes it too).
    pub fn try_from_hex(s: &str) -> Result<Self, crate::error::HexError> {
        let bytes =
            crate::decode_staging::hex(s).map_err(|_| crate::error::HexError::InvalidHex)?;
        Ok(Self::from_protected_bytes(bytes))
    }
}

// Base32 encoding and decoding for Dynamic<Vec<u8>> and Dynamic<[u8]>.
#[cfg(feature = "encoding-base32")]
impl<B: crate::DynamicBytes + ?Sized> Dynamic<B> {
    /// Decodes an uppercase, unpadded Base32 (RFC 4648 §6) string into
    /// `Dynamic<Vec<u8>>` or `Dynamic<[u8]>`, whichever the caller names.
    ///
    /// The decode buffer is allocated inside `Zeroizing` before a byte is written to it, so
    /// it is wiped when the input is rejected as well as on success, and it stays in
    /// `Zeroizing` until after the `Box` allocation completes (an OOM panic wipes it too).
    ///
    /// Decoding is strict about the alphabet, case, padding and length, but lenient
    /// about non-canonical trailing bits: unused bits in the final group are ignored
    /// rather than rejected, so `"MZ"` and `"MY"` both decode to `[0x66]`. Decoding is
    /// therefore not injective — two distinct strings can yield the same bytes, and
    /// only encoder-produced strings are canonical. Do not use the decoded value to
    /// decide that two encoded strings were equal.
    pub fn try_from_base32(s: &str) -> Result<Self, crate::error::Base32Error> {
        let bytes = crate::decode_staging::base32(s)
            .map_err(|_| crate::error::Base32Error::InvalidBase32)?;
        Ok(Self::from_protected_bytes(bytes))
    }
}

// Base64url encoding and decoding for Dynamic<Vec<u8>> and Dynamic<[u8]>.
#[cfg(feature = "encoding-base64")]
impl<B: crate::DynamicBytes + ?Sized> Dynamic<B> {
    /// Decodes a Base64url (unpadded) string into
    /// `Dynamic<Vec<u8>>` or `Dynamic<[u8]>`, whichever the caller names.
    ///
    /// The decode buffer is allocated inside `Zeroizing` before a byte is written to it, so
    /// it is wiped when the input is rejected as well as on success, and it stays in
    /// `Zeroizing` until after the `Box` allocation completes (an OOM panic wipes it too).
    pub fn try_from_base64url(s: &str) -> Result<Self, crate::error::Base64Error> {
        let bytes = crate::decode_staging::base64url(s)
            .map_err(|_| crate::error::Base64Error::InvalidBase64)?;
        Ok(Self::from_protected_bytes(bytes))
    }
}

// Bech32 (BIP-173) encoding and decoding for Dynamic<Vec<u8>> and Dynamic<[u8]>.
#[cfg(feature = "encoding-bech32")]
impl<B: crate::DynamicBytes + ?Sized> Dynamic<B> {
    /// Decodes a Bech32 (BIP-173) string, validating the HRP (case-insensitive), into
    /// `Dynamic<Vec<u8>>` or `Dynamic<[u8]>`, whichever the caller names.
    ///
    /// The decoded buffer is wrapped in `Zeroizing` as soon as it exists, and stays in it
    /// until after the `Box` allocation completes, guaranteeing zeroization even on OOM panic.
    ///
    /// HRP comparison is non-constant-time — this is intentional, as the HRP is public
    /// metadata, not secret material.
    pub fn try_from_bech32(s: &str, expected_hrp: &str) -> Result<Self, crate::error::Bech32Error> {
        Self::try_from_bech32_sized::<{ crate::BECH32_CODE_LENGTH }>(s, expected_hrp)
    }

    /// Like [`try_from_bech32`](Self::try_from_bech32), accepting strings up to `C`
    /// characters.
    ///
    /// `C` is the bech32 code length: the cap on the whole encoded string. Pass the `C`
    /// the string was encoded with, or any larger value. See
    /// [`BECH32_CODE_LENGTH`](crate::BECH32_CODE_LENGTH) for what `C` above
    /// [`BECH32_CODE_LENGTH`](crate::BECH32_CODE_LENGTH) costs.
    pub fn try_from_bech32_sized<const C: usize>(
        s: &str,
        expected_hrp: &str,
    ) -> Result<Self, crate::error::Bech32Error> {
        let checked = bech32::primitives::decode::CheckedHrpstring::new::<
            crate::traits::encoding::bech32::Bech32Sized<C>,
        >(s)
        .map_err(|_| crate::error::Bech32Error::OperationFailed)?;
        // Compare the HRP (public metadata, so not constant-time) *before* materializing any
        // payload byte, so a mismatch never leaves decoded secret material on the heap.
        if !checked.hrp().as_str().eq_ignore_ascii_case(expected_hrp) {
            return Err(crate::error::Bech32Error::UnexpectedHrp);
        }
        // `byte_iter()` is an ExactSizeIterator: one exact-size allocation, so no reallocation
        // leaves a stale copy of the payload behind.
        Ok(Self::from_protected_bytes(zeroize::Zeroizing::new(
            checked.byte_iter().collect(),
        )))
    }

    /// Decodes a Bech32 (BIP-173) string without validating the HRP, into
    /// `Dynamic<Vec<u8>>` or `Dynamic<[u8]>`, whichever the caller names.
    ///
    /// Use [`try_from_bech32`](Self::try_from_bech32) in security-critical code to prevent
    /// cross-protocol confusion attacks.
    pub fn try_from_bech32_unchecked(s: &str) -> Result<Self, crate::error::Bech32Error> {
        Self::try_from_bech32_unchecked_sized::<{ crate::BECH32_CODE_LENGTH }>(s)
    }

    /// Like [`try_from_bech32_unchecked`](Self::try_from_bech32_unchecked), accepting
    /// strings up to `C` characters.
    pub fn try_from_bech32_unchecked_sized<const C: usize>(
        s: &str,
    ) -> Result<Self, crate::error::Bech32Error> {
        let checked = bech32::primitives::decode::CheckedHrpstring::new::<
            crate::traits::encoding::bech32::Bech32Sized<C>,
        >(s)
        .map_err(|_| crate::error::Bech32Error::OperationFailed)?;
        Ok(Self::from_protected_bytes(zeroize::Zeroizing::new(
            checked.byte_iter().collect(),
        )))
    }
}

// Bech32m (BIP-350) encoding and decoding for Dynamic<Vec<u8>> and Dynamic<[u8]>.
#[cfg(feature = "encoding-bech32")]
impl<B: crate::DynamicBytes + ?Sized> Dynamic<B> {
    /// Decodes a Bech32m (BIP-350) string, validating the HRP (case-insensitive), into
    /// `Dynamic<Vec<u8>>` or `Dynamic<[u8]>`, whichever the caller names.
    ///
    /// The decoded buffer is wrapped in `Zeroizing` as soon as it exists, and stays in it
    /// until after the `Box` allocation completes, guaranteeing zeroization even on OOM panic.
    pub fn try_from_bech32m(
        s: &str,
        expected_hrp: &str,
    ) -> Result<Self, crate::error::Bech32Error> {
        Self::try_from_bech32m_sized::<{ crate::BECH32_CODE_LENGTH }>(s, expected_hrp)
    }

    /// Like [`try_from_bech32m`](Self::try_from_bech32m), accepting strings up to `C`
    /// characters. See [`BECH32_CODE_LENGTH`](crate::BECH32_CODE_LENGTH) for what `C` above
    /// [`BECH32_CODE_LENGTH`](crate::BECH32_CODE_LENGTH) costs.
    pub fn try_from_bech32m_sized<const C: usize>(
        s: &str,
        expected_hrp: &str,
    ) -> Result<Self, crate::error::Bech32Error> {
        let checked = bech32::primitives::decode::CheckedHrpstring::new::<
            crate::traits::encoding::bech32m::Bech32mSized<C>,
        >(s)
        .map_err(|_| crate::error::Bech32Error::OperationFailed)?;
        // Compare the HRP (public metadata, so not constant-time) *before* materializing any
        // payload byte, so a mismatch never leaves decoded secret material on the heap.
        if !checked.hrp().as_str().eq_ignore_ascii_case(expected_hrp) {
            return Err(crate::error::Bech32Error::UnexpectedHrp);
        }
        // `byte_iter()` is an ExactSizeIterator: one exact-size allocation, so no reallocation
        // leaves a stale copy of the payload behind.
        Ok(Self::from_protected_bytes(zeroize::Zeroizing::new(
            checked.byte_iter().collect(),
        )))
    }

    /// Decodes a Bech32m (BIP-350) string without validating the HRP, into
    /// `Dynamic<Vec<u8>>` or `Dynamic<[u8]>`, whichever the caller names.
    ///
    /// Use [`try_from_bech32m`](Self::try_from_bech32m) in security-critical code.
    pub fn try_from_bech32m_unchecked(s: &str) -> Result<Self, crate::error::Bech32Error> {
        Self::try_from_bech32m_unchecked_sized::<{ crate::BECH32_CODE_LENGTH }>(s)
    }

    /// Like [`try_from_bech32m_unchecked`](Self::try_from_bech32m_unchecked), accepting
    /// strings up to `C` characters.
    pub fn try_from_bech32m_unchecked_sized<const C: usize>(
        s: &str,
    ) -> Result<Self, crate::error::Bech32Error> {
        let checked = bech32::primitives::decode::CheckedHrpstring::new::<
            crate::traits::encoding::bech32m::Bech32mSized<C>,
        >(s)
        .map_err(|_| crate::error::Bech32Error::OperationFailed)?;
        Ok(Self::from_protected_bytes(zeroize::Zeroizing::new(
            checked.byte_iter().collect(),
        )))
    }
}

/// Construction helpers for `Dynamic<Vec<u8>>` and `Dynamic<[u8]>`.
impl<B: crate::DynamicBytes + ?Sized> Dynamic<B> {
    /// Moves (`Vec<u8>`) or copies (`[u8]`) `protected` bytes into a freshly boxed buffer,
    /// keeping [`zeroize::Zeroizing`] alive across the allocation that can panic.
    ///
    /// # Panic safety
    ///
    /// For `Vec<u8>`, the 24-byte header is the only allocation; for `[u8]`, a box of
    /// exactly the secret's length. Either way `protected` is still in scope while it is
    /// made, so a panic there wipes the secret bytes during unwind, and for `[u8]` the
    /// source is wiped when it drops after the copy.
    ///
    /// For `Vec<u8>`, after the swap `protected` holds an empty `Vec` (no-op to zeroize) and
    /// `Dynamic::from(boxed)` is an infallible struct-field assignment.
    ///
    /// Note: `Box::new(*protected)` would be cleaner but does not compile —
    /// `Zeroizing` implements `Deref` (returning `&T`), not a move-out, so
    /// `*protected` yields a reference rather than an owned value (E0507).
    #[cfg(any(
        feature = "encoding-hex",
        feature = "encoding-base32",
        feature = "encoding-base64",
        feature = "encoding-bech32",
        feature = "serde-deserialize"
    ))]
    #[inline(always)]
    fn from_protected_bytes(protected: zeroize::Zeroizing<alloc::vec::Vec<u8>>) -> Self {
        Self {
            inner: B::from_protected(protected, crate::traits::dynamic_bytes::TOKEN),
        }
    }

    /// Writes into a **sized, pre-zeroed slot** inside the wrapper's own storage.
    ///
    /// The closure receives exactly `len` bytes, **every one of them zero**. That is a
    /// guarantee, not an implementation detail: callers rely on the tail being zero as
    /// real input — a 40-bit RC4 key is five bytes of derived material followed by
    /// eleven zeros, and those zeros are key-schedule input rather than padding, so a
    /// slot that merely happened to be zeroed would produce a different cipher the day
    /// it was not.
    ///
    /// Two allocations, not one: the slot of exactly `len` bytes, plus the `Box<Vec<u8>>`
    /// header the bytes are swapped into on the way out. `tests/lifecycle_trace_heap.rs`
    /// measures `from_random(len)` — this constructor with an RNG in the closure — at
    /// exactly two, "the payload buffer and the `Box<Vec<u8>>` header", and measures
    /// `Dynamic::new(owned)` at exactly one, since a move carries its buffer along. By
    /// allocation count this is therefore the joint most expensive constructor here, tied
    /// with `From<&[u8]>`; the count is not what recommends it. What does is the shape of
    /// the slot: capacity equals length, so the wrapper never holds slack, and the slot is
    /// a slice, so **growth is not expressible** and the reallocation hazard cannot arise.
    ///
    /// # Why it takes a length
    ///
    /// A closure handed an empty `Vec<u8>` to fill would reallocate as it grew, and a
    /// `Vec` reallocation frees the old block **without zeroizing it**, abandoning a copy
    /// of the secret on the heap that nothing would ever wipe. So the closure gets a
    /// slice of the final size instead.
    ///
    /// Pass the final length and fill the slot:
    ///
    /// ```rust
    /// # #[cfg(feature = "alloc")] {
    /// use secure_gate::{Dynamic, RevealSecret};
    ///
    /// let key = Dynamic::<Vec<u8>>::new_with(16, |slot| {
    ///     slot[..4].copy_from_slice(&[1, 2, 3, 4]);
    /// });
    /// assert_eq!(key.expose_secret().len(), 16);
    /// key.with_secret(|b| assert_eq!(&b[4..], &[0u8; 12]));
    /// # }
    /// ```
    ///
    /// # When the length is not known in advance
    ///
    /// Use [`Dynamic::new`] with an empty `Vec` and write through the
    /// [`std::io::Write`] impl, which grows by hand and **zeroizes each abandoned
    /// buffer** before releasing it — the one growth path in this crate that does.
    /// See the [`Write`](#impl-Write-for-Dynamic<Vec<u8>>) impl for what it does and
    /// does not cover. It requires the `std` feature.
    ///
    /// # Panics
    ///
    /// Allocating the slot is `alloc::vec![0u8; len]`, so `len` is not a hint — it is an
    /// allocation request, and both allocator failure modes are reachable through it. A
    /// `len` above `isize::MAX` panics with `"capacity overflow"` before anything is
    /// allocated. A `len` the allocator cannot satisfy reaches `handle_alloc_error`, which
    /// **aborts** rather than unwinding: no destructor runs anywhere, so nothing on this
    /// stack or any frame above it gets the chance to wipe anything.
    ///
    /// `len` is caller-supplied, and the worked example on the fallible sibling is
    /// `try_new_with(len, |slot| r.read_exact(slot))` — precisely the shape where `len`
    /// arrives off the wire, out of a frame header or a manifest. Bound it before passing
    /// it here, for the same reason `deserialize_with_limit` on this type takes a ceiling
    /// instead of trusting the payload: a length field is attacker-controlled input until
    /// something checks it.
    ///
    /// For some callers that bound is not a check that *moves* — it is a check that changes
    /// *shape*, and the difference decides whether there is any work to do. If your length
    /// previously flowed into a decompressor or a comparison further down, a ceiling
    /// enforced after the fact was enough: an overstated length failed a check and you
    /// returned an error. Here the length **is** the allocation, and
    /// `alloc::vec![0u8; 9_000_000_000]` does not fail a comparison — it asks the allocator
    /// for nine gigabytes before any of your code runs. A caller whose length comes from a
    /// trusted source has nothing to do. A caller whose length comes from the file format
    /// has acquired an allocation-sized surface where it previously had a comparison, and
    /// needs a bound it may never have written.
    ///
    /// A panic *inside* `f` is safe: the slot is built zeroed inside the returned
    /// `Dynamic` before `f` runs, so the `Dynamic`'s own `Drop` wipes partially written
    /// bytes during unwinding.
    ///
    /// # See also
    ///
    /// - [`try_new_with`](Self::try_new_with) — when the fill can fail.
    /// - [`SlotWriter`](crate::SlotWriter) — append to the slot without writing offsets
    ///   by hand.
    #[inline(always)]
    pub fn new_with<F>(len: usize, f: F) -> Self
    where
        F: FnOnce(&mut [u8]),
    {
        // Built, zeroed, before a byte of the secret exists; from here on the wrapper's
        // own drop wipes it, on a panic inside `f` too.
        let mut this = Self {
            inner: B::zeroed(len, crate::traits::dynamic_bytes::TOKEN),
        };
        f(this.inner.bytes_mut(crate::traits::dynamic_bytes::TOKEN));
        this
    }

    /// [`new_with`](Self::new_with) for a fill that can fail.
    ///
    /// Identical in every respect but the closure's return type. On `Err` the
    /// partially written slot is **zeroized before the error is returned**: the slot is
    /// already inside the `Dynamic` being built, and that `Dynamic` is dropped on the way
    /// out, so its own `Drop` wipes it and a failed fill leaves nothing behind.
    ///
    /// That is not defensive tidiness. Decoders that write into a caller-supplied
    /// buffer routinely leave real plaintext in it when they fail; `miniz_oxide`'s
    /// `decompress_slice_iter_to_slice` documents exactly that ("in that case the
    /// output buffer will still contain the partial decompression"). Wrapping only on
    /// success would leave that partial secret in an unprotected buffer on every
    /// malformed input.
    ///
    /// # Errors
    ///
    /// Returns whatever the closure returns. The error type is the caller's; this
    /// method neither inspects nor wraps it.
    ///
    /// # A short fill is not an error, and its tail is the zero fill
    ///
    /// The closure returns `Result<(), E>`, which carries no bytes-written count. A closure
    /// that writes fewer than `len` bytes and returns `Ok` therefore yields a full-length
    /// secret whose untouched tail is the pre-zeroing. Nothing here can catch that, because
    /// nothing here is ever told how far the fill got.
    ///
    /// Whether that is the right answer or silent corruption depends on what is in the
    /// slot, and the two shapes differ completely:
    ///
    /// - **Fixed-width key material** — the 40-bit RC4 key from [`new_with`](Self::new_with):
    ///   five bytes of derived material followed by eleven zeros that are key-schedule
    ///   input. The short fill *is* the intended fill, and the zero guarantee is what makes
    ///   it reproducible.
    /// - **A variable-content payload** — a decoded document, a decompressed record, a frame
    ///   whose `len` came from a header that is only an upper bound or is simply wrong (a
    ///   truncated archive, a manifest that disagrees with its contents). Here the zero tail
    ///   is not input. It is missing plaintext in the shape of real data, and whatever
    ///   parses the result downstream will read it as real.
    ///
    /// For the second shape the closure has to check its own coverage and fail, since this
    /// method cannot do it: write through a [`SlotWriter`](crate::SlotWriter) and return
    /// `Err` unless [`is_full()`](crate::SlotWriter::is_full) holds at the end, or keep the
    /// count by hand and compare `bytes_written == slot.len()` before returning `Ok`. The
    /// `read_exact` example below does not demonstrate this and cannot be read as the
    /// pattern to copy — [`read_exact`](std::io::Read::read_exact) surfaces under-fill as
    /// `Err` by construction, so that closure gets the check for free and never writes one.
    ///
    /// # Panics
    ///
    /// The same two allocator failures as [`new_with`](Self::new_with), for the same
    /// reason: the body allocates the slot with the identical `alloc::vec![0u8; len]`. A
    /// `len` above `isize::MAX` panics with `"capacity overflow"`; a `len` the allocator
    /// cannot satisfy reaches `handle_alloc_error`, which aborts without unwinding, so no
    /// destructor anywhere on the stack runs. The `# Errors` section above describes the
    /// closure's failures only — an oversized `len` never reaches the closure and never
    /// arrives as `Err`, so a caller treating `Result` as the complete failure channel is
    /// wrong about this one. Bound `len` before passing it; the example below takes it
    /// straight from its caller, which in real code means straight from a frame header.
    ///
    /// A panic *inside* `f` is safe, exactly as in `new_with`: the slot is inside the
    /// `Dynamic` being built for the whole call, and that `Dynamic`'s own `Drop` wipes it
    /// during unwinding.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(all(feature = "alloc", feature = "std"))] {
    /// use secure_gate::{Dynamic, RevealSecret};
    /// use std::io::Read;
    ///
    /// fn read_exact_secret<R: Read>(r: &mut R, len: usize) -> std::io::Result<Dynamic<Vec<u8>>> {
    ///     Dynamic::<Vec<u8>>::try_new_with(len, |slot| r.read_exact(slot))
    /// }
    ///
    /// let secret = read_exact_secret(&mut [7u8; 32].as_slice(), 32).unwrap();
    /// assert_eq!(secret.expose_secret().len(), 32);
    ///
    /// // A short read fails, and yields no secret at all.
    /// assert!(read_exact_secret(&mut [7u8; 8].as_slice(), 32).is_err());
    /// # }
    /// ```
    ///
    /// This is also how to generate from an RNG you supply. Anything that fills a byte slice
    /// works, whatever crate or `rand` version it comes from;
    /// [`from_random`](Self::from_random) covers the system RNG.
    ///
    /// ```rust
    /// # #[cfg(all(feature = "alloc", feature = "rand"))] {
    /// use rand::rngs::StdRng;
    /// use rand::{SeedableRng, TryRng};
    /// use secure_gate::Dynamic;
    ///
    /// let mut rng = StdRng::from_seed([9u8; 32]);
    /// let nonce = Dynamic::<Vec<u8>>::try_new_with(24, |b| rng.try_fill_bytes(b)).expect("rng fill");
    /// # }
    /// ```
    #[inline(always)]
    pub fn try_new_with<F, E>(len: usize, f: F) -> Result<Self, E>
    where
        F: FnOnce(&mut [u8]) -> Result<(), E>,
    {
        let mut this = Self {
            inner: B::zeroed(len, crate::traits::dynamic_bytes::TOKEN),
        };
        // On the error path `this` is dropped here, so the wrapper wipes whatever the
        // closure wrote before it gave up. That is why the buffer is built before the
        // fill rather than assembled after it.
        f(this.inner.bytes_mut(crate::traits::dynamic_bytes::TOKEN))?;
        Ok(this)
    }
}

// `new_with` was removed here in 0.9.0-rc.12, deliberately and with no replacement.
//
// It handed the closure a zero-capacity `String`, so filling it reallocated and each
// reallocation freed the old buffer unwiped — the same defect the `Vec<u8>` arm had,
// in the arm most likely to hold a password. The `Vec` arm was fixed by handing a
// sized slot instead; no such slot exists for text. A `&mut str` cannot be usefully
// filled: `String` must hold valid UTF-8 and characters have variable byte widths, so
// a fixed byte window is not a place you can write arbitrary text into.
//
// The replacement is to build a pre-sized `String` yourself and move it in with
// `Dynamic::new`, which transfers the buffer rather than copying it — so the
// allocation you filled is the allocation the wrapper protects. `From<&str>` copies
// and leaves your source unwiped; prefer `new` for secret material.
//
// That leaves this impl block with no unconditional member: `from_protected_bytes`
// below exists solely for `deserialize_with_limit`, so — unlike the `Vec<u8>` arm's
// copy of the same helper, which `new_with`/`try_new_with` keep alive unconditionally
// — it is `#[cfg]`-gated on `serde-deserialize` rather than left to go dead under
// `alloc` alone.
#[cfg(feature = "serde-deserialize")]
impl Dynamic<alloc::string::String> {
    /// Heap-only construction from a `Zeroizing<String>`. Swaps the protected
    /// buffer into a default-initialized `Box<String>` and returns the
    /// `Dynamic`. Panic-safe: if the `Box` allocation OOM-panics, `protected`
    /// stays live and `Zeroizing::drop` zeroes the secret bytes during unwind.
    #[inline(always)]
    fn from_protected_bytes(mut protected: zeroize::Zeroizing<alloc::string::String>) -> Self {
        // Only fallible allocation; protected stays live across it for panic-safety
        let mut boxed = Box::<alloc::string::String>::default();
        core::mem::swap(&mut *boxed, &mut *protected);
        Self::from(boxed)
    }
}

/// Hex encoding for `Dynamic<Vec<u8>>` and `Dynamic<[u8]>`.
///
/// Deliberately **not** implemented for `Dynamic<String>` — hex-encoding
/// textual secrets is a design smell; convert explicitly inside `with_secret`
/// if genuinely needed. Bring the trait into scope: `use secure_gate::ToHex;`.
///
/// ```rust
/// # #[cfg(feature = "encoding-hex")] {
/// use secure_gate::{Dynamic, ToHex};
///
/// let token: Dynamic<Vec<u8>> = Dynamic::from(&[0xDEu8, 0xAD][..]);
/// assert_eq!(&*token.to_hex(), "dead");
/// # }
/// ```
#[cfg(feature = "encoding-hex")]
impl<B: crate::DynamicBytes + ?Sized> ToHex for Dynamic<B> {
    #[inline]
    fn to_hex(&self) -> crate::EncodedSecret {
        self.inner
            .bytes(crate::traits::dynamic_bytes::TOKEN)
            .to_hex()
    }

    #[inline]
    fn to_hex_upper(&self) -> crate::EncodedSecret {
        self.inner
            .bytes(crate::traits::dynamic_bytes::TOKEN)
            .to_hex_upper()
    }
}

/// Base32 encoding for `Dynamic<Vec<u8>>` and `Dynamic<[u8]>`.
///
/// Bring the trait into scope: `use secure_gate::ToBase32;`.
///
/// ```rust
/// # #[cfg(feature = "encoding-base32")] {
/// use secure_gate::{Dynamic, ToBase32};
///
/// let token: Dynamic<Vec<u8>> = Dynamic::from(&[0xABu8; 4][..]);
/// assert_eq!(&*token.to_base32(), "VOV2XKY");
/// # }
/// ```
#[cfg(feature = "encoding-base32")]
impl<B: crate::DynamicBytes + ?Sized> ToBase32 for Dynamic<B> {
    #[inline]
    fn to_base32(&self) -> crate::EncodedSecret {
        self.inner
            .bytes(crate::traits::dynamic_bytes::TOKEN)
            .to_base32()
    }
}

/// Base64url encoding for `Dynamic<Vec<u8>>` and `Dynamic<[u8]>`.
///
/// Bring the trait into scope: `use secure_gate::ToBase64Url;`.
///
/// ```rust
/// # #[cfg(feature = "encoding-base64")] {
/// use secure_gate::{Dynamic, ToBase64Url};
///
/// let token: Dynamic<Vec<u8>> = Dynamic::from(&[0xABu8; 4][..]);
/// assert_eq!(&*token.to_base64url(), "q6urqw");
/// # }
/// ```
#[cfg(feature = "encoding-base64")]
impl<B: crate::DynamicBytes + ?Sized> ToBase64Url for Dynamic<B> {
    #[inline]
    fn to_base64url(&self) -> crate::EncodedSecret {
        self.inner
            .bytes(crate::traits::dynamic_bytes::TOKEN)
            .to_base64url()
    }
}

/// Bech32 encoding for `Dynamic<Vec<u8>>` and `Dynamic<[u8]>`.
///
/// Bring the trait into scope: `use secure_gate::ToBech32;`.
#[cfg(feature = "encoding-bech32")]
impl<B: crate::DynamicBytes + ?Sized> ToBech32 for Dynamic<B> {
    #[inline]
    fn try_to_bech32(
        &self,
        hrp: &str,
        case: crate::Case,
    ) -> Result<crate::EncodedSecret, crate::error::Bech32Error> {
        self.inner
            .bytes(crate::traits::dynamic_bytes::TOKEN)
            .try_to_bech32(hrp, case)
    }

    #[inline]
    fn try_to_bech32_sized<const C: usize>(
        &self,
        hrp: &str,
        case: crate::Case,
    ) -> Result<crate::EncodedSecret, crate::error::Bech32Error> {
        self.inner
            .bytes(crate::traits::dynamic_bytes::TOKEN)
            .try_to_bech32_sized::<C>(hrp, case)
    }
}

/// Bech32m encoding for `Dynamic<Vec<u8>>` and `Dynamic<[u8]>`.
///
/// Bring the trait into scope: `use secure_gate::ToBech32m;`.
#[cfg(feature = "encoding-bech32")]
impl<B: crate::DynamicBytes + ?Sized> ToBech32m for Dynamic<B> {
    #[inline]
    fn try_to_bech32m(
        &self,
        hrp: &str,
        case: crate::Case,
    ) -> Result<crate::EncodedSecret, crate::error::Bech32Error> {
        self.inner
            .bytes(crate::traits::dynamic_bytes::TOKEN)
            .try_to_bech32m(hrp, case)
    }

    #[inline]
    fn try_to_bech32m_sized<const C: usize>(
        &self,
        hrp: &str,
        case: crate::Case,
    ) -> Result<crate::EncodedSecret, crate::error::Bech32Error> {
        self.inner
            .bytes(crate::traits::dynamic_bytes::TOKEN)
            .try_to_bech32m_sized::<C>(hrp, case)
    }
}

// RevealSecret — one generic impl covers every inner type, including local
// user-defined ones. Length reporting lives in the narrower `SecretLen`
// (implemented for `Dynamic<String>` and `Dynamic<Vec<T>>`), because a generic
// `T` has no meaningful length.
impl<T: ?Sized + zeroize::Zeroize> crate::RevealSecret for Dynamic<T> {
    type Inner = T;

    #[inline(always)]
    fn with_secret<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&T) -> R,
    {
        f(&self.inner)
    }

    #[inline(always)]
    fn expose_secret(&self) -> &T {
        &self.inner
    }

    /// Consumes `self` and transfers ownership of the plain inner value.
    ///
    /// **Allocation note:** allocates one small `Box<T>` sentinel (24 bytes for
    /// `String`/`Vec` on 64-bit) before the swap. If that allocation panics (OOM),
    /// `self.inner` is unchanged and `Dynamic::drop` zeroizes the real secret during
    /// unwind — confidentiality is preserved. This is the same OOM-safety pattern
    /// used by `from_protected_bytes` and `deserialize_with_limit`.
    ///
    /// See [`RevealSecret::into_inner`](crate::RevealSecret::into_inner) for the full
    /// contract. Protection ends at this call: the returned value is an ordinary
    /// `String` / `Vec<T>`, moved out without copying.
    #[inline(always)]
    fn into_inner(mut self) -> T
    where
        Self: Sized,
        Self::Inner: Sized + crate::SentinelValue + zeroize::Zeroize,
    {
        // Swap in a sentinel. If Box::new panics (OOM) before the swap, self.inner
        // still holds the real secret and Dynamic::drop zeroizes it on unwind.
        // After the swap, self.inner is an inert sentinel — zeroized on
        // Dynamic::drop as a no-op. `*boxed` deref-moves the value out of the Box.
        let boxed = core::mem::replace(
            &mut self.inner,
            Box::new(crate::SentinelValue::sentinel_value()),
        );
        *boxed
    }
}

// RevealSecretMut — same generic coverage as RevealSecret.
impl<T: ?Sized + zeroize::Zeroize> crate::RevealSecretMut for Dynamic<T> {
    #[inline(always)]
    fn with_secret_mut<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut T) -> R,
    {
        f(&mut self.inner)
    }

    #[inline(always)]
    fn expose_secret_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

#[cfg(feature = "serde-deserialize")]
impl Dynamic<[u8]> {
    /// Copies `bytes` into a slice of exactly their length, built inside the wrapper.
    /// `vec![0u8; len]` has capacity equal to its length, so `into_boxed_slice` keeps the
    /// allocation instead of copying it. The source stays the caller's to wipe.
    #[inline(always)]
    fn copy_of(bytes: &[u8]) -> Self {
        let mut this = Self {
            inner: alloc::vec![0u8; bytes.len()].into_boxed_slice(),
        };
        this.inner.copy_from_slice(bytes);
        this
    }
}

// Random generation
#[cfg(feature = "rand")]
impl<B: crate::DynamicBytes + ?Sized> Dynamic<B> {
    /// Fills a new buffer of `len` cryptographically secure random bytes and wraps it, as
    /// `Dynamic<Vec<u8>>` or `Dynamic<[u8]>`, whichever the caller names.
    ///
    /// Uses the system RNG ([`SysRng`](rand::rngs::SysRng)). Requires the `rand` feature (and
    /// `alloc`, which `Dynamic` always needs).
    ///
    /// # Panics
    ///
    /// Panics if the system RNG fails to provide bytes ([`TryRng::try_fill_bytes`](rand::TryRng::try_fill_bytes)
    /// returns `Err`). This is treated as a fatal environment error.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(all(feature = "alloc", feature = "rand"))]
    /// use secure_gate::{Dynamic, RevealSecret, SecretLen};
    ///
    /// # #[cfg(all(feature = "alloc", feature = "rand"))]
    /// # {
    /// let nonce: Dynamic<Vec<u8>> = Dynamic::from_random(24);
    /// assert_eq!(nonce.len(), 24);
    /// # }
    /// ```
    #[inline]
    pub fn from_random(len: usize) -> Self {
        Self::new_with(len, |slot| {
            SysRng
                .try_fill_bytes(slot)
                .expect("SysRng failure is a program error");
        })
    }
}

/// Constant-time equality for `Dynamic<T>` — routes through [`expose_secret()`](crate::RevealSecret::expose_secret).
///
/// `==` is **deliberately not implemented**. Always use `ct_eq`.
#[cfg(feature = "ct-eq")]
impl<T: ?Sized + zeroize::Zeroize> crate::ConstantTimeEq for Dynamic<T>
where
    T: crate::ConstantTimeEq,
    Self: crate::RevealSecret<Inner = T>,
{
    fn ct_eq(&self, other: &Self) -> bool {
        self.expose_secret().ct_eq(other.expose_secret())
    }
}

/// Always prints `[REDACTED]` — secrets never appear in debug output.
impl<T: ?Sized + zeroize::Zeroize> core::fmt::Debug for Dynamic<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Opt-in cloning — requires `cloneable` feature and [`CloneableSecret`](crate::CloneableSecret)
/// marker. Each clone is independently zeroized on drop, but cloning increases exposure surface.
#[cfg(feature = "cloneable")]
impl<T: zeroize::Zeroize + crate::CloneableSecret> Clone for Dynamic<T> {
    fn clone(&self) -> Self {
        Self::new(self.inner.clone())
    }
}

// ---------------------------------------------------------------------------
// Streaming I/O (std only)
// ---------------------------------------------------------------------------

/// Streams bytes directly into the protected buffer via [`RevealSecretMut`](crate::RevealSecretMut).
///
/// Data flows **into** the wrapper, so no intermediate unprotected `Vec<u8>` is
/// accumulated before wrapping.
///
/// # Growth wipes the outgoing buffer
///
/// Writing past the current capacity cannot simply delegate to `Vec`: `Vec` would
/// reallocate, copy the secret into the new allocation, and hand the **old** one
/// back to the allocator with the plaintext still in it. This impl grows by hand
/// instead — it allocates the larger buffer, copies, zeroizes the old buffer
/// (contents and spare capacity), and only then releases it.
///
/// Pre-sizing with `Vec::with_capacity` avoids the copy altogether and is worth
/// doing when the length is known up front:
///
/// ```rust
/// # #[cfg(feature = "std")] {
/// use std::io::Write;
/// use secure_gate::Dynamic;
///
/// let payload = b"decrypted payload";
///
/// // Pre-sized: no growth, so no copy and nothing to wipe.
/// let mut secret = Dynamic::<Vec<u8>>::new(Vec::with_capacity(payload.len()));
/// secret.write_all(payload).unwrap();
/// # }
/// ```
///
/// # This is the sanctioned path for a secret whose length you do not know
///
/// **Every buffer this impl abandons is zeroized before it is released.** Growth is done
/// by hand — allocate, copy, wipe the old buffer including its spare capacity, and only
/// then drop it — rather than through `Vec`'s own reallocation, which would free the old
/// block still holding plaintext. Doubling is amortized, so streaming stays linear.
///
/// That makes the pair complete: **length known before the fill, use
/// [`new_with(len, …)`](Dynamic::new_with); length not known, use `Write`.** Neither
/// leaves an unwiped copy behind, and there is no third case that needs one.
///
/// ## What it does not cover
///
/// The guarantee is about the buffer this impl owns, and three things sit outside it:
///
/// - **A caller who grows the `Vec` themselves**, through
///   [`with_secret_mut`](crate::RevealSecretMut::with_secret_mut) or
///   [`expose_secret_mut`](crate::RevealSecretMut::expose_secret_mut), holds
///   `&mut Vec<u8>` directly and their reallocation is `Vec`'s, not this one's. See the
///   heap-reallocation residue section in `SECURITY.md`.
/// - **Whatever fed the bytes in.** Driving this with [`std::io::copy`] passes every byte
///   through `copy`'s own transfer buffer, and [`std::io::Stdin`] keeps a
///   process-lifetime internal buffer. Nothing here can reach either. To close the
///   transfer buffer too, read into a [`Fixed<[u8; N]>`](crate::Fixed) chunk and
///   `write_all` each chunk through this impl.
/// - **The `std` feature**, which gates this impl. Without it the recommended path for
///   unknown-length secrets is simply absent, and the growable alternatives are not.
///
/// What it eliminates is the **unbounded chain** of unwiped reallocations — the residue
/// that scales with input size, leaving an intermediate copy on the heap for every
/// growth. That is the defect; the buffers above are bounded and do not accumulate.
#[cfg(feature = "std")]
impl std::io::Write for Dynamic<alloc::vec::Vec<u8>> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        use crate::RevealSecretMut;
        use zeroize::Zeroize;

        self.with_secret_mut(|v: &mut alloc::vec::Vec<u8>| -> std::io::Result<usize> {
            if buf.len() > v.capacity() - v.len() {
                // Grow by hand so the outgoing allocation can be wiped before the
                // allocator gets it back. `Vec`'s own realloc would copy the secret
                // into the new buffer and free the old one still holding plaintext.
                let needed = v.len().checked_add(buf.len()).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::OutOfMemory, "capacity overflow")
                })?;
                // Mirror `Vec`'s amortized doubling so repeated writes stay linear.
                let new_cap = core::cmp::max(needed, v.capacity().saturating_mul(2));
                let mut grown = alloc::vec::Vec::with_capacity(new_cap);
                grown.extend_from_slice(v);
                // Wipes contents *and* spare capacity, and sets len to 0 without
                // freeing; the assignment below then drops the zeroed allocation.
                v.zeroize();
                *v = grown;
            }
            v.extend_from_slice(buf);
            Ok(buf.len())
        })
    }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Cursor-like reader over a [`Dynamic<Vec<u8>>`].
///
/// Created by [`Dynamic::<Vec<u8>>::as_reader`]. Borrows the `Dynamic`
/// immutably and tracks the read position internally. Each [`Read::read`](std::io::Read::read)
/// call goes through [`with_secret`](crate::RevealSecret::with_secret),
/// preserving the crate's auditable access model.
///
/// # Security
///
/// `Read::read()` copies secret bytes into the caller-supplied buffer.
/// The caller is responsible for zeroizing that buffer. Prefer piping
/// directly into encrypted writers (`io::copy` into an encryptor, etc.)
/// rather than reading into intermediate `Vec<u8>` buffers.
///
/// The `Dynamic` wrapper continues to zeroize its contents on drop
/// regardless of how many bytes have been read out.
#[cfg(feature = "std")]
pub struct DynamicReader<'a> {
    secret: &'a Dynamic<alloc::vec::Vec<u8>>,
    offset: usize,
}

#[cfg(feature = "std")]
impl std::io::Read for DynamicReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let offset = self.offset;
        let n = self.secret.with_secret(|v| {
            let remaining = v.len().saturating_sub(offset);
            let n = remaining.min(buf.len());
            buf[..n].copy_from_slice(&v[offset..offset + n]);
            n
        });
        self.offset += n;
        Ok(n)
    }
}

#[cfg(feature = "std")]
impl Dynamic<alloc::vec::Vec<u8>> {
    /// Returns a [`DynamicReader`] that implements [`std::io::Read`].
    ///
    /// This replaces the common `with_secret` + `Cursor` boilerplate:
    ///
    /// ```rust
    /// # #[cfg(feature = "std")] {
    /// use std::io;
    /// use secure_gate::Dynamic;
    ///
    /// let secret = Dynamic::<Vec<u8>>::new(vec![1, 2, 3, 4]);
    ///
    /// // Before: awkward closure + Cursor dance
    /// // secret.with_secret(|b| io::copy(&mut Cursor::new(b), &mut encryptor))?;
    ///
    /// // After: pipe directly into an encrypted writer — no intermediate buffer
    /// let mut encryptor = io::sink(); // stand-in for a real encryptor
    /// io::copy(&mut secret.as_reader(), &mut encryptor).unwrap();
    /// # }
    /// ```
    ///
    /// # Security
    ///
    /// Each `read()` call copies secret bytes into the caller's buffer.
    /// Prefer piping directly into encrypted writers rather than reading
    /// into intermediate buffers. The caller is responsible for zeroizing
    /// any destination buffer.
    #[inline]
    pub fn as_reader(&self) -> DynamicReader<'_> {
        DynamicReader {
            secret: self,
            offset: 0,
        }
    }
}

/// Opt-in serialization — requires `serde-serialize` feature and
/// [`SerializableSecret`](crate::SerializableSecret) marker. Serialization exposes the
/// full secret — audit every impl.
#[cfg(feature = "serde-serialize")]
impl<T: zeroize::Zeroize + crate::SerializableSecret> serde::Serialize for Dynamic<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.inner.serialize(serializer)
    }
}

// Deserialize

/// Default maximum byte length accepted when deserializing `Dynamic<Vec<u8>>`,
/// `Dynamic<[u8]>` or `Dynamic<String>` via the standard `serde::Deserialize` impl (1 MiB).
///
/// Pass a custom value to [`Dynamic::deserialize_with_limit`] when a different
/// ceiling is required.
///
/// **Important:** the limit bounds what this crate holds: a byte sequence is rejected at
/// the first byte past it, and text before it is copied. It does not bound what the
/// deserializer or the transport has already read into memory. For untrusted input,
/// enforce size limits at the transport or parser layer upstream as well.
#[cfg(feature = "serde-deserialize")]
pub const MAX_DESERIALIZE_BYTES: usize = 1_048_576;

#[cfg(feature = "serde-deserialize")]
impl Dynamic<alloc::vec::Vec<u8>> {
    /// Deserializes into `Dynamic<Vec<u8>>`, rejecting payloads larger than `limit` bytes.
    ///
    /// The standard [`serde::Deserialize`] impl calls this with [`MAX_DESERIALIZE_BYTES`].
    /// Use this method directly when you need a tighter or looser ceiling.
    ///
    /// **Zeroization scope.** The bytes are read straight into a buffer this crate wipes;
    /// no plain `Vec<u8>` exists in between (since 0.9.1, #249). That buffer is wiped when
    /// the input is rejected partway, when it exceeds `limit`, and each time it is
    /// outgrown: growth is done by hand (allocate, copy, wipe the old buffer), because
    /// `Vec`'s own growth frees the old block as it is. Through 0.9.0 the value was built
    /// by `Vec<u8>`'s own impl first, which left a 1008-byte secret read from a JSON array
    /// in 5 freed blocks holding 992 of its bytes; `tests/heap_zeroize.rs` now gates on
    /// those blocks being zero.
    ///
    /// **Where it stops:** at the deserializer. Whatever it buffers before handing a byte
    /// over is its own, and so is the input it reads from. See `SECURITY.md`, "Feature
    /// Security Implications".
    ///
    /// **The limit** is checked as each byte arrives, so this crate never holds more than
    /// `limit` bytes of an over-long secret, and stops reading at the first byte past it.
    /// It bounds what this crate allocates, not what the deserializer or the transport
    /// already has in memory: for untrusted input, cap the size upstream as well.
    ///
    /// Accepts what `Vec<u8>` accepts: a sequence of bytes, asked for with
    /// `deserialize_seq`.
    pub fn deserialize_with_limit<'de, D>(deserializer: D, limit: usize) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // `deserialize_seq`, as `Vec<u8>`'s own impl asks, so every format accepts and
        // rejects exactly what it did; only the buffer being filled is different.
        let buf = deserializer.deserialize_seq(crate::secret_visitor::BytesVisitor { limit })?;
        Ok(Self::from_protected_bytes(buf))
    }
}

#[cfg(feature = "serde-deserialize")]
impl Dynamic<String> {
    /// Deserializes into `Dynamic<String>`, rejecting payloads larger than `limit` bytes.
    ///
    /// The standard [`serde::Deserialize`] impl calls this with [`MAX_DESERIALIZE_BYTES`].
    /// Use this method directly when you need a tighter or looser ceiling.
    ///
    /// **Zeroization scope.** No plain `String` exists in between (since 0.9.1, #249).
    /// Text the deserializer lends (`visit_str`) is checked against `limit` and then
    /// copied once, into a buffer of exactly its length that this crate wipes. Text it
    /// gives (`visit_string`) is taken over as it is and wiped from then on, on rejection
    /// too. Through 0.9.0 the value was built by `String`'s own impl first and wrapped
    /// afterwards.
    ///
    /// **Where it stops:** at the deserializer. A string has to be assembled somewhere
    /// before it can be handed over, and that somewhere is the deserializer's: with
    /// `serde_json`, a string containing escapes is unescaped into its scratch buffer,
    /// which grows as a plain `Vec` and is freed unwiped. This crate never holds that
    /// buffer and cannot wipe it. Text without escapes read from a `&str` is lent straight
    /// out of the input. See `SECURITY.md`, "Feature Security Implications". Where that
    /// residue matters, do not deserialize the secret as text: size a `String` to its
    /// exact final length yourself and move it in with [`Dynamic::new`](Dynamic::new).
    ///
    /// **The limit** is checked before the text is copied or kept. It bounds what this
    /// crate holds, not what the deserializer or the transport already has in memory: for
    /// untrusted input, cap the size upstream as well.
    ///
    /// Accepts what `String` accepts, asked for with `deserialize_string`.
    pub fn deserialize_with_limit<'de, D>(deserializer: D, limit: usize) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // `deserialize_string`, as `String`'s own impl asks.
        let buf =
            deserializer.deserialize_string(crate::secret_visitor::StringVisitor { limit })?;
        Ok(Self::from_protected_bytes(buf))
    }
}

#[cfg(feature = "serde-deserialize")]
impl<'de> serde::Deserialize<'de> for Dynamic<alloc::vec::Vec<u8>> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::deserialize_with_limit(deserializer, MAX_DESERIALIZE_BYTES)
    }
}

#[cfg(feature = "serde-deserialize")]
impl<'de> serde::Deserialize<'de> for Dynamic<String> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::deserialize_with_limit(deserializer, MAX_DESERIALIZE_BYTES)
    }
}

#[cfg(feature = "serde-deserialize")]
impl Dynamic<[u8]> {
    /// Deserializes into `Dynamic<[u8]>`, rejecting payloads larger than `limit` bytes.
    ///
    /// Reads exactly as the `Dynamic<Vec<u8>>` method of the same name does, with the same wiping and the same limit, then copies the bytes once into a
    /// slice of exactly their length and wipes the buffer they were read into. The
    /// standard [`serde::Deserialize`] impl calls this with [`MAX_DESERIALIZE_BYTES`].
    pub fn deserialize_with_limit<'de, D>(deserializer: D, limit: usize) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let buf = deserializer.deserialize_seq(crate::secret_visitor::BytesVisitor { limit })?;
        Ok(Self::copy_of(&buf))
    }
}

#[cfg(feature = "serde-deserialize")]
impl<'de> serde::Deserialize<'de> for Dynamic<[u8]> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::deserialize_with_limit(deserializer, MAX_DESERIALIZE_BYTES)
    }
}

/// Zeroizes the inner value (including `Vec`/`String` spare capacity).
///
/// **Warning:** does not run under `panic = "abort"`.
impl<T: ?Sized + zeroize::Zeroize> zeroize::Zeroize for Dynamic<T> {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

/// Unconditionally zeroizes the inner value when the wrapper is dropped.
///
/// **Warning:** `Drop` does not run under `panic = "abort"`.
impl<T: ?Sized + zeroize::Zeroize> Drop for Dynamic<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Marker confirming that `Dynamic<T>` always zeroizes on drop.
impl<T: ?Sized + zeroize::Zeroize> zeroize::ZeroizeOnDrop for Dynamic<T> {}

impl crate::SecretLen for Dynamic<String> {
    #[inline(always)]
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl<T: zeroize::Zeroize> crate::SecretLen for Dynamic<Vec<T>> {
    #[inline(always)]
    fn len(&self) -> usize {
        self.inner.len()
    }

    #[inline(always)]
    fn byte_len(&self) -> usize {
        self.inner.len() * core::mem::size_of::<T>()
    }
}

/// Length of a boxed slice. `byte_len` is the size in bytes, as for `Dynamic<Vec<T>>`.
impl<T: zeroize::Zeroize> crate::SecretLen for Dynamic<[T]>
where
    [T]: zeroize::Zeroize,
{
    #[inline(always)]
    fn len(&self) -> usize {
        self.inner.len()
    }

    #[inline(always)]
    fn byte_len(&self) -> usize {
        core::mem::size_of_val::<[T]>(&self.inner)
    }
}
