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
//! - **Heap-only** — secret bytes never reside on the stack. Inner value stored in `Box<T>`.
//! - **Opt-in `Clone`** — requires `T: CloneableSecret` and the `cloneable` feature.
//! - **Opt-in `Serialize`** — requires the `SerializableSecret` marker and the
//!   `serde-serialize`/`serde-deserialize` features.
//! - **Panic safety** — all decode constructors use the `from_protected_bytes` pattern:
//!   a `Zeroizing` wrapper survives OOM panics from `Box::new`.
//!
//! # Choosing the inner type for security
//!
//! Different inner types have different reallocation-residue profiles:
//!
//! | Inner type | Realloc surface | Use case |
//! |---|---|---|
//! | `Dynamic<[u8; N]>` (boxed array) | **None** — fixed size | Long-lived known-size keys held on the heap |
//! | `Dynamic<Vec<u8>>` pre-sized | None *if* you avoid capacity-growing mutations | Variable-length secrets with a known upper bound |
//! | `Dynamic<Vec<u8>>` growable | **Yes** — each realloc leaves the old buffer unzeroed | Convenient, but see realloc-residue warning below |
//! | `Dynamic<String>` | Same as `Dynamic<Vec<u8>>` | Passwords, API keys |
//!
//! For **long-lived, known-size key material**, prefer `Dynamic<[u8; N]>` —
//! it combines `Dynamic`'s heap-only property with zero realloc surface.
//! See `SECURITY.md` § "Inherent Rust Limitations" for the broader discussion.
//!
//! # Construction
//!
//! | Constructor | Notes |
//! |---|---|
//! | [`Dynamic::new(value)`](Dynamic::new) | Ergonomic default; accepts `String`, `Vec<u8>`, `&str`, `Box<T>`, etc. |
//! | [`Dynamic::<Vec<u8>>::new_with(f)`](Dynamic::new_with) | Scoped; for API symmetry with [`Fixed::new_with`](crate::Fixed::new_with) |
//! | [`Dynamic::<String>::new_with(f)`](Dynamic::new_with) | Scoped; for API symmetry |
//!
//! Unlike [`Fixed::new_with`](crate::Fixed::new_with), `Dynamic` is already heap-only so
//! `new_with` exists for consistent API idiom, not for stack-residue avoidance.
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
//! # Warning
//!
//! Ensure your profile sets `panic = "unwind"` — `panic = "abort"` skips destructors
//! and therefore skips zeroization. (`Dynamic` cannot be `static` since it requires
//! `Box` allocation, so the static-secret warning from `Fixed` does not apply.)
//!
//! For `Dynamic<Vec<_>>` and `Dynamic<String>`, capacity-changing mutations can
//! cause the standard allocator to free the previous buffer without zeroizing it.
//! Pre-allocate to the maximum size, use capacity-stable mutations, prefer
//! `Dynamic<[u8; N]>` (no realloc surface) for known-size heap secrets, or use
//! [`Fixed<T>`](crate::Fixed) for known-size stack secrets. See `SECURITY.md` for
//! the full threat-model discussion and deployment-level mitigations including
//! the [`zeroizing-alloc`](https://crates.io/crates/zeroizing-alloc) global
//! allocator.
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

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base32",
    feature = "encoding-base64",
    feature = "encoding-bech32",
    feature = "ct-eq",
    feature = "std",
))]
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
use rand::{rngs::OsRng, TryCryptoRng, TryRngCore};

// Dynamic<Vec<u8>> is always alloc-dependent, so the alloc-gated blanket traits
// are always available when encoding features are enabled for this type.
#[cfg(feature = "encoding-base32")]
use crate::traits::decoding::base32::FromBase32Str;
#[cfg(feature = "encoding-base64")]
use crate::traits::decoding::base64_url::FromBase64UrlStr;
#[cfg(feature = "encoding-bech32")]
use crate::traits::decoding::bech32::FromBech32Str;
#[cfg(feature = "encoding-bech32")]
use crate::traits::decoding::bech32m::FromBech32mStr;
#[cfg(feature = "encoding-hex")]
use crate::traits::decoding::hex::FromHexStr;

/// Zero-cost heap-allocated wrapper for variable-length secrets.
///
/// `Dynamic<T>` stores a `T: Zeroize` value in a `Box<T>` and unconditionally zeroizes
/// it on drop (including `Vec`/`String` spare capacity). There is no `Deref`, `AsRef`,
/// or `Copy` — every access is explicit through [`RevealSecret`](crate::RevealSecret)
/// or [`RevealSecretMut`](crate::RevealSecretMut).
///
/// This is **not** `Fixed<T>` — it is the heap-allocated alternative for variable-length
/// secrets. Secret bytes never reside on the stack.
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
/// # Constructors for `Dynamic<Vec<u8>>`
///
/// | Constructor | Feature | Notes |
/// |---|---|---|
/// | [`new(value)`](Self::new) | — | Accepts `Vec<u8>`, `&[u8]`, `Box<Vec<u8>>` |
/// | [`new_with(f)`](Self::new_with) | — | Scoped closure construction |
/// | [`try_from_hex(s)`](Self::try_from_hex) | `encoding-hex` | Constant-time hex decoding |
/// | [`try_from_base32(s)`](Self::try_from_base32) | `encoding-base32` | Constant-time Base32 decoding |
/// | [`try_from_base64url(s)`](Self::try_from_base64url) | `encoding-base64` | Constant-time Base64url decoding |
/// | [`try_from_bech32(s, hrp)`](Self::try_from_bech32) | `encoding-bech32` | HRP-validated Bech32 |
/// | [`try_from_bech32_unchecked(s)`](Self::try_from_bech32_unchecked) | `encoding-bech32` | Bech32 without HRP check |
/// | [`try_from_bech32m(s, hrp)`](Self::try_from_bech32m) | `encoding-bech32` | HRP-validated Bech32m |
/// | [`try_from_bech32m_unchecked(s)`](Self::try_from_bech32m_unchecked) | `encoding-bech32` | Bech32m without HRP check |
/// | [`from_random(len)`](Self::from_random) | `rand` | System RNG |
/// | [`from_rng(len, rng)`](Self::from_rng) | `rand` | Custom RNG |
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
    /// Accepts any type that implements `Into<Box<T>>` — including owned values,
    /// `Box<T>`, `String`, `Vec<u8>`, `&str` (via the blanket `From<&str>` impl), etc.
    ///
    /// Equivalent to `Dynamic::from(value)` — `#[doc(alias = "from")]` is set so both
    /// names appear in docs.rs search.
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

/// Zero-copy wrapping of an already-boxed value.
impl<T: ?Sized + zeroize::Zeroize> From<Box<T>> for Dynamic<T> {
    #[inline(always)]
    fn from(boxed: Box<T>) -> Self {
        Self { inner: boxed }
    }
}

/// Copies a byte slice to the heap and wraps it.
impl From<&[u8]> for Dynamic<Vec<u8>> {
    #[inline(always)]
    fn from(slice: &[u8]) -> Self {
        Self::new(slice.to_vec())
    }
}

/// Copies a string to the heap and wraps it.
impl From<&str> for Dynamic<String> {
    #[inline(always)]
    fn from(input: &str) -> Self {
        Self::new(input.to_string())
    }
}

/// Boxes the value and wraps it.
impl<T: 'static + zeroize::Zeroize> From<T> for Dynamic<T> {
    #[inline(always)]
    fn from(value: T) -> Self {
        Self {
            inner: Box::new(value),
        }
    }
}

// Hex encoding and decoding for Dynamic<Vec<u8>>.
// Dynamic is always heap-allocated, so no no-alloc split is needed.
#[cfg(feature = "encoding-hex")]
impl Dynamic<Vec<u8>> {
    /// Decodes a hex string (lowercase, uppercase, or mixed) into `Dynamic<Vec<u8>>`.
    ///
    /// The decoded buffer is kept inside a `Zeroizing` wrapper until after the
    /// `Box` allocation completes, guaranteeing zeroization even on OOM panic.
    pub fn try_from_hex(s: &str) -> Result<Self, crate::error::HexError> {
        Ok(Self::from_protected_bytes(zeroize::Zeroizing::new(
            s.try_from_hex()?,
        )))
    }
}

// Base32 encoding and decoding for Dynamic<Vec<u8>>.
#[cfg(feature = "encoding-base32")]
impl Dynamic<Vec<u8>> {
    /// Decodes an uppercase, unpadded Base32 (RFC 4648 §6) string into `Dynamic<Vec<u8>>`.
    ///
    /// The decoded buffer is kept inside a `Zeroizing` wrapper until after the
    /// `Box` allocation completes, guaranteeing zeroization even on OOM panic.
    ///
    /// Decoding is strict about the alphabet, case, padding and length, but lenient
    /// about non-canonical trailing bits: unused bits in the final group are ignored
    /// rather than rejected, so `"MZ"` and `"MY"` both decode to `[0x66]`. Decoding is
    /// therefore not injective — two distinct strings can yield the same bytes, and
    /// only encoder-produced strings are canonical. Do not use the decoded value to
    /// decide that two encoded strings were equal.
    pub fn try_from_base32(s: &str) -> Result<Self, crate::error::Base32Error> {
        Ok(Self::from_protected_bytes(zeroize::Zeroizing::new(
            s.try_from_base32()?,
        )))
    }
}

// Base64url encoding and decoding for Dynamic<Vec<u8>>.
#[cfg(feature = "encoding-base64")]
impl Dynamic<Vec<u8>> {
    /// Decodes a Base64url (unpadded) string into `Dynamic<Vec<u8>>`.
    ///
    /// The decoded buffer is kept inside a `Zeroizing` wrapper until after the
    /// `Box` allocation completes, guaranteeing zeroization even on OOM panic.
    pub fn try_from_base64url(s: &str) -> Result<Self, crate::error::Base64Error> {
        Ok(Self::from_protected_bytes(zeroize::Zeroizing::new(
            s.try_from_base64url()?,
        )))
    }
}

// Bech32 (BIP-173) encoding and decoding for Dynamic<Vec<u8>>.
#[cfg(feature = "encoding-bech32")]
impl Dynamic<Vec<u8>> {
    /// Decodes a Bech32 (BIP-173) string into `Dynamic<Vec<u8>>`, validating the HRP
    /// (case-insensitive).
    ///
    /// The decoded buffer is kept inside a `Zeroizing` wrapper until after the
    /// `Box` allocation completes, guaranteeing zeroization even on OOM panic.
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
    /// [`Bech32Sized`](crate::Bech32Sized) for what `C` above
    /// [`BECH32_CODE_LENGTH`](crate::BECH32_CODE_LENGTH) costs.
    pub fn try_from_bech32_sized<const C: usize>(
        s: &str,
        expected_hrp: &str,
    ) -> Result<Self, crate::error::Bech32Error> {
        Ok(Self::from_protected_bytes(zeroize::Zeroizing::new(
            s.try_from_bech32_sized::<C>(expected_hrp)?,
        )))
    }

    /// Decodes a Bech32 (BIP-173) string into `Dynamic<Vec<u8>>` without validating the HRP.
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
        let (_hrp, bytes) = s.try_from_bech32_unchecked_sized::<C>()?;
        Ok(Self::from_protected_bytes(zeroize::Zeroizing::new(bytes)))
    }
}

// Bech32m (BIP-350) encoding and decoding for Dynamic<Vec<u8>>.
#[cfg(feature = "encoding-bech32")]
impl Dynamic<Vec<u8>> {
    /// Decodes a Bech32m (BIP-350) string into `Dynamic<Vec<u8>>`, validating the HRP
    /// (case-insensitive).
    ///
    /// The decoded buffer is kept inside a `Zeroizing` wrapper until after the
    /// `Box` allocation completes, guaranteeing zeroization even on OOM panic.
    pub fn try_from_bech32m(
        s: &str,
        expected_hrp: &str,
    ) -> Result<Self, crate::error::Bech32Error> {
        Self::try_from_bech32m_sized::<{ crate::BECH32_CODE_LENGTH }>(s, expected_hrp)
    }

    /// Like [`try_from_bech32m`](Self::try_from_bech32m), accepting strings up to `C`
    /// characters. See [`Bech32mSized`](crate::Bech32mSized) for what `C` above
    /// [`BECH32_CODE_LENGTH`](crate::BECH32_CODE_LENGTH) costs.
    pub fn try_from_bech32m_sized<const C: usize>(
        s: &str,
        expected_hrp: &str,
    ) -> Result<Self, crate::error::Bech32Error> {
        Ok(Self::from_protected_bytes(zeroize::Zeroizing::new(
            s.try_from_bech32m_sized::<C>(expected_hrp)?,
        )))
    }

    /// Decodes a Bech32m (BIP-350) string into `Dynamic<Vec<u8>>` without validating the HRP.
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
        let (_hrp, bytes) = s.try_from_bech32m_unchecked_sized::<C>()?;
        Ok(Self::from_protected_bytes(zeroize::Zeroizing::new(bytes)))
    }
}

/// Construction helpers and random generation for `Dynamic<Vec<u8>>`.
impl Dynamic<Vec<u8>> {
    /// Transfers `protected` bytes into a freshly boxed `Vec`, keeping
    /// [`zeroize::Zeroizing`] alive across the only allocation that can panic.
    ///
    /// # Panic safety
    ///
    /// `Box::new(Vec::new())` is the sole allocation point — just the 24-byte
    /// `Vec` header, no data buffer. If it panics (OOM), `protected` is still
    /// in scope and `Zeroizing::drop` zeroes the secret bytes during unwind.
    /// After the swap, `protected` holds an empty `Vec` (no-op to zeroize) and
    /// `Dynamic::from(boxed)` is an infallible struct-field assignment.
    ///
    /// Note: `Box::new(*protected)` would be cleaner but does not compile —
    /// `Zeroizing` implements `Deref` (returning `&T`), not a move-out, so
    /// `*protected` yields a reference rather than an owned value (E0507).
    #[inline(always)]
    fn from_protected_bytes(mut protected: zeroize::Zeroizing<alloc::vec::Vec<u8>>) -> Self {
        // Only fallible allocation; protected stays live across it for panic-safety
        let mut boxed = Box::<alloc::vec::Vec<u8>>::default();
        core::mem::swap(&mut *boxed, &mut *protected);
        Self::from(boxed)
    }

    /// Closure-based constructor that protects against closure panics.
    ///
    /// The intermediate `Vec<u8>` is held inside a `Zeroizing` wrapper for the
    /// entire duration of the closure, so any bytes the closure writes are
    /// zeroed during stack unwinding if `f` panics. Constructed via the same
    /// `Zeroizing` + swap pattern used by `from_protected_bytes`.
    #[inline(always)]
    pub fn new_with<F>(f: F) -> Self
    where
        F: FnOnce(&mut alloc::vec::Vec<u8>),
    {
        let mut v: zeroize::Zeroizing<alloc::vec::Vec<u8>> =
            zeroize::Zeroizing::new(alloc::vec::Vec::new());
        f(&mut v);
        Self::from_protected_bytes(v)
    }
}

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

    /// Closure-based constructor that protects against closure panics.
    ///
    /// The intermediate `String` is held inside a `Zeroizing` wrapper for the
    /// entire duration of the closure, so any bytes the closure writes are
    /// zeroed during stack unwinding if `f` panics. Constructed via the same
    /// `Zeroizing` + swap pattern used by `from_protected_bytes`.
    #[inline(always)]
    pub fn new_with<F>(f: F) -> Self
    where
        F: FnOnce(&mut alloc::string::String),
    {
        let mut s: zeroize::Zeroizing<alloc::string::String> =
            zeroize::Zeroizing::new(alloc::string::String::new());
        f(&mut s);
        Self::from_protected_bytes(s)
    }
}

/// Hex encoding for `Dynamic<Vec<u8>>`; delegates via `with_secret`.
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
impl ToHex for Dynamic<Vec<u8>> {
    #[inline]
    fn to_hex(&self) -> crate::EncodedSecret {
        self.with_secret(|s| s.to_hex())
    }

    #[inline]
    fn to_hex_upper(&self) -> crate::EncodedSecret {
        self.with_secret(|s| s.to_hex_upper())
    }
}

/// Base32 encoding for `Dynamic<Vec<u8>>`; delegates via `with_secret`.
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
impl ToBase32 for Dynamic<Vec<u8>> {
    #[inline]
    fn to_base32(&self) -> crate::EncodedSecret {
        self.with_secret(|s| s.to_base32())
    }
}

/// Base64url encoding for `Dynamic<Vec<u8>>`; delegates via `with_secret`.
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
impl ToBase64Url for Dynamic<Vec<u8>> {
    #[inline]
    fn to_base64url(&self) -> crate::EncodedSecret {
        self.with_secret(|s| s.to_base64url())
    }
}

/// Bech32 encoding for `Dynamic<Vec<u8>>`; delegates via `with_secret`.
///
/// Bring the trait into scope: `use secure_gate::ToBech32;`.
#[cfg(feature = "encoding-bech32")]
impl ToBech32 for Dynamic<Vec<u8>> {
    #[inline]
    fn try_to_bech32(&self, hrp: &str) -> Result<crate::EncodedSecret, crate::error::Bech32Error> {
        self.with_secret(|s| s.try_to_bech32(hrp))
    }

    #[inline]
    fn try_to_bech32_sized<const C: usize>(
        &self,
        hrp: &str,
    ) -> Result<crate::EncodedSecret, crate::error::Bech32Error> {
        self.with_secret(|s| s.try_to_bech32_sized::<C>(hrp))
    }
}

/// Bech32m encoding for `Dynamic<Vec<u8>>`; delegates via `with_secret`.
///
/// Bring the trait into scope: `use secure_gate::ToBech32m;`.
#[cfg(feature = "encoding-bech32")]
impl ToBech32m for Dynamic<Vec<u8>> {
    #[inline]
    fn try_to_bech32m(&self, hrp: &str) -> Result<crate::EncodedSecret, crate::error::Bech32Error> {
        self.with_secret(|s| s.try_to_bech32m(hrp))
    }

    #[inline]
    fn try_to_bech32m_sized<const C: usize>(
        &self,
        hrp: &str,
    ) -> Result<crate::EncodedSecret, crate::error::Bech32Error> {
        self.with_secret(|s| s.try_to_bech32m_sized::<C>(hrp))
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

// Random generation
#[cfg(feature = "rand")]
impl Dynamic<alloc::vec::Vec<u8>> {
    /// Fills a new `Vec<u8>` with `len` cryptographically secure random bytes and wraps it.
    ///
    /// Uses the system RNG ([`OsRng`](rand::rngs::OsRng)) via [`TryRngCore::try_fill_bytes`](rand::TryRngCore::try_fill_bytes).
    /// Requires the `rand` feature (and `alloc`, which `Dynamic<Vec<u8>>` always needs).
    ///
    /// # Panics
    ///
    /// Panics if the system RNG fails to provide bytes ([`TryRngCore::try_fill_bytes`](rand::TryRngCore::try_fill_bytes)
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
        Self::new_with(|v| {
            v.resize(len, 0u8);
            OsRng
                .try_fill_bytes(v)
                .expect("OsRng failure is a program error");
        })
    }

    /// Allocates a `Vec<u8>` of length `len`, fills it from `rng`, and wraps it.
    ///
    /// Accepts any [`TryCryptoRng`](rand::TryCryptoRng) + [`TryRngCore`](rand::TryRngCore) — for example,
    /// a seeded [`StdRng`](rand::rngs::StdRng) for deterministic tests. Requires the `rand`
    /// feature and `alloc` (implicit — [`Dynamic<T>`](crate::Dynamic) itself requires it).
    ///
    /// # Errors
    ///
    /// Returns `R::Error` if [`try_fill_bytes`](rand::TryRngCore::try_fill_bytes) fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(all(feature = "alloc", feature = "rand"))]
    /// # {
    /// use rand::rngs::StdRng;
    /// use rand::SeedableRng;
    /// use secure_gate::Dynamic;
    ///
    /// let mut rng = StdRng::from_seed([9u8; 32]);
    /// let nonce: Dynamic<Vec<u8>> = Dynamic::from_rng(24, &mut rng).expect("rng fill");
    /// # }
    /// ```
    #[inline]
    pub fn from_rng<R: TryRngCore + TryCryptoRng>(
        len: usize,
        rng: &mut R,
    ) -> Result<Self, R::Error> {
        let mut result = Ok(());
        let this = Self::new_with(|v| {
            v.resize(len, 0u8);
            result = rng.try_fill_bytes(v);
        });
        result.map(|_| this)
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
/// This addresses only the buffer this impl owns. A caller who grows the `Vec`
/// themselves through [`with_secret_mut`](crate::RevealSecretMut::with_secret_mut)
/// or [`expose_secret_mut`](crate::RevealSecretMut::expose_secret_mut) holds
/// `&mut Vec<u8>` directly, and their reallocation is outside this crate's
/// control — see the heap-reallocation residue section in `SECURITY.md`.
#[cfg(feature = "std")]
impl std::io::Write for Dynamic<alloc::vec::Vec<u8>> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        use crate::RevealSecretMut;

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

/// Default maximum byte length accepted when deserializing `Dynamic<Vec<u8>>` or
/// `Dynamic<String>` via the standard `serde::Deserialize` impl (1 MiB).
///
/// Pass a custom value to [`Dynamic::deserialize_with_limit`] when a different
/// ceiling is required.
///
/// **Important:** this limit is enforced *after* the upstream deserializer has fully
/// materialized the payload. It is a **result-length acceptance bound**, not a
/// pre-allocation DoS guard. For untrusted input, enforce size limits at the
/// transport or parser layer upstream.
#[cfg(feature = "serde-deserialize")]
pub const MAX_DESERIALIZE_BYTES: usize = 1_048_576;

#[cfg(feature = "serde-deserialize")]
impl Dynamic<alloc::vec::Vec<u8>> {
    /// Deserializes into `Dynamic<Vec<u8>>`, rejecting payloads larger than `limit` bytes.
    ///
    /// The standard [`serde::Deserialize`] impl calls this with [`MAX_DESERIALIZE_BYTES`].
    /// Use this method directly when you need a tighter or looser ceiling.
    ///
    /// **Zeroization scope.** Once the upstream deserializer returns a complete
    /// `Vec<u8>`, the value is wrapped in `Zeroizing` and stays protected for the
    /// rest of this function: oversized buffers are zeroized before the error is
    /// returned, and an OOM panic in the subsequent `Box` allocation triggers
    /// zeroization on unwind. **However, this guarantee does *not* extend backwards
    /// into the deserializer itself.** If the upstream `Vec<u8>` visitor accumulates
    /// bytes element-by-element (e.g., a JSON sequence) and fails partway through,
    /// the partial buffer is owned by the visitor and dropped as a plain `Vec<u8>` —
    /// not zeroized. In the typical untrusted-input threat model the partial bytes
    /// are attacker-controlled (the malformed payload they sent), so the practical
    /// disclosure surface is bounded; but if your threat model includes deserialization
    /// of trusted-but-corruptible secret material, treat the deserialize step as
    /// outside the zeroization boundary and use `from_protected_bytes` (private API)
    /// or `new_with` for in-process construction instead.
    ///
    /// **Important:** this limit is enforced *after* the upstream deserializer has fully
    /// materialized the payload. It is a **result-length acceptance bound**, not a
    /// pre-allocation DoS guard. For untrusted input, enforce size limits at the
    /// transport or parser layer upstream.
    pub fn deserialize_with_limit<'de, D>(deserializer: D, limit: usize) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut buf: zeroize::Zeroizing<alloc::vec::Vec<u8>> =
            zeroize::Zeroizing::new(serde::Deserialize::deserialize(deserializer)?);
        if buf.len() > limit {
            // buf drops here → Zeroizing zeros the oversized buffer before deallocation
            return Err(serde::de::Error::custom(
                "deserialized secret exceeds maximum size",
            ));
        }
        // Only fallible allocation; protected stays live across it for panic-safety
        let mut boxed = Box::<alloc::vec::Vec<u8>>::default();
        core::mem::swap(&mut *boxed, &mut *buf);
        Ok(Self::from(boxed))
    }
}

#[cfg(feature = "serde-deserialize")]
impl Dynamic<String> {
    /// Deserializes into `Dynamic<String>`, rejecting payloads larger than `limit` bytes.
    ///
    /// The standard [`serde::Deserialize`] impl calls this with [`MAX_DESERIALIZE_BYTES`].
    /// Use this method directly when you need a tighter or looser ceiling.
    ///
    /// **Zeroization scope.** Once the upstream deserializer returns a complete
    /// `String`, the value is wrapped in `Zeroizing` and stays protected for the
    /// rest of this function: oversized buffers are zeroized before the error is
    /// returned, and an OOM panic in the subsequent `Box` allocation triggers
    /// zeroization on unwind. **However, this guarantee does *not* extend backwards
    /// into the deserializer itself.** If the upstream `String` visitor accumulates
    /// characters and fails partway through (e.g., on an invalid UTF-8 boundary),
    /// the partial buffer is owned by the visitor and dropped as a plain `String` —
    /// not zeroized. In the typical untrusted-input threat model the partial bytes
    /// are attacker-controlled (the malformed payload they sent), so the practical
    /// disclosure surface is bounded; but if your threat model includes deserialization
    /// of trusted-but-corruptible secret material, treat the deserialize step as
    /// outside the zeroization boundary and use `from_protected_bytes` (private API)
    /// or `new_with` for in-process construction instead.
    ///
    /// **Important:** this limit is enforced *after* the upstream deserializer has fully
    /// materialized the payload. It is a **result-length acceptance bound**, not a
    /// pre-allocation DoS guard. For untrusted input, enforce size limits at the
    /// transport or parser layer upstream.
    pub fn deserialize_with_limit<'de, D>(deserializer: D, limit: usize) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut buf: zeroize::Zeroizing<alloc::string::String> =
            zeroize::Zeroizing::new(serde::Deserialize::deserialize(deserializer)?);
        if buf.len() > limit {
            // buf drops here → Zeroizing zeros the oversized buffer before deallocation
            return Err(serde::de::Error::custom(
                "deserialized secret exceeds maximum size",
            ));
        }
        // Only fallible allocation; protected stays live across it for panic-safety
        let mut boxed = Box::<alloc::string::String>::default();
        core::mem::swap(&mut *boxed, &mut *buf);
        Ok(Self::from(boxed))
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
