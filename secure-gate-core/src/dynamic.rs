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
//! - **Opt-in `Serialize`/`Deserialize`** — requires marker traits and the
//!   `serde-serialize`/`serde-deserialize` features.
//! - **Panic safety** — all decode constructors use the `from_protected_bytes` pattern:
//!   a `Zeroizing` wrapper survives OOM panics from `Box::new`.
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
//! use secure_gate::{Dynamic, RevealSecret, RevealSecretMut};
//!
//! let mut pw: Dynamic<String> = Dynamic::new(String::from("hunter2"));
//!
//! // Tier 1 — scoped (preferred): borrow is confined to the closure.
//! let len = pw.with_secret(|s: &String| s.len());
//! assert_eq!(len, 7);
//!
//! // Tier 1 mutable — scoped mutation.
//! pw.with_secret_mut(|s: &mut String| s.push('!'));
//!
//! // Tier 2 — direct reference (escape hatch).
//! assert_eq!(pw.expose_secret(), "hunter2!");
//!
//! // Tier 3 — owned consumption.
//! let owned = pw.into_inner();
//! assert_eq!(format!("{:?}", owned), "[REDACTED]");
//! # }
//! ```
//!
//! # Warning
//!
//! Ensure your profile sets `panic = "unwind"` — `panic = "abort"` skips destructors
//! and therefore skips zeroization. (`Dynamic` cannot be `static` since it requires
//! `Box` allocation, so the static-secret warning from `Fixed` does not apply.)
//!
//! # See also
//!
//! - [`Fixed<T>`](crate::Fixed) — stack-allocated alternative for fixed-size secrets
//!   (always available, no `alloc` required).

#[cfg(feature = "alloc")]
extern crate alloc;
use alloc::boxed::Box;
use zeroize::Zeroize;

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32",
    feature = "encoding-bech32m",
    feature = "ct-eq",
))]
use crate::RevealSecret;

// Encoding traits
#[cfg(feature = "encoding-base64")]
use crate::traits::encoding::base64_url::ToBase64Url;
#[cfg(feature = "encoding-bech32")]
use crate::traits::encoding::bech32::ToBech32;
#[cfg(feature = "encoding-bech32m")]
use crate::traits::encoding::bech32m::ToBech32m;
#[cfg(feature = "encoding-hex")]
use crate::traits::encoding::hex::ToHex;

#[cfg(feature = "rand")]
use rand::{rngs::OsRng, TryCryptoRng, TryRngCore};

// Dynamic<Vec<u8>> is always alloc-dependent, so the alloc-gated blanket traits
// are always available when encoding features are enabled for this type.
#[cfg(feature = "encoding-base64")]
use crate::traits::decoding::base64_url::FromBase64UrlStr;
#[cfg(feature = "encoding-bech32")]
use crate::traits::decoding::bech32::FromBech32Str;
#[cfg(feature = "encoding-bech32m")]
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
/// use secure_gate::{Dynamic, RevealSecret};
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
/// | [`try_from_base64url(s)`](Self::try_from_base64url) | `encoding-base64` | Constant-time Base64url decoding |
/// | [`try_from_bech32(s, hrp)`](Self::try_from_bech32) | `encoding-bech32` | HRP-validated Bech32 |
/// | [`try_from_bech32_unchecked(s)`](Self::try_from_bech32_unchecked) | `encoding-bech32` | Bech32 without HRP check |
/// | [`try_from_bech32m(s, hrp)`](Self::try_from_bech32m) | `encoding-bech32m` | HRP-validated Bech32m |
/// | [`try_from_bech32m_unchecked(s)`](Self::try_from_bech32m_unchecked) | `encoding-bech32m` | Bech32m without HRP check |
/// | [`from_random(len)`](Self::from_random) | `rand` | System RNG |
/// | [`from_rng(len, rng)`](Self::from_rng) | `rand` | Custom RNG |
///
/// # See also
///
/// - [`RevealSecret`](crate::RevealSecret) / [`RevealSecretMut`](crate::RevealSecretMut) — the 3-tier access traits.
/// - [`Fixed<T>`](crate::Fixed) — stack-allocated alternative.
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
    /// Encodes the secret bytes as a lowercase hex string.
    #[inline]
    pub fn to_hex(&self) -> alloc::string::String {
        self.with_secret(|s: &Vec<u8>| s.to_hex())
    }

    /// Encodes the secret bytes as an uppercase hex string.
    #[inline]
    pub fn to_hex_upper(&self) -> alloc::string::String {
        self.with_secret(|s: &Vec<u8>| s.to_hex_upper())
    }

    /// Encodes the secret bytes as a lowercase hex string, returning
    /// [`EncodedSecret`](crate::EncodedSecret) to preserve zeroization.
    #[inline]
    pub fn to_hex_zeroizing(&self) -> crate::EncodedSecret {
        self.with_secret(|s: &Vec<u8>| s.to_hex_zeroizing())
    }

    /// Encodes the secret bytes as an uppercase hex string, returning
    /// [`EncodedSecret`](crate::EncodedSecret) to preserve zeroization.
    #[inline]
    pub fn to_hex_upper_zeroizing(&self) -> crate::EncodedSecret {
        self.with_secret(|s: &Vec<u8>| s.to_hex_upper_zeroizing())
    }

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

// Base64url encoding and decoding for Dynamic<Vec<u8>>.
#[cfg(feature = "encoding-base64")]
impl Dynamic<Vec<u8>> {
    /// Encodes the secret bytes as an unpadded Base64url string (RFC 4648, URL-safe alphabet).
    #[inline]
    pub fn to_base64url(&self) -> alloc::string::String {
        self.with_secret(|s: &Vec<u8>| s.to_base64url())
    }

    /// Encodes the secret bytes as an unpadded Base64url string, returning
    /// [`EncodedSecret`](crate::EncodedSecret) to preserve zeroization.
    #[inline]
    pub fn to_base64url_zeroizing(&self) -> crate::EncodedSecret {
        self.with_secret(|s: &Vec<u8>| s.to_base64url_zeroizing())
    }

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
    /// Encodes the secret bytes as a Bech32 (BIP-173) string with the given HRP.
    #[inline]
    pub fn try_to_bech32(
        &self,
        hrp: &str,
    ) -> Result<alloc::string::String, crate::error::Bech32Error> {
        self.with_secret(|s: &Vec<u8>| s.try_to_bech32(hrp))
    }

    /// Encodes the secret bytes as a Bech32 string, returning
    /// [`EncodedSecret`](crate::EncodedSecret) to preserve zeroization.
    #[inline]
    pub fn try_to_bech32_zeroizing(
        &self,
        hrp: &str,
    ) -> Result<crate::EncodedSecret, crate::error::Bech32Error> {
        self.with_secret(|s: &Vec<u8>| s.try_to_bech32_zeroizing(hrp))
    }

    /// Decodes a Bech32 (BIP-173) string into `Dynamic<Vec<u8>>`, validating the HRP
    /// (case-insensitive).
    ///
    /// The decoded buffer is kept inside a `Zeroizing` wrapper until after the
    /// `Box` allocation completes, guaranteeing zeroization even on OOM panic.
    ///
    /// HRP comparison is non-constant-time — this is intentional, as the HRP is public
    /// metadata, not secret material.
    pub fn try_from_bech32(s: &str, expected_hrp: &str) -> Result<Self, crate::error::Bech32Error> {
        Ok(Self::from_protected_bytes(zeroize::Zeroizing::new(
            s.try_from_bech32(expected_hrp)?,
        )))
    }

    /// Decodes a Bech32 (BIP-173) string into `Dynamic<Vec<u8>>` without validating the HRP.
    ///
    /// Use [`try_from_bech32`](Self::try_from_bech32) in security-critical code to prevent
    /// cross-protocol confusion attacks.
    pub fn try_from_bech32_unchecked(s: &str) -> Result<Self, crate::error::Bech32Error> {
        let (_hrp, bytes) = s.try_from_bech32_unchecked()?;
        Ok(Self::from_protected_bytes(zeroize::Zeroizing::new(bytes)))
    }
}

// Bech32m (BIP-350) encoding and decoding for Dynamic<Vec<u8>>.
#[cfg(feature = "encoding-bech32m")]
impl Dynamic<Vec<u8>> {
    /// Encodes the secret bytes as a Bech32m (BIP-350) string with the given HRP.
    #[inline]
    pub fn try_to_bech32m(
        &self,
        hrp: &str,
    ) -> Result<alloc::string::String, crate::error::Bech32Error> {
        self.with_secret(|s: &Vec<u8>| s.try_to_bech32m(hrp))
    }

    /// Encodes the secret bytes as a Bech32m string, returning
    /// [`EncodedSecret`](crate::EncodedSecret) to preserve zeroization.
    #[inline]
    pub fn try_to_bech32m_zeroizing(
        &self,
        hrp: &str,
    ) -> Result<crate::EncodedSecret, crate::error::Bech32Error> {
        self.with_secret(|s: &Vec<u8>| s.try_to_bech32m_zeroizing(hrp))
    }

    /// Decodes a Bech32m (BIP-350) string into `Dynamic<Vec<u8>>`, validating the HRP
    /// (case-insensitive).
    ///
    /// The decoded buffer is kept inside a `Zeroizing` wrapper until after the
    /// `Box` allocation completes, guaranteeing zeroization even on OOM panic.
    pub fn try_from_bech32m(
        s: &str,
        expected_hrp: &str,
    ) -> Result<Self, crate::error::Bech32Error> {
        Ok(Self::from_protected_bytes(zeroize::Zeroizing::new(
            s.try_from_bech32m(expected_hrp)?,
        )))
    }

    /// Decodes a Bech32m (BIP-350) string into `Dynamic<Vec<u8>>` without validating the HRP.
    ///
    /// Use [`try_from_bech32m`](Self::try_from_bech32m) in security-critical code.
    pub fn try_from_bech32m_unchecked(s: &str) -> Result<Self, crate::error::Bech32Error> {
        let (_hrp, bytes) = s.try_from_bech32m_unchecked()?;
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
    #[cfg(any(
        feature = "encoding-hex",
        feature = "encoding-base64",
        feature = "encoding-bech32",
        feature = "encoding-bech32m",
    ))]
    #[inline(always)]
    fn from_protected_bytes(mut protected: zeroize::Zeroizing<alloc::vec::Vec<u8>>) -> Self {
        // Only fallible allocation; protected stays live across it for panic-safety
        let mut boxed = Box::<alloc::vec::Vec<u8>>::default();
        core::mem::swap(&mut *boxed, &mut *protected);
        Self::from(boxed)
    }

    /// Closure-based constructor for consistent API with [`Fixed::new_with`](crate::Fixed::new_with).
    /// The actual secret data is allocated on the heap; this method exists
    /// for consistent security-first construction idiom across the crate.
    #[inline(always)]
    pub fn new_with<F>(f: F) -> Self
    where
        F: FnOnce(&mut alloc::vec::Vec<u8>),
    {
        let mut v = alloc::vec::Vec::new();
        f(&mut v);
        Self::new(v)
    }
}

impl Dynamic<alloc::string::String> {
    /// Closure-based constructor for consistent API with [`Fixed::new_with`](crate::Fixed::new_with).
    /// The actual secret data is allocated on the heap; this method exists
    /// for consistent security-first construction idiom across the crate.
    #[inline(always)]
    pub fn new_with<F>(f: F) -> Self
    where
        F: FnOnce(&mut alloc::string::String),
    {
        let mut s = alloc::string::String::new();
        f(&mut s);
        Self::new(s)
    }
}

// RevealSecret
impl crate::RevealSecret for Dynamic<String> {
    type Inner = String;

    #[inline(always)]
    fn with_secret<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&String) -> R,
    {
        f(&self.inner)
    }

    #[inline(always)]
    fn expose_secret(&self) -> &String {
        &self.inner
    }

    #[inline(always)]
    fn len(&self) -> usize {
        self.inner.len()
    }

    /// Consumes `self` and returns the inner `String` wrapped in [`crate::InnerSecret`].
    ///
    /// **Allocation note:** allocates one small `Box<String>` sentinel (24 bytes on
    /// 64-bit) before the swap. If that allocation panics (OOM), `self.inner` is
    /// unchanged and `Dynamic::drop` zeroizes the real secret during unwind —
    /// confidentiality is preserved. This is the same OOM-safety pattern used by
    /// `from_protected_bytes` and `deserialize_with_limit`.
    ///
    /// See [`RevealSecret::into_inner`] for full documentation including the
    /// redacted `Debug` behavior.
    #[inline(always)]
    fn into_inner(mut self) -> crate::InnerSecret<String>
    where
        Self: Sized,
        Self::Inner: Sized + Default + zeroize::Zeroize,
    {
        // Swap in an empty-String sentinel. If Default::default() panics (OOM) before
        // the swap, self.inner still holds the real secret and Dynamic::drop zeroizes
        // it on unwind. After the swap, self.inner is Box<String::new()> — zeroized
        // on Dynamic::drop as a no-op. `*boxed` deref-moves the String out of the Box.
        let boxed = core::mem::take(&mut self.inner);
        crate::InnerSecret::new(*boxed)
    }
}

impl<T: zeroize::Zeroize> crate::RevealSecret for Dynamic<Vec<T>> {
    type Inner = Vec<T>;

    #[inline(always)]
    fn with_secret<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&Vec<T>) -> R,
    {
        f(&self.inner)
    }

    #[inline(always)]
    fn expose_secret(&self) -> &Vec<T> {
        &self.inner
    }

    #[inline(always)]
    fn len(&self) -> usize {
        self.inner.len() * core::mem::size_of::<T>()
    }

    /// Consumes `self` and returns the inner `Vec<T>` wrapped in [`crate::InnerSecret`].
    ///
    /// **Allocation note:** allocates one small `Box<Vec<T>>` sentinel (24 bytes on
    /// 64-bit) before the swap. If that allocation panics (OOM), `self.inner` is
    /// unchanged and `Dynamic::drop` zeroizes the real secret during unwind —
    /// confidentiality is preserved. This is the same OOM-safety pattern used by
    /// `from_protected_bytes` and `deserialize_with_limit`.
    ///
    /// See [`RevealSecret::into_inner`] for full documentation including the
    /// redacted `Debug` behavior.
    #[inline(always)]
    fn into_inner(mut self) -> crate::InnerSecret<Vec<T>>
    where
        Self: Sized,
        Self::Inner: Sized + Default + zeroize::Zeroize,
    {
        // Swap in an empty-Vec sentinel. If Default::default() panics (OOM) before the
        // swap, self.inner still holds the real secret and Dynamic::drop zeroizes it on
        // unwind. After the swap, self.inner is Box<Vec::new()> — zeroized on
        // Dynamic::drop as a no-op. `*boxed` deref-moves the Vec out of the Box.
        let boxed = core::mem::take(&mut self.inner);
        crate::InnerSecret::new(*boxed)
    }
}

// RevealSecretMut
impl crate::RevealSecretMut for Dynamic<String> {
    #[inline(always)]
    fn with_secret_mut<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut String) -> R,
    {
        f(&mut self.inner)
    }

    #[inline(always)]
    fn expose_secret_mut(&mut self) -> &mut String {
        &mut self.inner
    }
}

impl<T: zeroize::Zeroize> crate::RevealSecretMut for Dynamic<Vec<T>> {
    #[inline(always)]
    fn with_secret_mut<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut Vec<T>) -> R,
    {
        f(&mut self.inner)
    }

    #[inline(always)]
    fn expose_secret_mut(&mut self) -> &mut Vec<T> {
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
    /// use secure_gate::{Dynamic, RevealSecret};
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
/// Data flows **into** the wrapper — this is a pure security improvement over
/// accumulating plaintext in a bare `Vec<u8>` before wrapping.
///
/// # Example
///
/// ```rust
/// # #[cfg(feature = "std")] {
/// use std::io::Write;
/// use secure_gate::Dynamic;
///
/// let mut secret = Dynamic::<Vec<u8>>::new(vec![]);
/// secret.write_all(b"decrypted payload").unwrap();
///
/// // Secret material was protected from the first byte —
/// // no intermediate unprotected buffer ever existed.
/// # }
/// ```
#[cfg(feature = "std")]
impl std::io::Write for Dynamic<alloc::vec::Vec<u8>> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        use crate::RevealSecretMut;
        self.with_secret_mut(|v| std::io::Write::write(v, buf))
    }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Cursor-like reader over a [`Dynamic<Vec<u8>>`].
///
/// Created by [`Dynamic::<Vec<u8>>::as_reader`]. Borrows the `Dynamic`
/// immutably and tracks the read position internally. Each [`Read::read`]
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
        use crate::RevealSecret;
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
    /// use std::io::Read;
    /// use secure_gate::Dynamic;
    ///
    /// let secret = Dynamic::<Vec<u8>>::new(vec![1, 2, 3, 4]);
    ///
    /// // Before: awkward closure + Cursor dance
    /// // secret.with_secret(|b| io::copy(&mut Cursor::new(b), &mut writer))?;
    ///
    /// // After: clean streaming
    /// let mut out = Vec::new();
    /// secret.as_reader().read_to_end(&mut out).unwrap();
    /// assert_eq!(out, [1, 2, 3, 4]);
    /// # }
    /// ```
    ///
    /// # Security
    ///
    /// Each `read()` call copies secret bytes into the caller's buffer.
    /// The caller must zeroize that buffer when done.
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
    /// The intermediate buffer is kept inside a `Zeroizing` wrapper until after the `Box`
    /// allocation completes, guaranteeing zeroization even on OOM panic. Oversized buffers
    /// are also zeroized before the error is returned.
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
    /// The intermediate buffer is kept inside a `Zeroizing` wrapper until after the `Box`
    /// allocation completes, guaranteeing zeroization even on OOM panic. Oversized buffers
    /// are also zeroized before the error is returned.
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
