//! Traits for controlled, polymorphic secret revelation.
//!
//! > **Import path:** `use secure_gate::RevealSecret;`
//!
//! This module defines the core `RevealSecret` trait. See
//! [`revealed_secrets`](crate::traits::revealed_secrets) for
//! [`EncodedSecret`](crate::EncodedSecret), the wrapper for encoded output.
//!
//! The design ensures:
//! - No implicit borrowing (`Deref`, `AsRef`, etc.) from the secret wrapper itself —
//!   reaching the secret always names a method
//! - Scoped access is preferred (minimizes lifetime of exposed references)
//! - Direct exposure is possible but clearly marked as an escape hatch
//! - Owned consumption is available for FFI hand-off and type migration
//! - Length metadata (`len`, `is_empty` via [`SecretLen`]) is available without
//!   exposing contents — though length itself can be sensitive; see [`SecretLen`]
//!
//! # Three-Tier Access Model
//!
//! All secret access follows an explicit hierarchy. Prefer tiers earlier in the list:
//!
//! | Tier | Method | When to use |
//! |------|--------|-------------|
//! | 1 — Scoped borrow (preferred) | `with_secret` / `with_secret_mut` | Almost all application code |
//! | 2 — Direct reference (escape hatch) | `expose_secret` / `expose_secret_mut` | FFI, third-party APIs requiring `&T` |
//! | 3 — Owned consumption | `into_inner` | FFI hand-off, type migration, APIs requiring `T` by value |
//!
//! **Audit note:** `into_inner` does not appear in an `expose_secret*` grep sweep —
//! audit it separately. See the [`revealed_secrets`](crate::traits::revealed_secrets) module
//! and SECURITY.md for the full list of auditable access surfaces.
//!
//! # Key Traits
//!
//! | Trait                  | Access     | Preferred Method          | Escape Hatch             | Metadata          | Feature     |
//! |------------------------|------------|---------------------------|--------------------------|-------------------|-------------|
//! | [`RevealSecret`]                | Read-only  | `with_secret` (scoped)    | `expose_secret`     | — (see [`SecretLen`]) | Always |
//! | [`crate::RevealSecretMut`]      | Mutable    | `with_secret_mut` (scoped)| `expose_secret_mut` | Inherits above    | Always |
//!
//! # Security Model
//!
//! - **Core wrappers** (`Fixed<T>`, `Dynamic<T>`) implement both traits → full access.
//! - **Generated newtypes** (`fixed_newtype!` / `dynamic_newtype!`) implement both, forwarding to the wrapper they hold.
//! - **`EncodedSecret` implements neither.** It is an output wrapper, not a secret wrapper: its contents are reached through `Deref<Target = str>` and its two named consumers.
//! - **Zero-cost** — all methods are `#[inline(always)]` where possible.
//! - **Scoped access preferred** — `with_secret` / `with_secret_mut` limit borrow lifetime, reducing leak risk.
//! - **Direct exposure** (`expose_secret` / `expose_secret_mut`) is provided for legitimate needs (FFI, third-party APIs), but marked as an escape hatch.
//! - **Owned consumption** (`into_inner`) is available when the secret must be moved out of the
//!   wrapper. It transfers ownership of the plain value and nothing is copied; the wrapper's
//!   zeroize-on-drop does not follow it, so the caller owns the value's lifetime from there.
//!
//! # Note for `RevealSecret` Implementors
//!
//! Adding `into_inner` to this trait means every `RevealSecret` implementor must provide
//! an owned-extraction implementation. For wrappers intentionally limited to borrowing
//! semantics, implement `into_inner` with `unimplemented!()` or a compile-time guard, and
//! document the design rationale clearly.
//!
//! # Usage Guidelines
//!
//! The preferred and recommended way to access secrets is the scoped `with_secret` /
//! `with_secret_mut` methods. `expose_secret` / `expose_secret_mut` are escape hatches
//! for rare cases and should be audited closely. `into_inner` is reserved for the uncommon
//! case where ownership of the inner value is required.
//!
//! - **Always prefer scoped methods** (`with_secret`, `with_secret_mut`) in application code.
//! - Use direct exposure only when necessary (e.g., passing raw pointer + length to C FFI).
//! - Audit every `expose_secret*` call — they should be rare and well-justified.
//! - Audit every `into_inner` call — it transfers ownership out of the wrapper's protection.
//!
//! # Examples
//!
//! Scoped (recommended):
//!
//! ```rust
//! use secure_gate::{Fixed, RevealSecret};
//!
//! let secret = Fixed::new([42u8; 4]);
//! let sum: u32 = secret.with_secret(|bytes| bytes.iter().map(|&b| b as u32).sum());
//! assert_eq!(sum, 42 * 4);
//! ```
//!
//! Direct (escape hatch – use with caution):
//!
//! ```rust
//! use secure_gate::{Fixed, RevealSecret};
//!
//! let secret = Fixed::new([42u8; 4]);
//!
//! // Example: FFI call needing raw pointer + length
//! // unsafe {
//! //     c_function(secret.expose_secret().as_ptr(), secret.len());
//! // }
//! ```
//!
//! Mutable scoped:
//!
//! ```rust
//! use secure_gate::{Fixed, RevealSecret, RevealSecretMut};
//!
//! let mut secret = Fixed::new([0u8; 4]);
//! secret.with_secret_mut(|bytes| bytes[0] = 99);
//! assert_eq!(secret.expose_secret()[0], 99);
//! ```
//!
//! Owned consumption (into_inner):
//!
//! ```rust
//! use secure_gate::{Fixed, RevealSecret};
//!
//! let key = Fixed::new([0xABu8; 16]);
//! // Consumes `key` and transfers ownership of the bytes. Nothing is copied:
//! // an inert sentinel is left for `Fixed::drop` to zeroize in their place.
//! let owned: [u8; 16] = key.into_inner();
//! assert_eq!(owned, [0xABu8; 16]);
//! // `owned` is an ordinary array now — you own its lifetime.
//! ```
//!
//! Polymorphic generic code:
//!
//! ```rust
//! use secure_gate::SecretLen;
//!
//! fn print_length<S: SecretLen>(secret: &S) {
//!     println!("Length: {} bytes", secret.len());
//! }
//! ```
//!
//! These traits are the foundation of secure-gate's security model: all secret access is
//! explicit, auditable, and controlled. Prefer scoped methods in nearly all cases.
//!
//! # Implementation Notes
//!
//! Long-lived `expose_secret()` references can defeat scoping — the borrow outlives the
//! call site and the compiler cannot enforce that the secret is not retained. This is an
//! intentional escape hatch for FFI and legacy APIs; audit every call site.

/// Read-only access to a wrapped secret.
///
/// Implemented for **all** [`Fixed<T>`](crate::Fixed) and [`Dynamic<T>`](crate::Dynamic),
/// whatever the inner type — length metadata lives in the narrower [`SecretLen`].
/// Prefer the scoped [`with_secret`](Self::with_secret) method; use
/// [`expose_secret`](Self::expose_secret) only when a long-lived reference is
/// unavoidable. See [`RevealSecretMut`](crate::RevealSecretMut) for the mutable
/// counterpart.
pub trait RevealSecret {
    /// The inner secret type being revealed.
    ///
    /// This can be a sized type (e.g. `[u8; N]`, `u32`) or unsized (e.g. `str`, `[u8]`).
    type Inner: ?Sized;

    /// Provides scoped (recommended) read-only access to the secret.
    ///
    /// The closure receives a reference that cannot escape — the borrow ends when
    /// the closure returns, minimizing the lifetime of the exposed secret.
    /// Prefer this over [`expose_secret`](Self::expose_secret) in all application code.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{Fixed, RevealSecret};
    ///
    /// let secret = Fixed::new([42u8; 4]);
    /// let sum: u32 = secret.with_secret(|bytes| bytes.iter().map(|&b| b as u32).sum());
    /// assert_eq!(sum, 42 * 4);
    /// ```
    fn with_secret<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&Self::Inner) -> R;

    /// Returns a direct (auditable) read-only reference to the secret.
    ///
    /// Long-lived `expose_secret()` references can defeat scoping — prefer
    /// [`with_secret`](Self::with_secret) in application code. Use this only when
    /// a long-lived reference is unavoidable (e.g. FFI, third-party APIs).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{Fixed, RevealSecret};
    ///
    /// let secret = Fixed::new([42u8; 4]);
    ///
    /// // Auditable escape hatch — FFI use case:
    /// // unsafe { c_fn(secret.expose_secret().as_ptr(), secret.len()); }
    /// let _ = secret.expose_secret();
    /// ```
    fn expose_secret(&self) -> &Self::Inner;

    /// Consumes the wrapper and transfers ownership of the plain inner value.
    ///
    /// This is the safe, idiomatic path when ownership of the secret is required — for
    /// example, to hand the value to an API that takes `T` by value, to move between
    /// wrapper types, or at FFI boundaries where the callee takes ownership.
    ///
    /// **Protection ends here.** The returned value is an ordinary `[u8; N]` / `String` /
    /// `Vec<T>` with no zeroize-on-drop and no redacted `Debug` — you own the secret and
    /// its lifetime from this call onward. Nothing is copied: the value is moved out and
    /// an inert [`SentinelValue`](crate::SentinelValue) is left for the wrapper's `Drop`
    /// to zeroize in its place. If you want the protection to continue, do not call this
    /// — keep the wrapper, or move the value into a new one.
    ///
    /// # Availability
    ///
    /// Only callable when `Self::Inner: Sized + SentinelValue + Zeroize`. The
    /// [`SentinelValue`](crate::SentinelValue) bound is required to construct the inert
    /// placeholder that the wrapper's `Drop` impl runs on after the real secret is moved
    /// out. (A plain `Default` bound is deliberately **not** used: the standard library
    /// only implements `Default` for arrays up to 32 elements, which would make
    /// `into_inner` unusable for `[u8; 64]` and other common key sizes.) The `Zeroize`
    /// bound is required because the wrapper still zeroizes the sentinel on drop.
    /// For custom inner types that intentionally omit `SentinelValue` (e.g. key types
    /// where no safe placeholder value exists), `into_inner` is not callable — use
    /// `with_secret` or `expose_secret` instead.
    ///
    /// The three concrete implementations in this crate all satisfy the bounds:
    /// - `Fixed<[u8; N]>` — `[u8; N]: SentinelValue + Zeroize` for **any** `N` ✓
    /// - `Dynamic<String>` — `String: SentinelValue + Zeroize` ✓
    /// - `Dynamic<Vec<T>>` — `Vec<T>: SentinelValue + Zeroize` ✓
    ///
    /// # Allocation Behavior
    ///
    /// `Fixed::into_inner` is zero-cost (no allocation). The `Dynamic::into_inner`
    /// impls allocate one small `Box<T>` sentinel (24 bytes on 64-bit) before swapping
    /// out the real secret; if that allocation panics (OOM), the original `inner` is
    /// untouched and `Dynamic::drop` zeroizes the secret during unwind. Confidentiality
    /// is preserved on the panic path. See the per-impl docs on
    /// [`Dynamic`](crate::Dynamic) for the exact pattern.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{Fixed, RevealSecret};
    ///
    /// let key = Fixed::new([0xABu8; 16]);
    /// let owned: [u8; 16] = key.into_inner();
    /// assert_eq!(owned, [0xABu8; 16]);
    /// // `owned` is a plain array — no wiping, no redaction. You own it.
    /// ```
    ///
    /// ```rust
    /// # #[cfg(feature = "alloc")]
    /// # {
    /// use secure_gate::{Dynamic, RevealSecret};
    ///
    /// let pw = Dynamic::<String>::new("hunter2".to_string());
    /// let owned: String = pw.into_inner();
    /// assert_eq!(owned, "hunter2");
    /// // Same allocation, moved out — no copy was made.
    /// # }
    /// ```
    fn into_inner(self) -> Self::Inner
    where
        Self: Sized,
        Self::Inner: Sized + crate::SentinelValue + zeroize::Zeroize;
}

/// Length metadata for secrets whose inner type has a meaningful length.
///
/// Separated from [`RevealSecret`] so the core access trait can be implemented
/// for **every** inner type — including local user-defined ones (see the
/// [`CloneableSecret`](crate::CloneableSecret) newtype pattern), which have no
/// meaningful `len()`. Implemented for `Fixed<[T; N]>`, `Dynamic<String>`, and
/// `Dynamic<Vec<T>>`.
///
/// # Security
///
/// These methods do not expose secret **contents** — but that is not the same
/// as length being harmless, and the distinction matters:
///
/// - For `Fixed<[u8; N]>`, `len()` is `N`: a compile-time constant already
///   visible in the type. Nothing is revealed.
/// - For variable-length secrets (`Dynamic<String>`, `Dynamic<Vec<u8>>`),
///   length **can be sensitive**. A password's length narrows a brute-force
///   search; a token's length can fingerprint its issuer. Treat it as metadata
///   *about* a secret, not as public data: validate against it (minimum-length
///   checks, buffer sizing) but never log it, put it in an error message that
///   leaves the process, or persist it next to an identifier.
///
/// This trait is deliberately separate from [`RevealSecret`] so that measuring
/// a secret is a visible choice. `use secure_gate::SecretLen;` is an audit
/// marker — `grep SecretLen` finds every module that measures secrets — and
/// generic code bounded only on `RevealSecret` cannot call `len()`. The other
/// route, `with_secret(|s| s.len())`, needs no trait but surfaces in the
/// `with_secret` audit sweep instead. Neither is prevented; both are greppable.
/// This is accident-prevention, not a barrier.
///
/// Constant-time comparison is **not** length-hiding: `ConstantTimeEq` on
/// variable-length secrets delegates to `subtle`, whose slice comparison
/// short-circuits when lengths differ, so length *inequality* is observable
/// through timing whether or not `len()` is ever called. Lengths are usually
/// public in the protocols where that matters; for password verification, be
/// aware of it.
///
/// # Examples
///
/// ```rust
/// use secure_gate::{Fixed, SecretLen};
///
/// let key = Fixed::new([0u8; 32]);
/// assert_eq!(key.len(), 32);
/// assert_eq!(key.byte_len(), 32);
/// assert!(!key.is_empty());
/// ```
pub trait SecretLen: RevealSecret {
    /// Returns the number of elements in the secret, matching the underlying
    /// container's `len()` — element count for `Vec<T>` and `[T; N]`, byte
    /// count for `String` (where the element is a byte).
    fn len(&self) -> usize;

    /// Returns the total size of the secret in bytes.
    ///
    /// For single-byte element types (`Vec<u8>`, `String`, `[u8; N]`) this
    /// equals `len()`. Implementations for multi-byte element types override
    /// this to return `len() * core::mem::size_of::<T>()`.
    #[inline(always)]
    fn byte_len(&self) -> usize {
        self.len()
    }

    /// Returns `true` if the secret is empty.
    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
