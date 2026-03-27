//! Traits for controlled, polymorphic secret revelation.
//!
//! This module defines the core traits that enforce explicit, auditable access to
//! secret data across all wrapper types (`Fixed<T>`, `Dynamic<T>`, aliases, etc.).
//!
//! The design ensures:
//! - No implicit borrowing (`Deref`, `AsRef`, etc.)
//! - Scoped access is preferred (minimizes lifetime of exposed references)
//! - Direct exposure is possible but clearly marked as an escape hatch
//! - Owned consumption is available for FFI hand-off and type migration
//! - Metadata (`len`, `is_empty`) is always available without full exposure
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
//! audit it separately. See SECURITY.md for the full list of auditable access surfaces.
//!
//! # Key Traits
//!
//! | Trait                  | Access     | Preferred Method          | Escape Hatch             | Metadata          | Feature     |
//! |------------------------|------------|---------------------------|--------------------------|-------------------|-------------|
//! | [`RevealSecret`]                | Read-only  | `with_secret` (scoped)    | `expose_secret`     | `len`, `is_empty` | Always |
//! | [`crate::RevealSecretMut`]      | Mutable    | `with_secret_mut` (scoped)| `expose_secret_mut` | Inherits above    | Always |
//!
//! # Security Model
//!
//! - **Core wrappers** (`Fixed<T>`, `Dynamic<T>`) implement both traits → full access.
//! - **Read-only wrappers** (encoding wrappers, random types) implement only `RevealSecret` → mutation prevented.
//! - **Zero-cost** — all methods are `#[inline(always)]` where possible.
//! - **Scoped access preferred** — `with_secret` / `with_secret_mut` limit borrow lifetime, reducing leak risk.
//! - **Direct exposure** (`expose_secret` / `expose_secret_mut`) is provided for legitimate needs (FFI, third-party APIs), but marked as an escape hatch.
//! - **Owned consumption** (`into_inner`) is available when the secret must be moved out of the wrapper.
//!   Zeroization transfers to the returned `Zeroizing<T>` — the caller must let it drop normally.
//!
//! # `Debug` Warning for `into_inner`
//!
//! `with_secret`/`expose_secret` retain the `[REDACTED]` `Debug` invariant because the
//! wrapper is still live. After `into_inner`, the caller holds a `Zeroizing<T>`, which
//! delegates `Debug` directly to `T` with **no redaction**. Printing `{:?}` on the
//! return value will expose raw secret bytes for common inner types (`[u8; N]`, `Vec<u8>`,
//! `String`). **Do not log, print, or format the result of `into_inner()` directly.**
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
//! // Consumes `key`; zeroization transfers to the returned Zeroizing<[u8; 16]>.
//! let owned: zeroize::Zeroizing<[u8; 16]> = key.into_inner();
//! assert_eq!(*owned, [0xABu8; 16]);
//! // ⚠ Do NOT: println!("{:?}", owned);  — Zeroizing<T> does not redact on Debug.
//! // `owned` zeroizes its bytes when it drops.
//! ```
//!
//! Polymorphic generic code:
//!
//! ```rust
//! use secure_gate::RevealSecret;
//!
//! fn print_length<S: RevealSecret>(secret: &S) {
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
/// Implemented by [`Fixed<T>`](crate::Fixed) and [`Dynamic<T>`](crate::Dynamic).
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

    /// Returns the length of the secret in bytes.
    ///
    /// Always safe to call — does not expose secret contents.
    fn len(&self) -> usize;

    /// Returns `true` if the secret is empty.
    ///
    /// Always safe to call — does not expose secret contents.
    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Consumes the wrapper and returns the inner value wrapped in [`zeroize::Zeroizing`],
    /// preserving automatic zeroization on drop.
    ///
    /// This is the safe, idiomatic path when ownership of the secret is required — for
    /// example, to hand the value to an API that takes `T` by value, to move between
    /// wrapper types, or at FFI boundaries where the callee takes ownership.
    ///
    /// The zeroization contract transfers to the caller: when the returned
    /// `Zeroizing<Self::Inner>` drops, it calls `Self::Inner::zeroize()` automatically,
    /// exactly as the wrapper's own `Drop` impl would have.
    ///
    /// # Availability
    ///
    /// Only callable when `Self::Inner: Sized + Default + Zeroize`. The `Default` bound
    /// is required to construct a zero-sentinel that the wrapper's `Drop` impl runs on
    /// after the real secret is moved out. The `Zeroize` bound is required so the
    /// returned `Zeroizing<T>` can call `zeroize()` on drop. For types that intentionally
    /// omit `Default` (e.g. custom key types where an all-zero value is invalid or
    /// dangerous), `into_inner` is not callable — use `with_secret` or `expose_secret`
    /// instead.
    ///
    /// The three concrete implementations in this crate all satisfy the bounds:
    /// - `Fixed<[u8; N]>` — `[u8; N]: Default + Zeroize` ✓
    /// - `Dynamic<String>` — `String: Default + Zeroize` ✓
    /// - `Dynamic<Vec<T>>` — `Vec<T>: Default + Zeroize` ✓
    ///
    /// # Debug Warning
    ///
    /// The returned `Zeroizing<T>` does **not** redact on `Debug` if `T: Debug`.
    /// Printing it (e.g. `{:?}`) **will reveal the secret bytes** for common inner types
    /// like `[u8; N]`, `Vec<u8>`, or `String`.
    ///
    /// **Do not log, print, or format the result of `into_inner()` directly.**
    /// Use it only to transfer ownership to code that consumes the value without exposing it.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{Fixed, RevealSecret};
    ///
    /// let key = Fixed::new([0xABu8; 16]);
    /// let owned: zeroize::Zeroizing<[u8; 16]> = key.into_inner();
    /// // `owned` zeroizes its 16 bytes when it drops — same guarantee as Fixed<[u8; 16]>.
    /// assert_eq!(*owned, [0xABu8; 16]);
    /// // ⚠ Do NOT log or format `owned` — Zeroizing<[u8; 16]> prints raw bytes on Debug.
    /// ```
    ///
    /// ```rust
    /// # #[cfg(feature = "alloc")]
    /// # {
    /// use secure_gate::{Dynamic, RevealSecret};
    ///
    /// let pw = Dynamic::<String>::new("hunter2".to_string());
    /// let owned: zeroize::Zeroizing<String> = pw.into_inner();
    /// assert_eq!(*owned, "hunter2");
    /// // `owned` zeroizes its heap buffer when it drops.
    /// # }
    /// ```
    fn into_inner(self) -> zeroize::Zeroizing<Self::Inner>
    where
        Self: Sized,
        Self::Inner: Sized + Default + zeroize::Zeroize;
}
