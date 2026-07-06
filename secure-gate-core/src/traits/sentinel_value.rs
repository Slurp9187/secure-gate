//! Sentinel placeholders for owned secret extraction.
//!
//! > **Import path:** `use secure_gate::SentinelValue;`
//!
//! [`RevealSecret::into_inner`](crate::RevealSecret::into_inner) moves the real
//! secret out of a wrapper while the wrapper's `Drop` impl still runs afterwards.
//! Something inert must be left behind for that `Drop` to zeroize —
//! [`SentinelValue::sentinel_value`] produces it.
//!
//! `Default` is *not* used for this purpose because the standard library only
//! implements `Default` for arrays up to 32 elements, which would make
//! `into_inner` unusable for common secret sizes such as `[u8; 64]`
//! (Ed25519 expanded keys, HMAC-SHA512 keys). The `[T; N]` implementation here
//! uses [`core::array::from_fn`], which works for every `N`.

/// Produces the inert placeholder left inside a wrapper after
/// [`into_inner`](crate::RevealSecret::into_inner) moves the real secret out.
///
/// # Contract
///
/// A sentinel must be cheap to construct and must never contain secret
/// material — it exists only so the wrapper's `Drop` impl zeroizes a harmless
/// value instead of the already-moved secret. The provided implementations
/// return an all-default array, an empty `String`, or an empty `Vec`.
///
/// # Provided implementations
///
/// | Type | Sentinel | Notes |
/// |------|----------|-------|
/// | `[T; N]` where `T: Default` | `[T::default(); N]` | Any `N` — not limited to 32 like `Default` |
/// | `String` | `String::new()` | Requires `alloc`; no allocation |
/// | `Vec<T>` | `Vec::new()` | Requires `alloc`; no allocation |
///
/// Implement this for your own inner types to make `into_inner` available on
/// wrappers around them. For inner types where every representable value is
/// meaningful secret material (i.e. no safe placeholder exists), do not
/// implement this trait — `into_inner` then stays uncallable for them, which
/// is the safe default.
pub trait SentinelValue: Sized {
    /// Returns the inert placeholder value. Must not contain secret material.
    fn sentinel_value() -> Self;
}

impl<T: Default, const N: usize> SentinelValue for [T; N] {
    #[inline(always)]
    fn sentinel_value() -> Self {
        core::array::from_fn(|_| T::default())
    }
}

#[cfg(feature = "alloc")]
impl SentinelValue for alloc::string::String {
    #[inline(always)]
    fn sentinel_value() -> Self {
        alloc::string::String::new()
    }
}

#[cfg(feature = "alloc")]
impl<T> SentinelValue for alloc::vec::Vec<T> {
    #[inline(always)]
    fn sentinel_value() -> Self {
        alloc::vec::Vec::new()
    }
}
