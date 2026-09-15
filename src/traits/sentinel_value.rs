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
/// | `[T; N]` where `T: Default` | `[T::default(); N]` | Any `N` — not limited to 32 like `Default`. **Contract, not description** — see below |
/// | `String` | `String::new()` | Requires `alloc`; no allocation |
/// | `Vec<T>` | `Vec::new()` | Requires `alloc`; no allocation |
///
/// ## The `[T; N]` row is a contract
///
/// Every other row is free to change its sentinel later without breaking anyone —
/// `String::new()` and `Vec::new()` are the only allocation-free values either type
/// has, so there is nothing to tighten. `[T; N]` is different: `T::default()` is one
/// of many values that satisfy the trait-level contract above ("cheap to construct,
/// never secret"), and this crate's own
/// [`Fixed::new_with`](crate::Fixed::new_with) and
/// [`Fixed::try_new_with`](crate::Fixed::try_new_with) reuse this same
/// implementation to fill the wrapper's storage *before* the caller's closure runs —
/// not only to build the post-`into_inner` placeholder this trait was written for. A
/// closure passed to either constructor that writes fewer than `N` elements leaves
/// the rest of the array at whatever `sentinel_value()` produced, so callers of those
/// constructors read that remainder as the sentinel, not just callers of
/// `into_inner`.
///
/// This implementation therefore promises, as part of its contract rather than as a
/// description of today's code: for `[T; N]` with `T: Default`, `sentinel_value()`
/// is `[T::default(); N]` element-for-element — all-zero for every integer type,
/// `bool`, and any other `T` whose `Default` is its zero value. A caller may rely on
/// an untouched array element or tail being `T::default()`, specifically zero for
/// byte and integer arrays, the same way it relies on any other documented API
/// surface. Replacing this with a poison-fill pattern — plausible-sounding for
/// something named "sentinel", and permitted by the trait-level contract alone,
/// which only rules out secret material — would be a **breaking change** to this
/// implementation, not a hardening of it, because it would silently corrupt every
/// zero-padded value [`Fixed::new_with`](crate::Fixed::new_with) or
/// [`Fixed::try_new_with`](crate::Fixed::try_new_with) produces through their
/// pre-fill, not only values that pass through `into_inner`.
///
/// [`Dynamic::new_with`](crate::Dynamic::new_with) does not go through this trait for
/// its own pre-fill — it zero-fills its heap slot directly (`vec![0u8; len]`, always
/// zero, independent of any `SentinelValue` impl) rather than asking `Vec<T>`'s
/// sentinel for a length it cannot produce (`Vec::new()` is empty, not zeroed to a
/// given length). This contract binds the `[T; N]` row read through
/// [`Fixed`](crate::Fixed) and through `into_inner` on any wrapper around a `[T; N]`;
/// it does not extend to `Dynamic`'s unrelated, and separately guaranteed, zero-fill.
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
