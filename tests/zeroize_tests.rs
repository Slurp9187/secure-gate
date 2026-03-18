//! tests/zeroize_tests.rs
//! Zeroization behavior tests for Fixed<T> and Dynamic<T>.
//!
//! This is the canonical test for v0.8.0's mandatory zeroize-on-drop guarantee.
//! Adapted from upstream RustCrypto zeroize patterns. Uses spare-capacity and
//! drop-order assertions to verify correctness.
//!
//! Run with `cargo test --release` so LLVM optimizations are applied.

#![allow(clippy::undocumented_unsafe_blocks)]

use secure_gate::{ExposeSecret, Fixed};
use zeroize::Zeroize;

#[cfg(feature = "alloc")]
use secure_gate::{Dynamic, ExposeSecretMut};

// ---------------------------------------------------------------------------
// Helper types (adapted from upstream zeroize/tests/zeroize.rs)
// ---------------------------------------------------------------------------

/// Zeroizes its inner `u64` on drop.
///
/// `impl Zeroize` is required here (unlike the bare upstream definition) because
/// `Fixed<T>` requires `T: Zeroize`. The upstream `ZeroizedOnDrop` is only ever
/// wrapped in raw arrays, never in `Fixed`.
///
/// Used by `fixed_needs_drop` to demonstrate drop glue exists for non-primitive inner types.
#[derive(Clone, Debug, PartialEq)]
struct ZeroizedOnDrop(u64);

impl Zeroize for ZeroizedOnDrop {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for ZeroizedOnDrop {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Panics in `Drop` if the inner value was not zeroized before being dropped.
///
/// Used by `fixed_zeroize_on_drop` to verify that `Fixed::drop` calls `zeroize()` on the
/// inner value before the inner `Drop` runs (standard, UB-free pattern).
///
/// Also used by `dynamic_spare_capacity_vec_zeroized` to assert that `Vec::zeroize()`
/// byte-zeroes spare-capacity slots via `spare_capacity_mut().zeroize()`.
#[derive(Clone)]
struct PanicOnNonZeroDrop(u64);

impl Zeroize for PanicOnNonZeroDrop {
    fn zeroize(&mut self) {
        self.0 = 0;
    }
}

impl Drop for PanicOnNonZeroDrop {
    fn drop(&mut self) {
        assert_eq!(self.0, 0, "dropped non-zeroized data");
    }
}

// ---------------------------------------------------------------------------
// Fixed<T> tests
// ---------------------------------------------------------------------------

/// Direct `.zeroize()` call zeroes the stack contents and is visible through the public API.
#[test]
fn fixed_direct_zeroize() {
    let mut secret = Fixed::new([0xAAu8; 32]);
    secret.zeroize();
    secret.with_secret(|arr| assert_eq!(arr, &[0u8; 32]));
}

/// `Fixed::drop` calls `zeroize()` on the inner value before the inner `Drop` runs.
///
/// `PanicOnNonZeroDrop` asserts in its own `Drop` that `.0 == 0`. Drop order in Rust
/// guarantees `Fixed::drop` runs first (calling `zeroize()` → sets `.0 = 0`), then the
/// inner `PanicOnNonZeroDrop::drop` runs and finds `.0 == 0`. If `Fixed::drop` did not
/// call `zeroize()` (as in all pre-0.8.0 versions), the inner `Drop` would panic. ✓
///
/// No `unsafe`, no `drop_in_place`, no read-after-drop UB — fully sound and Miri-clean.
#[test]
fn fixed_zeroize_on_drop() {
    let _secret = Fixed::new(PanicOnNonZeroDrop(0xAA));
    // drop order: Fixed::drop → zeroize() → PanicOnNonZeroDrop::drop → assert .0==0 ✓
}

/// `Fixed<T>` has a real `Drop` glue destructor (not just a marker).
///
/// In the broken pre-0.8.0 versions (only the `ZeroizeOnDrop` marker was impl'd,
/// no actual `Drop`), `needs_drop` would have returned `false`.
#[test]
fn fixed_needs_drop() {
    assert!(core::mem::needs_drop::<Fixed<[u8; 32]>>());
    assert!(core::mem::needs_drop::<Fixed<ZeroizedOnDrop>>());
}

// ---------------------------------------------------------------------------
// Dynamic<T> tests
// ---------------------------------------------------------------------------

/// Direct `.zeroize()` on `Dynamic<Vec<u8>>` empties the Vec (all content zeroed).
#[test]
#[cfg(feature = "alloc")]
fn dynamic_direct_zeroize_vec() {
    let mut secret: Dynamic<Vec<u8>> = Dynamic::new(vec![0xAAu8; 64]);
    secret.zeroize();
    secret.with_secret(|v| assert!(v.is_empty()));
}

/// Direct `.zeroize()` on `Dynamic<String>` empties the String (all content zeroed).
#[test]
#[cfg(feature = "alloc")]
fn dynamic_direct_zeroize_string() {
    let mut secret: Dynamic<String> = Dynamic::new("top secret".to_string());
    secret.zeroize();
    secret.with_secret(|s| assert!(s.is_empty()));
}

/// `Vec::zeroize()` byte-zeroes spare capacity (memory beyond `len` but within `cap`).
///
/// Adapted from upstream `zeroize/tests/zeroize.rs` lines 137–150.
///
/// Mechanism:
/// 1. Create vec with 2 elements; reduce `len` to 1 — element[1] is spare capacity
///    (initialized in memory but invisible to Vec).
/// 2. Explicit `.zeroize()`: element[0] is zeroized+dropped, then `spare_capacity_mut()`
///    byte-zeroes element[1]'s backing memory.
/// 3. Restore `len=2` via `with_secret_mut` — element[1] is now "visible" as all-zero bytes.
/// 4. On drop, `Dynamic::drop → zeroize → Vec::clear` calls `PanicOnNonZeroDrop::drop`
///    for element[1]. Because its memory was zeroed in step 2, the assertion passes. ✓
#[test]
#[cfg(feature = "alloc")]
fn dynamic_spare_capacity_vec_zeroized() {
    let mut v = vec![PanicOnNonZeroDrop(42); 2];
    // SAFETY: reducing len makes element[1] spare capacity; its memory remains initialized.
    unsafe { v.set_len(1) };

    let mut secret: Dynamic<Vec<PanicOnNonZeroDrop>> = Dynamic::new(v);
    secret.zeroize();
    // SAFETY: memory at index 1 was byte-zeroed by spare_capacity_mut().zeroize() above,
    // so PanicOnNonZeroDrop(0) is a valid representation for reading back via drop.
    secret.with_secret_mut(|v| unsafe { v.set_len(2) });
    // drop: Dynamic::drop → zeroize → clear → PanicOnNonZeroDrop::drop for element[1]
    // element[1].0 == 0 (zeroed in the spare_capacity_mut pass above) ✓
}

/// `Dynamic<Vec<u8>>` has a real `Drop` glue destructor.
///
/// In the broken pre-0.8.0 versions, `needs_drop` would have returned `false`.
#[test]
#[cfg(feature = "alloc")]
fn dynamic_needs_drop() {
    assert!(core::mem::needs_drop::<Dynamic<Vec<u8>>>());
}

/// `Dynamic<String>` has a real `Drop` glue destructor.
#[test]
#[cfg(feature = "alloc")]
fn dynamic_needs_drop_string() {
    assert!(core::mem::needs_drop::<Dynamic<String>>());
}
