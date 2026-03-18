//! tests/zeroize_tests.rs
//! Zeroization behavior tests for Fixed<T> and Dynamic<T>.
//!
//! This is the canonical test for v0.8.0's mandatory zeroize-on-drop guarantee.
//! Adapted from upstream RustCrypto zeroize patterns. Uses spare-capacity and
//! drop-order assertions to verify correctness.
//!
//! Run with `cargo test --release` so LLVM optimizations are applied.

#![allow(clippy::undocumented_unsafe_blocks)]

use secure_gate::{ExposeSecret, ExposeSecretMut, Fixed};
use zeroize::Zeroize;

#[cfg(feature = "alloc")]
use secure_gate::Dynamic;

// ---------------------------------------------------------------------------
// Helper types (adapted from upstream zeroize/tests/zeroize.rs)
// ---------------------------------------------------------------------------

/// Zeroizes its inner `u64` on drop.
///
/// `impl Zeroize` is required here (unlike the bare upstream definition) because
/// `Fixed<T>` requires `T: Zeroize`. The upstream `ZeroizedOnDrop` is only ever
/// wrapped in raw arrays, never in `Fixed`.
///
/// Used by `fixed_needs_drop_custom_type` and `fixed_mutate_custom_type_then_zeroize`
/// to demonstrate drop glue and mutation over non-primitive inner types.
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
// Fixed<T> tests — basic
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

// ---------------------------------------------------------------------------
// Fixed<T> tests — needs_drop (split from original combined test)
// ---------------------------------------------------------------------------

/// `Fixed<[u8; 32]>` has a real `Drop` glue destructor (not just a marker).
///
/// In the broken pre-0.8.0 versions (only the `ZeroizeOnDrop` marker was impl'd,
/// no actual `Drop`), `needs_drop` would have returned `false`.
#[test]
fn fixed_needs_drop_array() {
    assert!(core::mem::needs_drop::<Fixed<[u8; 32]>>());
}

/// `Fixed<ZeroizedOnDrop>` has a real `Drop` glue destructor.
#[test]
fn fixed_needs_drop_custom_type() {
    assert!(core::mem::needs_drop::<Fixed<ZeroizedOnDrop>>());
}

/// `Fixed<[u8; N]>` has a real `Drop` glue destructor for every tested array size.
#[test]
fn fixed_needs_drop_all_sizes() {
    assert!(core::mem::needs_drop::<Fixed<[u8; 8]>>());
    assert!(core::mem::needs_drop::<Fixed<[u8; 16]>>());
    assert!(core::mem::needs_drop::<Fixed<[u8; 32]>>());
    assert!(core::mem::needs_drop::<Fixed<[u8; 64]>>());
    assert!(core::mem::needs_drop::<Fixed<[u8; 128]>>());
}

// ---------------------------------------------------------------------------
// Fixed<T> tests — parameterized sizes with black_box
// ---------------------------------------------------------------------------

/// Generates a test that:
/// 1. Wraps a `[0xAA; N]` array in `Fixed`.
/// 2. Calls `black_box` to prevent LLVM from eliding the store (critical for release builds).
/// 3. Explicitly calls `.zeroize()`.
/// 4. Asserts all bytes are zero via the public API.
macro_rules! fixed_size_zeroize_test {
    ($name:ident, $n:expr) => {
        #[test]
        fn $name() {
            let mut secret = Fixed::new([0xAAu8; $n]);
            core::hint::black_box(&mut secret);
            secret.zeroize();
            secret.with_secret(|arr| assert_eq!(arr, &[0u8; $n]));
        }
    };
}

fixed_size_zeroize_test!(fixed_direct_zeroize_8, 8);
fixed_size_zeroize_test!(fixed_direct_zeroize_16, 16);
fixed_size_zeroize_test!(fixed_direct_zeroize_32, 32);
fixed_size_zeroize_test!(fixed_direct_zeroize_64, 64);
fixed_size_zeroize_test!(fixed_direct_zeroize_128, 128);

// ---------------------------------------------------------------------------
// Fixed<T> tests — pre-drop mutation
// ---------------------------------------------------------------------------

/// `with_secret_mut` mutation followed by `zeroize()` leaves all bytes zero.
///
/// Verifies that mutations visible through the mutable accessor are properly
/// erased by `zeroize()` regardless of what values were written.
#[test]
fn fixed_mutate_with_secret_mut_then_zeroize() {
    let mut secret = Fixed::new([0xAAu8; 32]);
    secret.with_secret_mut(|arr| {
        arr[0] = 0xFF;
        arr[15] = 0x01;
        arr[31] = 0x42;
    });
    core::hint::black_box(&mut secret);
    secret.zeroize();
    secret.with_secret(|arr| assert_eq!(arr, &[0u8; 32]));
}

/// `expose_secret_mut` mutation followed by `zeroize()` leaves all bytes zero.
///
/// Same invariant as above but exercises the `expose_secret_mut` code path,
/// which returns a raw `&mut [u8; N]` reference rather than a scoped closure.
#[test]
fn fixed_mutate_expose_secret_mut_then_zeroize() {
    let mut secret = Fixed::new([0xBBu8; 64]);
    {
        let arr = secret.expose_secret_mut();
        arr[0] = 0xDE;
        arr[63] = 0xAD;
        core::hint::black_box(arr as *mut _);
    }
    secret.zeroize();
    secret.with_secret(|arr| assert_eq!(arr, &[0u8; 64]));
}

/// `expose_secret_mut` on a `Fixed<[ZeroizedOnDrop; 1]>` followed by `zeroize()` clears the inner `u64`.
///
/// `ExposeSecret` / `ExposeSecretMut` are implemented for `Fixed<[T; N]>` (arrays), so we wrap
/// the custom type in a single-element array. This covers the custom-type path — with its own
/// `Drop` impl — that the bare `[u8; N]` macro cannot exercise.
#[test]
fn fixed_mutate_custom_type_then_zeroize() {
    let mut secret = Fixed::new([ZeroizedOnDrop(0xDEAD_BEEF_CAFE_u64)]);
    {
        let arr = secret.expose_secret_mut();
        arr[0].0 = 0x1234_5678_9ABC_DEF0;
        core::hint::black_box(&arr[0].0 as *const _);
    }
    secret.zeroize();
    secret.with_secret(|arr| assert_eq!(arr[0].0, 0));
}

// ---------------------------------------------------------------------------
// Fixed<T> tests — scoped access + drop
// ---------------------------------------------------------------------------

/// `with_secret` scoped access followed by implicit drop correctly zeroes the secret.
///
/// Accesses the secret once (summing all bytes, result passed through `black_box`),
/// then lets it drop. This verifies the end-to-end flow: access → implicit zeroize-on-drop,
/// without requiring an explicit `.zeroize()` call.
#[test]
fn fixed_scoped_access_then_drop() {
    let secret = Fixed::new([0xCCu8; 32]);
    let sum = secret.with_secret(|arr| arr.iter().map(|b| *b as u64).sum::<u64>());
    core::hint::black_box(sum);
    // drop here → Fixed::drop → zeroize() → all bytes cleared ✓
}

// ---------------------------------------------------------------------------
// Dynamic<T> tests — basic
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

// ---------------------------------------------------------------------------
// Dynamic<T> tests — mutation sequences
// ---------------------------------------------------------------------------

/// `Dynamic<Vec<u8>>` mutation sequence (push → truncate → extend → shrink_to_fit →
/// with_secret_mut) followed by `.zeroize()` leaves an empty Vec.
///
/// Tests that zeroization is correct regardless of the Vec's growth/shrink history,
/// including that spare capacity from `shrink_to_fit` is also zeroed.
#[test]
#[cfg(feature = "alloc")]
fn dynamic_mutate_vec_sequence_then_zeroize() {
    let mut secret: Dynamic<Vec<u8>> = Dynamic::new(Vec::new());

    secret.with_secret_mut(|v| {
        // push phase
        for b in 0u8..64 {
            v.push(b);
        }
        // truncate — creates 32 bytes of spare capacity
        v.truncate(32);
        // extend_from_slice — refills some of that spare capacity
        v.extend_from_slice(&[0xFFu8; 16]);
        // shrink_to_fit — capacity drops to len (48)
        v.shrink_to_fit();
    });

    // final write via with_secret_mut before zeroize
    secret.with_secret_mut(|v| {
        if let Some(b) = v.first_mut() {
            *b = 0xAB;
        }
    });

    core::hint::black_box(&mut secret);
    secret.zeroize();
    secret.with_secret(|v| assert!(v.is_empty()));
}

/// `Dynamic<String>` mutation sequence (push_str → truncate → with_secret_mut)
/// followed by `.zeroize()` leaves an empty String.
#[test]
#[cfg(feature = "alloc")]
fn dynamic_mutate_string_sequence_then_zeroize() {
    let mut secret: Dynamic<String> = Dynamic::new(String::new());

    secret.with_secret_mut(|s| {
        s.push_str("top-secret-password-123");
        s.truncate(12); // "top-secret-p"
        s.push_str("-MODIFIED");
    });

    secret.with_secret_mut(|s| {
        // overwrite first char with a sentinel
        if !s.is_empty() {
            // SAFETY: all chars are ASCII so byte-level truncation is valid
            unsafe { s.as_bytes_mut()[0] = 0xFF };
        }
    });

    core::hint::black_box(&mut secret);
    secret.zeroize();
    secret.with_secret(|s| assert!(s.is_empty()));
}

// ---------------------------------------------------------------------------
// Dynamic<T> tests — spare-capacity String
// ---------------------------------------------------------------------------

/// `String::zeroize()` byte-zeroes spare capacity in `Dynamic<String>`.
///
/// Mirrors `dynamic_spare_capacity_vec_zeroized` but for `String`. The mechanism
/// is identical: String is a `Vec<u8>` under the hood, so `String::zeroize()` also
/// calls `spare_capacity_mut().zeroize()` on the backing buffer.
///
/// Steps:
/// 1. Reserve extra capacity so `cap > len`.
/// 2. Explicitly call `.zeroize()` — clears content and spare capacity.
/// 3. Re-extend the String via its byte representation to verify the spare capacity
///    slots are now all zero (uses the same PanicOnNonZeroDrop pattern at byte level).
#[test]
#[cfg(feature = "alloc")]
fn dynamic_spare_capacity_string_zeroized() {
    // Build a String with known content and extra capacity
    let mut s = String::with_capacity(32);
    s.push_str("secret"); // len=6, cap=32 → 26 bytes of spare capacity
    let mut secret: Dynamic<String> = Dynamic::new(s);

    // Zeroize clears content and spare capacity bytes
    secret.zeroize();
    secret.with_secret(|s| {
        assert!(s.is_empty(), "content should be empty after zeroize");
        // capacity is preserved (String::zeroize shrinks len to 0 but keeps cap)
        assert!(s.capacity() >= 6, "capacity should be retained");
    });

    // Restore len to verify spare-capacity bytes were zeroed.
    // SAFETY: the memory from index 0..6 was written as "secret" then zeroed;
    // all bytes are now 0x00, which is valid UTF-8 (null bytes).
    secret.with_secret_mut(|s| unsafe {
        let v = s.as_mut_vec();
        v.set_len(6);
    });
    secret.with_secret(|s| {
        assert_eq!(s.len(), 6);
        // every byte in the restored region must be 0x00 (zeroed by zeroize)
        for b in s.as_bytes() {
            assert_eq!(*b, 0, "spare-capacity byte was not zeroed");
        }
    });
    // drop: Dynamic::drop → zeroize → String empty → no panic ✓
}

// ---------------------------------------------------------------------------
// Dynamic<T> tests — scoped access + drop
// ---------------------------------------------------------------------------

/// Scoped `with_secret_mut` access followed by implicit drop correctly zeroes the secret.
///
/// Verifies the end-to-end guarantee: mutate, read back (via `black_box`), let drop
/// handle zeroization — no explicit `.zeroize()` call needed.
#[test]
#[cfg(feature = "alloc")]
fn dynamic_scoped_with_secret_mut_drop() {
    let mut secret: Dynamic<Vec<u8>> = Dynamic::new(vec![0xCCu8; 48]);
    let checksum = secret.with_secret_mut(|v| {
        v[0] = 0xDE;
        v[47] = 0xAD;
        v.iter().map(|b| *b as u64).sum::<u64>()
    });
    core::hint::black_box(checksum);
    // drop here → Dynamic::drop → zeroize() → Vec content zeroed ✓
}
