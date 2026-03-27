//! Heap-level zeroization verification for `Dynamic<T>`.
//!
//! Uses a `ProxyAllocator` (adapted from upstream `zeroize/tests/alloc.rs`) that intercepts
//! deallocations and asserts that the backing memory is fully zeroed before it is freed.
//!
//! This is a separate integration test binary so that `#[global_allocator]` does not interfere
//! with other test binaries. Do NOT merge this file into `zeroize_tests.rs`.
//!
//! Upstream `alloc.rs` checks a specific size unconditionally because their test binary is
//! minimal. Here we additionally gate on an `AtomicBool` + `AtomicUsize` pair to avoid false
//! positives from the test harness, which may allocate objects of the same size for internal
//! bookkeeping.
//!
//! IMPORTANT: this file intentionally uses one aggregate `#[test]` (`all_heap_zeroed`) that runs
//! all size checks sequentially. Avoid splitting this into multiple `#[test]` functions:
//! `ProxyAllocator` is global process state and parallel tests can interleave allocator activity,
//! causing false positives in CI.
//!
//! The panic-path positive-control test (`check_panic_path_bytes_zeroed`) uses a separate
//! recording mode (PANIC_CHECK_*) that records without asserting inside `dealloc`, then checks
//! after `catch_unwind` returns — safe because `dealloc` must never panic (allocator contract).
//! Size 8192 is used to avoid collision with small Rust panic-machinery allocations (message
//! formatting, backtrace, TLS) that may occur during unwind.

#![cfg(all(feature = "alloc", not(miri)))]
#![allow(clippy::undocumented_unsafe_blocks)]

use secure_gate::{Dynamic, RevealSecret, RevealSecretMut};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// Asserting-mode gate — active only while one happy-path check is running
// ---------------------------------------------------------------------------

/// Set to `true` only while the active test's closure is executing.
static CHECKING: AtomicBool = AtomicBool::new(false);

/// The exact byte count of the heap allocation currently under scrutiny.
/// Written before `CHECKING` is enabled.
static TARGET_SIZE: AtomicUsize = AtomicUsize::new(0);

// ---------------------------------------------------------------------------
// Recording-mode gate — used by the panic-path positive-control test
//
// Unlike the asserting mode, the recording mode never panics inside `dealloc`
// (which would be UB per the allocator contract). Instead it silently records
// whether the first matching deallocation was fully zeroed, then the test
// checks the result after `catch_unwind` returns.
// ---------------------------------------------------------------------------

/// Set to `true` before `catch_unwind`; cleared by `dealloc` on first match.
static PANIC_CHECK_ACTIVE: AtomicBool = AtomicBool::new(false);

/// The exact backing-buffer pointer of the allocation being tracked in recording mode.
/// Matching by pointer rather than by size makes the test immune to same-size
/// allocations from panic machinery (backtrace, symbol resolution, TLS).
static PANIC_CHECK_PTR: AtomicUsize = AtomicUsize::new(0);

/// `true` iff the tracked allocation was fully zeroed when its dealloc was observed.
static PANIC_CHECK_ZEROED: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// ProxyAllocator — adapted from upstream zeroize/tests/alloc.rs
// ---------------------------------------------------------------------------

/// A `GlobalAlloc` wrapper that:
///   - In **asserting mode** (`CHECKING`): panics if a deallocation of
///     `TARGET_SIZE` bytes contains any non-zero byte.
///   - In **recording mode** (`PANIC_CHECK_ACTIVE`): silently records whether
///     the deallocation of the specific pointer in `PANIC_CHECK_PTR` was fully
///     zeroed. Pointer-based matching avoids false results from same-size
///     allocations made by panic infrastructure (backtrace, symbol resolution).
struct ProxyAllocator;

unsafe impl GlobalAlloc for ProxyAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // Asserting mode: panic on non-zeroed bytes (never called during unwind)
        if CHECKING.load(Ordering::SeqCst) && layout.size() == TARGET_SIZE.load(Ordering::SeqCst) {
            for i in 0..layout.size() {
                let b = unsafe { core::ptr::read(ptr.add(i)) };
                assert_eq!(b, 0, "byte at offset {i} was not zeroed before dealloc");
            }
        }

        // Recording mode: match by exact pointer, not size, to avoid false results
        // from panic-infrastructure allocations of the same size (backtrace buffers,
        // symbol tables). Never panics — safe to call inside dealloc.
        if PANIC_CHECK_ACTIVE.load(Ordering::SeqCst)
            && PANIC_CHECK_PTR.load(Ordering::SeqCst) != 0
            && ptr as usize == PANIC_CHECK_PTR.load(Ordering::SeqCst)
        {
            let all_zero = (0..layout.size()).all(|i| unsafe { *ptr.add(i) == 0 });
            PANIC_CHECK_ZEROED.store(all_zero, Ordering::SeqCst);
            PANIC_CHECK_ACTIVE.store(false, Ordering::SeqCst);
        }

        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static PROXY: ProxyAllocator = ProxyAllocator;

// ---------------------------------------------------------------------------
// CheckGuard — RAII gate reset for asserting mode
// ---------------------------------------------------------------------------

/// RAII guard that clears the allocator check gate on drop (both normal return and unwind).
///
/// Without this, a panic inside the closure (e.g. from the capacity assertion) would leave
/// `CHECKING = true` during stack unwinding. Every subsequent deallocation of `TARGET_SIZE`
/// bytes during unwind — including panic-formatting allocations from `assert_eq!` / `format_args!`
/// — would be inspected, producing cascading assertion failures and confusing output.
///
/// Residual: panic-formatting allocations that occur *inside* the closure while the guard is
/// active are still inspected. In practice they are unlikely to match `TARGET_SIZE` exactly.
struct CheckGuard;

impl Drop for CheckGuard {
    fn drop(&mut self) {
        CHECKING.store(false, Ordering::SeqCst);
    }
}

// ---------------------------------------------------------------------------
// Test helper — asserting mode
// ---------------------------------------------------------------------------

/// Runs `f` under the ProxyAllocator gate for allocations of exactly `size` bytes.
///
/// The `CheckGuard` ensures the gate is cleared even if `f` panics.
/// This helper assumes checks are executed sequentially by a single aggregate test function.
fn with_proxy_check<F: FnOnce()>(size: usize, f: F) {
    TARGET_SIZE.store(size, Ordering::SeqCst);
    CHECKING.store(true, Ordering::SeqCst);
    let _guard = CheckGuard; // cleared on return OR on unwind
    f();
}

// ---------------------------------------------------------------------------
// Dynamic<[u8; N]> — fixed-size boxed array tests
//
// `Dynamic<[u8; N]>` boxes the array into a single `Box<[u8; N]>` — exactly
// one heap allocation of `N` bytes. When dropped, `Dynamic::drop` calls
// `zeroize()` which zeroes all N bytes. The ProxyAllocator then confirms all
// bytes are 0 before forwarding the deallocation to the system allocator.
// ---------------------------------------------------------------------------

fn check_array_zeroed<const N: usize>() {
    with_proxy_check(N, || {
        let secret: Dynamic<[u8; N]> = Dynamic::new([0xAAu8; N]);
        // Prevent the compiler from eliding construction or the fill pattern
        // before zeroization runs on drop.
        core::hint::black_box(&secret);
        drop(secret); // explicit: must occur while CHECKING is true
    });
}

// ---------------------------------------------------------------------------
// Dynamic<Vec<u8>> — backing-buffer zeroization tests
//
// `Dynamic<Vec<u8>>` = `Box<Vec<u8>>`. There are two distinct heap allocations:
//
//   1. The `Box<Vec<u8>>` struct itself (24 bytes on 64-bit: ptr + len + cap).
//      `Vec::zeroize()` does NOT zero this struct — it zeroes the *content*.
//
//   2. The Vec's backing buffer (`capacity` bytes) — IS zeroed by `Vec::zeroize()`.
//
// We set `TARGET_SIZE` to the data size N (the backing-buffer size after
// `shrink_to_fit`), NOT to 24. The ProxyAllocator catches the backing-buffer
// deallocation and asserts all N bytes are zero. The 24-byte Box struct
// deallocation is intentionally not checked (correct behavior: Vec header
// is freed but its fields are not expected to be zeroed).
//
// All test sizes are powers of two (16/32/64/128) to align with common
// allocator size classes and avoid rounding after shrink_to_fit.
// ---------------------------------------------------------------------------

fn check_vec_zeroed(size: usize) {
    with_proxy_check(size, || {
        let mut secret: Dynamic<Vec<u8>> = Dynamic::new(Vec::with_capacity(size));
        secret.with_secret_mut(|v| {
            // Fill exactly N bytes so len == N before shrink_to_fit.
            v.extend(std::iter::repeat(0xBBu8).take(size));
            v.shrink_to_fit();
            // Test realism guard: shrink_to_fit is best-effort; the allocator may
            // leave capacity larger than len. Assert exact capacity so TARGET_SIZE
            // matches layout.size() on dealloc — without this, the proxy check is
            // silently skipped (false negative).
            assert_eq!(
                v.capacity(),
                size,
                "allocator rounded up capacity after shrink_to_fit — proxy check would be skipped"
            );
        });
        // Prevent the compiler from eliding construction or the fill pattern
        // before zeroization runs on drop.
        core::hint::black_box(&secret);
        drop(secret); // explicit: must occur while CHECKING is true
    });
}

// ---------------------------------------------------------------------------
// Dynamic<String> — backing-buffer zeroization test
//
// `Dynamic<String>` wraps a `Box<String>`. The String's backing buffer is
// heap-allocated separately. `String::zeroize()` zeroes all bytes in the
// allocated buffer (bytes, not characters — encoding is irrelevant here).
// After shrink_to_fit ensures len == capacity == N, the ProxyAllocator
// confirms all N bytes are zeroed before deallocation.
//
// All test sizes are powers of two (16/32/64/128) to align with common
// allocator size classes and avoid rounding after shrink_to_fit.
// ---------------------------------------------------------------------------

fn check_string_zeroed(size: usize) {
    with_proxy_check(size, || {
        let mut secret: Dynamic<String> = Dynamic::new(String::with_capacity(size));
        secret.with_secret_mut(|s| {
            // Fill exactly `size` ASCII bytes so len == size before shrink_to_fit.
            s.extend(std::iter::repeat('A').take(size));
            s.shrink_to_fit();
            // Test realism guard: same rationale as check_vec_zeroed above.
            assert_eq!(
                s.capacity(),
                size,
                "allocator rounded up capacity after shrink_to_fit — proxy check would be skipped"
            );
        });
        // Prevent the compiler from eliding construction or the fill pattern
        // before zeroization runs on drop.
        core::hint::black_box(&secret);
        drop(secret); // explicit: must occur while CHECKING is true
    });
}

// ---------------------------------------------------------------------------
// Dynamic<Vec<u8>> — decode-path backing-buffer zeroization tests
//
// Verifies that decoding into a `Dynamic<Vec<u8>>` and then dropping the
// result correctly zeroizes the backing buffer. Each function exercises a
// different decode path (hex, base64url, bech32, bech32m) to confirm that
// all six constructors using `from_protected_bytes` produce a correctly
// zeroized result on the happy path.
//
// Note: on the error path (invalid input) no `Vec` is returned by the decoder,
// so there is no intermediate buffer — the `?` propagates before our code ever
// holds bytes.
//
// The decode is performed OUTSIDE the proxy window to avoid false positives
// from decoder-internal allocations of the same size. Only the final drop of
// the `Dynamic` occurs inside the proxy window.
// ---------------------------------------------------------------------------

#[cfg(feature = "encoding-hex")]
fn check_decode_hex_zeroed(hex: &str, expected_len: usize) {
    with_proxy_check(expected_len, || {
        let secret = Dynamic::<Vec<u8>>::try_from_hex(hex).expect("valid hex");
        core::hint::black_box(&secret);
        drop(secret); // explicit: must occur while CHECKING is true
    });
}

#[cfg(feature = "encoding-base64")]
fn check_decode_base64_zeroed(data: &[u8]) {
    use secure_gate::ToBase64Url;
    let encoded = data.to_base64url();
    let mut secret =
        Dynamic::<Vec<u8>>::try_from_base64url(&encoded).expect("valid base64url");
    // Shrink to exact len so TARGET_SIZE matches layout.size() on dealloc.
    secret.with_secret_mut(|v| {
        v.shrink_to_fit();
        assert_eq!(
            v.capacity(),
            data.len(),
            "allocator rounded up capacity after shrink_to_fit — proxy check would be skipped"
        );
    });
    with_proxy_check(data.len(), move || {
        core::hint::black_box(&secret);
        drop(secret);
    });
}

#[cfg(feature = "encoding-bech32")]
fn check_decode_bech32_zeroed(data: &[u8]) {
    use secure_gate::ToBech32;
    let encoded = data.try_to_bech32("test").expect("valid hrp");
    let mut secret =
        Dynamic::<Vec<u8>>::try_from_bech32(&encoded, "test").expect("valid bech32");
    secret.with_secret_mut(|v| {
        v.shrink_to_fit();
        assert_eq!(
            v.capacity(),
            data.len(),
            "allocator rounded up capacity after shrink_to_fit — proxy check would be skipped"
        );
    });
    with_proxy_check(data.len(), move || {
        core::hint::black_box(&secret);
        drop(secret);
    });
}

#[cfg(feature = "encoding-bech32m")]
fn check_decode_bech32m_zeroed(data: &[u8]) {
    use secure_gate::ToBech32m;
    let encoded = data.try_to_bech32m("testm").expect("valid hrp");
    let mut secret =
        Dynamic::<Vec<u8>>::try_from_bech32m(&encoded, "testm").expect("valid bech32m");
    secret.with_secret_mut(|v| {
        v.shrink_to_fit();
        assert_eq!(
            v.capacity(),
            data.len(),
            "allocator rounded up capacity after shrink_to_fit — proxy check would be skipped"
        );
    });
    with_proxy_check(data.len(), move || {
        core::hint::black_box(&secret);
        drop(secret);
    });
}

// ---------------------------------------------------------------------------
// Dynamic<Vec<u8>> / Dynamic<String> — serde deserialize-path zeroization
//
// Verifies that bytes materialized by `deserialize_with_limit` are correctly
// zeroized when the `Dynamic` is dropped. The deserialize call and
// shrink_to_fit happen OUTSIDE the proxy window to avoid interference from
// serde_json's internal allocations.
// ---------------------------------------------------------------------------

#[cfg(feature = "serde-deserialize")]
fn check_vec_deserialized_zeroed(size: usize) {
    // Build JSON array outside the proxy window.
    let json: String = {
        let nums: Vec<String> = (0..size).map(|i| (i as u8).to_string()).collect();
        format!("[{}]", nums.join(","))
    };
    let mut de = serde_json::Deserializer::from_str(&json);
    let mut secret = Dynamic::<Vec<u8>>::deserialize_with_limit(&mut de, size)
        .expect("within limit");
    secret.with_secret_mut(|v| {
        v.shrink_to_fit();
        assert_eq!(
            v.capacity(),
            size,
            "allocator rounded up capacity after shrink_to_fit — proxy check would be skipped"
        );
    });
    with_proxy_check(size, move || {
        core::hint::black_box(&secret);
        drop(secret);
    });
}

#[cfg(feature = "serde-deserialize")]
fn check_string_deserialized_zeroed(size: usize) {
    // Build JSON string of exactly `size` ASCII bytes outside the proxy window.
    let json: String = format!("\"{}\"", "A".repeat(size));
    let mut de = serde_json::Deserializer::from_str(&json);
    let mut secret = Dynamic::<String>::deserialize_with_limit(&mut de, size)
        .expect("within limit");
    secret.with_secret_mut(|s| {
        s.shrink_to_fit();
        assert_eq!(
            s.capacity(),
            size,
            "allocator rounded up capacity after shrink_to_fit — proxy check would be skipped"
        );
    });
    with_proxy_check(size, move || {
        core::hint::black_box(&secret);
        drop(secret);
    });
}

// ---------------------------------------------------------------------------
// Dynamic<Vec<u8>> — into_inner path backing-buffer zeroization tests
//
// Verifies that calling `into_inner()` on a `Dynamic<Vec<u8>>` and then
// dropping the returned `Zeroizing<Vec<u8>>` physically zeroes the backing
// buffer before deallocation. This closes the physical verification gap for
// the new `into_inner` code path: `zeroize_tests.rs` proves semantic
// correctness (spare-capacity, drop order); this test proves LLVM has not
// dead-store-eliminated the volatile writes through the
// `Zeroizing` → `Vec::zeroize()` path.
//
// The test follows the same pattern as `check_vec_zeroed`: fill a Vec of
// exactly `size` bytes, `shrink_to_fit`, then call `into_inner()` and drop
// the result while the ProxyAllocator gate is active.
// ---------------------------------------------------------------------------

fn check_into_inner_vec_zeroed(size: usize) {
    with_proxy_check(size, || {
        let mut secret: Dynamic<Vec<u8>> = Dynamic::new(Vec::with_capacity(size));
        secret.with_secret_mut(|v| {
            v.extend(std::iter::repeat(0xCCu8).take(size));
            v.shrink_to_fit();
            assert_eq!(
                v.capacity(),
                size,
                "allocator rounded up capacity after shrink_to_fit — proxy check would be skipped"
            );
        });
        core::hint::black_box(&secret);
        // Consume the wrapper; the returned Zeroizing<Vec<u8>> must zero the
        // backing buffer when it drops.
        let extracted = secret.into_inner();
        core::hint::black_box(&extracted);
        drop(extracted); // explicit: must occur while CHECKING is true
    });
}

// ---------------------------------------------------------------------------
// Panic-path positive-control test
//
// Verifies that `Zeroizing::drop` actually zeroes the backing buffer when a
// panic fires while `Zeroizing<Vec<u8>>` is in scope — the exact guarantee
// that `from_protected_bytes` relies on.
//
// Design:
//   1. Enable recording mode (PANIC_CHECK_ACTIVE).
//   2. Inside `catch_unwind`: allocate a Vec, pin its backing-buffer pointer
//      in PANIC_CHECK_PTR, wrap in Zeroizing, then panic. During unwind,
//      Zeroizing::drop → Vec::zeroize() → dealloc → pointer match → record.
//   3. After `catch_unwind`: assert PANIC_CHECK_ZEROED == true.
//
// Matching by pointer (not size) makes the test immune to same-size
// allocations from panic machinery. Under ASan with `build-std`, Rust's
// backtrace infrastructure allocates buffers during panic processing (observed:
// 8192 bytes). A size-based match would intercept a non-zeroed backtrace
// buffer instead of the Zeroizing-protected Vec, falsely failing the test.
//
// Regression value: this test would FAIL with the old `mem::take` pattern,
// because `mem::take` leaves `protected` holding an empty Vec at panic time.
// No SIZE-byte deallocation would be zeroed during unwind → PANIC_CHECK_ZEROED
// stays false → assertion fails. With `from_protected_bytes` (swap), the live
// `Zeroizing` holds the full buffer at panic time and zeroizes it on unwind.
// ---------------------------------------------------------------------------

fn check_panic_path_bytes_zeroed(size: usize) {
    PANIC_CHECK_PTR.store(0, Ordering::SeqCst);
    PANIC_CHECK_ZEROED.store(false, Ordering::SeqCst);
    PANIC_CHECK_ACTIVE.store(true, Ordering::SeqCst);

    // Simulate a panic that fires after Zeroizing::new but before Box::new —
    // the exact OOM window that `from_protected_bytes` is designed to protect.
    let result = std::panic::catch_unwind(|| {
        let v = vec![0xAAu8; size];
        // Pin the exact backing-buffer pointer before wrapping in Zeroizing.
        // dealloc matches this pointer, not the size, so concurrent panic-
        // infrastructure allocations of the same size don't interfere.
        PANIC_CHECK_PTR.store(v.as_ptr() as usize, Ordering::SeqCst);
        let _protected = zeroize::Zeroizing::new(v);
        // `_protected` is still alive. During unwind its Drop impl runs:
        // Zeroizing::drop → Vec::zeroize() → backing buffer zeroed → dealloc.
        panic!("simulated OOM before Box allocation");
    });

    PANIC_CHECK_ACTIVE.store(false, Ordering::SeqCst); // defensive cleanup
    assert!(result.is_err(), "catch_unwind should have captured the panic");
    assert!(
        PANIC_CHECK_ZEROED.load(Ordering::SeqCst),
        "Zeroizing must zero its backing buffer even when a panic fires before Box::new"
    );
}

// ---------------------------------------------------------------------------
// Aggregate test
// ---------------------------------------------------------------------------

/// Verifies `Dynamic<[u8; N]>`, `Dynamic<Vec<u8>>`, `Dynamic<String>`, all
/// decode paths, all deserialize paths, and the panic-path positive control
/// all zeroize heap memory before deallocation.
///
/// This stays as one aggregate test by design to avoid parallel test interleaving
/// with the global ProxyAllocator state.
#[test]
fn all_heap_zeroed() {
    // Dynamic<[u8; N]> — boxed arrays
    check_array_zeroed::<16>();
    check_array_zeroed::<32>();
    check_array_zeroed::<64>();
    check_array_zeroed::<128>();

    // Dynamic<Vec<u8>> and Dynamic<String> — interleaved for structural size parity
    for size in [16usize, 32, 64, 128] {
        check_vec_zeroed(size);
        check_string_zeroed(size);
    }

    // Decode-path backing-buffer zeroization (#96 / from_protected_bytes fix)
    #[cfg(feature = "encoding-hex")]
    {
        check_decode_hex_zeroed("deadbeef", 4);
        check_decode_hex_zeroed("0102030405060708090a0b0c0d0e0f10", 16);
    }

    #[cfg(feature = "encoding-base64")]
    {
        check_decode_base64_zeroed(&[0xAAu8; 16]);
        check_decode_base64_zeroed(&[0xBBu8; 32]);
    }

    #[cfg(feature = "encoding-bech32")]
    {
        check_decode_bech32_zeroed(&[0xAAu8; 16]);
        check_decode_bech32_zeroed(&[0xBBu8; 32]);
    }

    #[cfg(feature = "encoding-bech32m")]
    {
        check_decode_bech32m_zeroed(&[0xAAu8; 16]);
        check_decode_bech32m_zeroed(&[0xBBu8; 32]);
    }

    // Deserialize-path backing-buffer zeroization (deserialize_with_limit fix)
    #[cfg(feature = "serde-deserialize")]
    {
        check_vec_deserialized_zeroed(16);
        check_vec_deserialized_zeroed(32);
        check_string_deserialized_zeroed(16);
        check_string_deserialized_zeroed(32);
    }

    // into_inner path: verify Vec<u8> backing buffer is physically zeroed when the
    // returned Zeroizing<Vec<u8>> drops (closes the physical verification gap for
    // the into_inner code path added in issue #105).
    for size in [16usize, 32, 64, 128] {
        check_into_inner_vec_zeroed(size);
    }

    // Panic-path positive control: proves Zeroizing zeroes bytes on unwind.
    // Size 8192 avoids collision with panic-machinery allocations (see comment above).
    check_panic_path_bytes_zeroed(8192);
}
