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
//! Known gap: this suite verifies "no false positive on correct code" but does not include a
//! positive-control test that verifies the proxy *catches* non-zeroed memory. A safe positive
//! control would need `AtomicBool CAUGHT` + `std::panic::catch_unwind` to avoid panicking
//! inside `GlobalAlloc::dealloc`. Deferred to a future improvement.

#![cfg(all(feature = "alloc", not(miri)))]
#![allow(clippy::undocumented_unsafe_blocks)]

use secure_gate::{Dynamic, RevealSecretMut};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// Assertion gate — active only while one check is running
// ---------------------------------------------------------------------------

/// Set to `true` only while the active test's closure is executing.
static CHECKING: AtomicBool = AtomicBool::new(false);

/// The exact byte count of the heap allocation currently under scrutiny.
/// Written before `CHECKING` is enabled.
static TARGET_SIZE: AtomicUsize = AtomicUsize::new(0);

// ---------------------------------------------------------------------------
// ProxyAllocator — adapted from upstream zeroize/tests/alloc.rs
// ---------------------------------------------------------------------------

/// A `GlobalAlloc` wrapper that asserts deallocated memory is fully zeroed
/// for allocations of exactly `TARGET_SIZE` bytes while `CHECKING` is active.
struct ProxyAllocator;

unsafe impl GlobalAlloc for ProxyAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if CHECKING.load(Ordering::SeqCst) && layout.size() == TARGET_SIZE.load(Ordering::SeqCst) {
            for i in 0..layout.size() {
                let b = unsafe { core::ptr::read(ptr.add(i)) };
                assert_eq!(b, 0, "byte at offset {i} was not zeroed before dealloc");
            }
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static PROXY: ProxyAllocator = ProxyAllocator;

// ---------------------------------------------------------------------------
// CheckGuard — RAII gate reset
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
// Test helper
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
// Dynamic<Vec<u8>> — decode-path backing-buffer zeroization test
//
// Verifies that decoding into a `Dynamic<Vec<u8>>` via `try_from_hex` and then
// dropping the result correctly zeroizes the backing buffer. This exercises the
// `protect_decode_result` path added in issue #96.
//
// Note: on the error path (invalid input) no `Vec` is returned by the decoder,
// so there is no intermediate buffer for `Zeroizing` to clean up — the `?`
// propagates before our code ever holds bytes. The protection provided by the
// `Zeroizing` wrapper is for panics between a *successful* decode and `Self::new`.
// ---------------------------------------------------------------------------

#[cfg(feature = "encoding-hex")]
fn check_decode_temp_zeroed(hex: &str, expected_len: usize) {
    with_proxy_check(expected_len, || {
        let secret = Dynamic::<Vec<u8>>::try_from_hex(hex).expect("valid hex");
        // Prevent the compiler from eliding construction before zeroization runs on drop.
        core::hint::black_box(&secret);
        drop(secret); // explicit: must occur while CHECKING is true
    });
}

/// Verifies `Dynamic<[u8; N]>`, `Dynamic<Vec<u8>>`, `Dynamic<String>`, and the
/// `try_from_hex` decode path all zeroize heap memory before deallocation.
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

    // Dynamic<Vec<u8>> decode path — verify backing buffer is zeroized after
    // decoding via try_from_hex and dropping the result (#96)
    #[cfg(feature = "encoding-hex")]
    {
        check_decode_temp_zeroed("deadbeef", 4);
        check_decode_temp_zeroed("0102030405060708090a0b0c0d0e0f10", 16);
    }
}
