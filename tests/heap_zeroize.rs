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

#![cfg(all(feature = "alloc", not(miri)))]
#![allow(clippy::undocumented_unsafe_blocks)]

use secure_gate::{Dynamic, ExposeSecretMut};
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
// Test helper
// ---------------------------------------------------------------------------

/// Runs `f` under the ProxyAllocator gate for allocations of exactly `size` bytes.
///
/// This helper assumes checks are executed sequentially by a single aggregate test function.
fn with_proxy_check<F: FnOnce()>(size: usize, f: F) {
    TARGET_SIZE.store(size, Ordering::SeqCst);
    CHECKING.store(true, Ordering::SeqCst);
    f();
    CHECKING.store(false, Ordering::SeqCst);
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
        core::hint::black_box(&secret);
    }); // secret drops here → Dynamic::drop → zeroize → ProxyAllocator checks N bytes ✓
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
// ---------------------------------------------------------------------------

fn check_vec_zeroed(size: usize) {
    with_proxy_check(size, || {
        let mut secret: Dynamic<Vec<u8>> = Dynamic::new(Vec::with_capacity(size));
        secret.with_secret_mut(|v| {
            // Fill exactly N bytes so len == cap == N after shrink_to_fit.
            v.extend(std::iter::repeat_n(0xBBu8, size));
            // shrink_to_fit ensures the allocator sees exactly N bytes on dealloc.
            v.shrink_to_fit();
        });
        core::hint::black_box(&secret);
    }); // drop → Vec::zeroize (backing buf zeroed) → backing buf dealloc ← ProxyAllocator checks ✓
}

/// Verifies both `Dynamic<[u8; N]>` and `Dynamic<Vec<u8>>` zeroize heap memory
/// before deallocation across all supported sizes.
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

    // Dynamic<Vec<u8>> — backing buffers
    check_vec_zeroed(16);
    check_vec_zeroed(32);
    check_vec_zeroed(64);
    check_vec_zeroed(128);
}
