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
//! bookkeeping. A `Mutex` serializes tests so that `TARGET_SIZE` is stable for the duration
//! of each test (cargo test runs tests in parallel by default).

#![cfg(all(feature = "alloc", not(miri)))]
#![allow(clippy::undocumented_unsafe_blocks)]

use secure_gate::{Dynamic, ExposeSecretMut};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// Assertion gate — active only while a test holds the lock
// ---------------------------------------------------------------------------

/// Set to `true` only while the active test's closure is executing.
static CHECKING: AtomicBool = AtomicBool::new(false);

/// The exact byte count of the heap allocation currently under scrutiny.
/// Protected by `LOCK` — only written while the mutex is held, before `CHECKING` is set.
static TARGET_SIZE: AtomicUsize = AtomicUsize::new(0);

/// Serializes tests so that `TARGET_SIZE` + `CHECKING` form a coherent pair.
///
/// `cargo test` runs tests in the same binary in parallel across multiple threads.
/// Without this lock, two tests could race on `TARGET_SIZE`, causing the ProxyAllocator
/// to check the wrong size (false positive) or silently skip the check (false negative).
static LOCK: Mutex<()> = Mutex::new(());

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
/// Acquires `LOCK` to prevent concurrent tests from racing on `TARGET_SIZE`.
/// Sets `TARGET_SIZE = size` and `CHECKING = true` before invoking `f`, then
/// clears `CHECKING` after `f` returns (i.e. after the secret has dropped).
fn with_proxy_check<F: FnOnce()>(size: usize, f: F) {
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
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

/// Generates a test that verifies `Dynamic<[u8; N]>` zeroes its `N`-byte heap
/// allocation before the backing memory is freed.
macro_rules! heap_array_zeroed_test {
    ($name:ident, $n:expr) => {
        #[test]
        fn $name() {
            with_proxy_check($n, || {
                let secret: Dynamic<[u8; $n]> = Dynamic::new([0xAAu8; $n]);
                core::hint::black_box(&secret);
            }); // secret drops here → Dynamic::drop → zeroize → ProxyAllocator checks N bytes ✓
        }
    };
}

heap_array_zeroed_test!(dynamic_heap_zeroed_before_dealloc_16, 16);
heap_array_zeroed_test!(dynamic_heap_zeroed_before_dealloc_32, 32);
heap_array_zeroed_test!(dynamic_heap_zeroed_before_dealloc_64, 64);
heap_array_zeroed_test!(dynamic_heap_zeroed_before_dealloc_128, 128);

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

/// Generates a test that verifies the `N`-byte backing buffer of a `Dynamic<Vec<u8>>`
/// is fully zeroed before it is freed by the allocator.
macro_rules! heap_vec_zeroed_test {
    ($name:ident, $n:expr) => {
        #[test]
        fn $name() {
            with_proxy_check($n, || {
                let mut secret: Dynamic<Vec<u8>> = Dynamic::new(Vec::with_capacity($n));
                secret.with_secret_mut(|v| {
                    // Fill exactly N bytes so len == cap == N after shrink_to_fit.
                    v.extend(core::iter::repeat(0xBBu8).take($n));
                    // shrink_to_fit ensures the allocator sees exactly N bytes on dealloc.
                    v.shrink_to_fit();
                });
                core::hint::black_box(&secret);
            }); // drop → Vec::zeroize (backing buf zeroed) → backing buf dealloc ← ProxyAllocator checks ✓
        }
    };
}

heap_vec_zeroed_test!(dynamic_vec_heap_zeroed_16, 16);
heap_vec_zeroed_test!(dynamic_vec_heap_zeroed_32, 32);
heap_vec_zeroed_test!(dynamic_vec_heap_zeroed_64, 64);
heap_vec_zeroed_test!(dynamic_vec_heap_zeroed_128, 128);
