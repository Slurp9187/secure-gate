//! Heap-level zeroization verification for `Dynamic<T>`.
//!
//! Uses a `ProxyAllocator` (adapted from upstream `zeroize/tests/alloc.rs`) that intercepts
//! deallocations and asserts that the backing memory is fully zeroed before it is freed.
//!
//! This is a separate integration test binary so that `#[global_allocator]` does not interfere
//! with other test binaries. Do NOT merge this file into `zeroize_tests.rs`.
//!
//! Upstream `alloc.rs` checks a specific size unconditionally because their test binary is
//! minimal. Here we additionally gate on an `AtomicBool` to avoid false positives from the
//! test harness, which may allocate objects of the same size for internal bookkeeping.

#![cfg(feature = "alloc")]
#![allow(clippy::undocumented_unsafe_blocks)]

use secure_gate::Dynamic;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, Ordering};

// ---------------------------------------------------------------------------
// Assertion gate — true only while the test is active
// ---------------------------------------------------------------------------

static CHECKING: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// ProxyAllocator — adapted from upstream zeroize/tests/alloc.rs
// ---------------------------------------------------------------------------

/// The exact byte count of the heap allocation under test.
/// `Dynamic<[u8; 64]>` boxes a `[u8; 64]` → one 64-byte allocation.
const TARGET_SIZE: usize = 64;

/// A `GlobalAlloc` wrapper that asserts deallocated memory is fully zeroed
/// for allocations of exactly `TARGET_SIZE` bytes while `CHECKING` is active.
struct ProxyAllocator;

unsafe impl GlobalAlloc for ProxyAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if CHECKING.load(Ordering::SeqCst) && layout.size() == TARGET_SIZE {
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
// Test
// ---------------------------------------------------------------------------

/// Verifies that `Dynamic<[u8; 64]>` zeroes its heap allocation before freeing it.
///
/// `Dynamic<[u8; 64]>` boxes the array into a single `Box<[u8; 64]>` — exactly one
/// 64-byte heap allocation. When dropped, `Dynamic::drop` calls `zeroize()` which
/// zeroes all 64 bytes. The `ProxyAllocator` then confirms all bytes are 0 before
/// forwarding the deallocation to the system allocator.
///
/// `CHECKING` is set true immediately before the test and false immediately after
/// the secret drops, preventing the harness's own allocations from triggering spurious
/// assertion failures.
#[test]
fn dynamic_heap_zeroed_before_dealloc() {
    CHECKING.store(true, Ordering::SeqCst);
    {
        let secret: Dynamic<[u8; TARGET_SIZE]> = Dynamic::new([0xAAu8; TARGET_SIZE]);
        core::hint::black_box(&secret);
    } // `secret` drops here → Dynamic::drop → zeroize → ProxyAllocator assertion fires ✓
    CHECKING.store(false, Ordering::SeqCst);
}
