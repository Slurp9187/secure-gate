//! This crate's own workloads, so `residue_binary!` is exercised the way a consumer uses it:
//! one file per configuration, one invocation each, this module shared between them.
//!
//! Plain `Vec<u8>` shapes — the probe knows nothing about any particular program. What a
//! consumer's support module has to do is the same three things: plant the pattern, abandon
//! the buffer, and assert that the abandonment happened.

#![allow(dead_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use secure_gate_residue_probe::{plant, PATTERN};
use std::alloc::{GlobalAlloc, Layout};

/// Payload size of the buffer in both workloads.
pub const SECRET_LEN: usize = 4096;

/// **Growth-move** — grow one byte past capacity. The old block is abandoned with the
/// pattern still in it, and released through a `realloc` the spy routes into `dealloc`.
pub fn growth_move() {
    let mut buf = vec![0u8; SECRET_LEN];
    plant(&mut buf);
    let before = buf.as_ptr().addr();

    buf.push(PATTERN[0]);

    // If the buffer did not move there is no abandoned block, the pattern is never
    // released, and a clean count would report success for a run in which nothing
    // happened. Establish there was something to find before reporting that you did not
    // find it.
    assert_ne!(
        before,
        buf.as_ptr().addr(),
        "growth did not move the buffer, so no block was abandoned and this window measured \
         nothing"
    );
    std::hint::black_box(&buf);
}

/// **Truncate-then-shrink** — a capacity change that does not grow. The abandoned block
/// holds the live prefix *and* the discarded tail.
pub fn truncate_shrink() {
    let mut buf = vec![0u8; SECRET_LEN];
    plant(&mut buf);
    let before = buf.as_ptr().addr();

    buf.truncate(SECRET_LEN / 2);
    buf.shrink_to_fit();

    // `Vec::shrink_to_fit` is documented as *may* reduce the capacity. Require the move
    // rather than assuming it.
    assert_ne!(
        before,
        buf.as_ptr().addr(),
        "shrink_to_fit declined to reallocate, so no block was abandoned and this window \
         measured nothing"
    );
    std::hint::black_box(&buf);
}

/// Every workload, so the binaries stay identical apart from their allocator.
pub const WORKLOADS: [(&str, fn()); 2] = [
    ("growth-move", growth_move as fn()),
    ("truncate-then-shrink", truncate_shrink as fn()),
];

/// The smallest possible subject: zero every byte of a block, then forward.
///
/// Exists so this crate's own subject leg has a subject. It is not a recommendation of
/// anything and characterises nothing but itself. `realloc` is left to the `GlobalAlloc`
/// default for the reason `NoWipe` gives: a subject and its controls must release memory by
/// the same route.
pub struct WipeOnFree<A: GlobalAlloc>(pub A);

// SAFETY: every method forwards the caller's arguments unchanged; `dealloc` writes only
// within `layout.size()` of a block the caller is releasing, before the inner allocator has
// been told about it.
unsafe impl<A: GlobalAlloc> GlobalAlloc for WipeOnFree<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged; the caller upholds the contract.
        unsafe { self.0.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged; the caller upholds the contract.
        unsafe { self.0.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        for i in 0..layout.size() {
            // SAFETY: `ptr` is valid for writes of `layout.size()` bytes and `i < size`, so
            // `ptr.add(i)` is in bounds. Volatile so the wipe is not a dead store even at an
            // optimization level where the spy's volatile read would not be what keeps it.
            unsafe { ptr.add(i).write_volatile(0) };
        }
        // SAFETY: forwarded unchanged; `ptr` came from this allocator with `layout`, and the
        // loop above only wrote within it.
        unsafe { self.0.dealloc(ptr, layout) }
    }
}
