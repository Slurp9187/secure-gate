//! Allocator instrument, in the style of `secure-gate/tests/lifecycle_trace_heap.rs`.
//!
//! Deliberately a sibling of that file rather than an import: a `#[global_allocator]` is
//! per-binary, and `realloc` / `alloc_zeroed` are NOT overridden for exactly the reason that file
//! documents — the default `realloc` is alloc + copy + dealloc, so a `Vec`/`String` capacity change
//! routes the abandoned buffer through `dealloc`, where its bytes can be read. That forces the
//! worst case (a moving growth) rather than observing the typical one.
//!
//! Three modes, all process-global, all exercised from a single aggregate `#[test]`:
//!
//! * **watch mode** — one exact address; records whether it was freed inside the window, how many
//!   bytes were inspected, and how many were still non-zero at release. Never panics in `dealloc`.
//! * **census mode** — records EVERY release inside the window (pointer, size, non-zero count,
//!   longest run of the payload byte). It is how the multi-block orphan cases (`split_off`,
//!   `Deserialize`) are counted, where no single address is the whole story.
//! * **counting mode** — allocations performed on the calling thread inside a closure.
//!
//! Neither mode allocates: every store is to a static atomic, and reading a freed block is a
//! `ptr::read`. Nothing here spawns a thread.

#![allow(dead_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Every byte of the payload is non-zero, so "was it wiped" and "was it ever written" can never be
/// confused, and a non-zero count in a freed block is a count of surviving secret bytes.
pub const PAYLOAD: u8 = 0xD7;
/// A second non-zero pattern for material appended after construction.
pub const TAIL: u8 = 0xE3;

/// A census entry only counts as "held the secret" if it contains at least this many consecutive
/// `PAYLOAD` bytes. Keeps the harness's own traffic out of the numbers without size matching.
pub const MIN_PAYLOAD_RUN: usize = 64;

// --------------------------------------------------------------------- watch mode

static WATCH_ACTIVE: AtomicBool = AtomicBool::new(false);
static WATCH_PTR: AtomicUsize = AtomicUsize::new(0);
static WATCH_HITS: AtomicUsize = AtomicUsize::new(0);
static WATCH_SIZE: AtomicUsize = AtomicUsize::new(0);
static WATCH_NONZERO: AtomicUsize = AtomicUsize::new(0);

// --------------------------------------------------------------------- census mode

const CENSUS_CAP: usize = 512;
static CENSUS_ACTIVE: AtomicBool = AtomicBool::new(false);
static CENSUS_LEN: AtomicUsize = AtomicUsize::new(0);
static CENSUS_OVERFLOW: AtomicUsize = AtomicUsize::new(0);
static CENSUS_SIZE: [AtomicUsize; CENSUS_CAP] = [const { AtomicUsize::new(0) }; CENSUS_CAP];
static CENSUS_NONZERO: [AtomicUsize; CENSUS_CAP] = [const { AtomicUsize::new(0) }; CENSUS_CAP];
static CENSUS_RUN: [AtomicUsize; CENSUS_CAP] = [const { AtomicUsize::new(0) }; CENSUS_CAP];

// --------------------------------------------------------------------- counting mode

static COUNTING: AtomicBool = AtomicBool::new(false);

thread_local! {
    static THREAD_COUNTING: Cell<bool> = const { Cell::new(false) };
    static THREAD_ALLOC_COUNT: Cell<usize> = const { Cell::new(0) };
}

struct ProxyAllocator;

unsafe impl GlobalAlloc for ProxyAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::SeqCst) && THREAD_COUNTING.with(Cell::get) {
            THREAD_ALLOC_COUNT.with(|c| c.set(c.get() + 1));
        }
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if WATCH_ACTIVE.load(Ordering::SeqCst) && ptr as usize == WATCH_PTR.load(Ordering::SeqCst) {
            let mut nonzero = 0usize;
            for i in 0..layout.size() {
                if core::ptr::read(ptr.add(i)) != 0 {
                    nonzero += 1;
                }
            }
            WATCH_SIZE.store(layout.size(), Ordering::SeqCst);
            WATCH_NONZERO.store(nonzero, Ordering::SeqCst);
            WATCH_HITS.fetch_add(1, Ordering::SeqCst);
            WATCH_ACTIVE.store(false, Ordering::SeqCst);
        }

        if CENSUS_ACTIVE.load(Ordering::SeqCst) {
            let mut nonzero = 0usize;
            let mut run = 0usize;
            let mut best = 0usize;
            for i in 0..layout.size() {
                let b = core::ptr::read(ptr.add(i));
                if b != 0 {
                    nonzero += 1;
                }
                if b == PAYLOAD {
                    run += 1;
                    if run > best {
                        best = run;
                    }
                } else {
                    run = 0;
                }
            }
            let idx = CENSUS_LEN.fetch_add(1, Ordering::SeqCst);
            if idx < CENSUS_CAP {
                CENSUS_SIZE[idx].store(layout.size(), Ordering::SeqCst);
                CENSUS_NONZERO[idx].store(nonzero, Ordering::SeqCst);
                CENSUS_RUN[idx].store(best, Ordering::SeqCst);
            } else {
                CENSUS_OVERFLOW.fetch_add(1, Ordering::SeqCst);
            }
        }

        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static PROXY: ProxyAllocator = ProxyAllocator;

// --------------------------------------------------------------------- windows

/// What the allocator observed about one watched heap block.
#[derive(Debug, Clone, Copy)]
pub struct Witness {
    /// Whether the block was released inside the window at all.
    pub freed: bool,
    /// `layout.size()` at release — how many bytes were inspected.
    pub size: usize,
    /// How many of those bytes were still non-zero at release.
    pub nonzero: usize,
}

struct WatchGuard;
impl Drop for WatchGuard {
    fn drop(&mut self) {
        WATCH_ACTIVE.store(false, Ordering::SeqCst);
    }
}

/// Runs `f` while watching one exact heap address. `ptr` must be live at the call.
pub fn watch_block<F: FnOnce()>(ptr: *const u8, f: F) -> Witness {
    assert!(
        !ptr.is_null(),
        "watch_block needs the address of a live allocation"
    );
    WATCH_HITS.store(0, Ordering::SeqCst);
    WATCH_SIZE.store(0, Ordering::SeqCst);
    WATCH_NONZERO.store(0, Ordering::SeqCst);
    WATCH_PTR.store(ptr as usize, Ordering::SeqCst);
    WATCH_ACTIVE.store(true, Ordering::SeqCst);
    let _g = WatchGuard;
    f();
    Witness {
        freed: WATCH_HITS.load(Ordering::SeqCst) > 0,
        size: WATCH_SIZE.load(Ordering::SeqCst),
        nonzero: WATCH_NONZERO.load(Ordering::SeqCst),
    }
}

/// One released block, as the census saw it.
#[derive(Debug, Clone, Copy)]
pub struct Released {
    pub size: usize,
    pub nonzero: usize,
    /// Longest run of consecutive `PAYLOAD` bytes found in the block.
    pub payload_run: usize,
}

struct CensusGuard;
impl Drop for CensusGuard {
    fn drop(&mut self) {
        CENSUS_ACTIVE.store(false, Ordering::SeqCst);
    }
}

/// Runs `f` and returns every block released during it that held at least `MIN_PAYLOAD_RUN`
/// consecutive payload bytes. Allocating in the caller's own collecting code is fine: the vector is
/// built after the window closes.
pub fn census<F: FnOnce()>(f: F) -> Vec<Released> {
    CENSUS_LEN.store(0, Ordering::SeqCst);
    CENSUS_OVERFLOW.store(0, Ordering::SeqCst);
    CENSUS_ACTIVE.store(true, Ordering::SeqCst);
    let _g = CensusGuard;
    f();
    CENSUS_ACTIVE.store(false, Ordering::SeqCst);
    let n = CENSUS_LEN.load(Ordering::SeqCst).min(CENSUS_CAP);
    assert_eq!(
        CENSUS_OVERFLOW.load(Ordering::SeqCst),
        0,
        "census table overflowed; the numbers below would be an undercount"
    );
    (0..n)
        .map(|i| Released {
            size: CENSUS_SIZE[i].load(Ordering::SeqCst),
            nonzero: CENSUS_NONZERO[i].load(Ordering::SeqCst),
            payload_run: CENSUS_RUN[i].load(Ordering::SeqCst),
        })
        .filter(|r| r.payload_run >= MIN_PAYLOAD_RUN)
        .collect()
}

struct CountGuard;
impl Drop for CountGuard {
    fn drop(&mut self) {
        THREAD_COUNTING.with(|c| c.set(false));
        COUNTING.store(false, Ordering::SeqCst);
    }
}

/// Allocations performed by the calling thread inside `f`. Do not nest; do not spawn.
pub fn count_allocs<F: FnOnce()>(f: F) -> usize {
    THREAD_ALLOC_COUNT.with(|c| c.set(0));
    THREAD_COUNTING.with(|c| c.set(true));
    COUNTING.store(true, Ordering::SeqCst);
    let _g = CountGuard;
    f();
    THREAD_ALLOC_COUNT.with(Cell::get)
}

/// Total payload bytes still resident across a census result.
pub fn total_nonzero(rs: &[Released]) -> usize {
    rs.iter().map(|r| r.nonzero).sum()
}
