//! Heap lifecycle trace for `dynamic_newtype!` types: creation, mutation, destruction, hand-off.
//!
//! `tests/heap_zeroize.rs` does this for the bare `Dynamic<T>` wrappers. This file does it for the
//! *newtypes* the macro generates over them, and it follows the secret's bytes rather than the
//! API's return values: every check names the heap block that holds the payload and then asserts
//! what the allocator sees happen to that block — whether it is freed, how many bytes were
//! inspected, and how many of them were still non-zero at the moment of release.
//!
//! # Two spellings that look dated and are not
//!
//! This branch's MSRV is 1.70, so `std::iter::repeat(x).take(n)` stands in for
//! `std::iter::repeat_n` (stable 1.82) and an explicit `as *const T` cast stands in for
//! `std::ptr::from_ref` (stable 1.76); the one place that repeats a `&str` uses
//! `str::repeat`, which clippy's `manual_str_repeat` requires on this toolchain. All three
//! are what `main`'s copy of this file spells with the newer API; none changes what is
//! measured. Do not "modernize" them here — the MSRV job builds this file on 1.70.
//!
//! # Why this is a separate test binary
//!
//! It installs a `#[global_allocator]`, exactly as `heap_zeroize.rs` does, and for the same reason:
//! an allocator that reads freed memory must not be imposed on unrelated test binaries. The proxy
//! allocator below is therefore a deliberate sibling of that file's, not shared code — a global
//! allocator is per-binary, and the instrument is the thing under discussion here, so it is spelled
//! out rather than hidden behind an import.
//!
//! # The three modes, and the discipline each one demands
//!
//! * **Asserting mode** (`CHECKING` + `TARGET_SIZE`) panics inside `dealloc` when a block of
//!   exactly `TARGET_SIZE` bytes still holds a non-zero byte. It is process-global state, so it is
//!   only ever opened around a single drop. Sizes are chosen away from the harness's own traffic
//!   (1200 / 2400 / 3600 bytes), and every caller first asserts the buffer's capacity really is
//!   that size — otherwise `layout.size()` never matches and the check is silently skipped.
//! * **Watch mode** (`WATCH_*`) records, for one exact *pointer*, whether that block was released
//!   inside the window and how many of its bytes were non-zero at release. It never panics inside
//!   `dealloc`, so it is safe where asserting mode is not, and matching by pointer rather than by
//!   size makes it immune to same-size allocations from the harness. It is what turns "the old
//!   buffer is not wiped" from a caveat into a number.
//! * **Counting mode** (`COUNTING` + thread-local counter) reports how many allocations the calling
//!   thread performed inside a closure. It is how "nothing was copied" is observed: a constructor
//!   that moves a buffer allocates one block (the `Box` header), one that copies allocates two.
//!
//! **One aggregate `#[test]`.** `heap_zeroize.rs` records a real CI false positive caused by
//! splitting its checks into parallel test functions: asserting mode is global, and parallel
//! allocator activity interleaves with it. The same rule holds here, and watch mode needs it too —
//! its pointer slot is a single global. Counting mode additionally must not be nested or entered
//! from two threads at once; see `count_allocs`. Nothing in this file spawns a thread.
//!
//! # Why the size assertions do not print their own numbers
//!
//! A buffer's capacity is read through `with_secret`, so CodeQL's `rust/cleartext-logging` query
//! treats it as secret-derived, and an `assert_eq!` **format argument** is a logging sink for that
//! query. Interpolating the capacity into the failure message therefore raised a high-severity
//! alert at every one of these assertions. A capacity is a block size and not secret material, but
//! the interpolation was redundant anyway: `assert_eq!` prints both operands on failure, so the
//! numbers are still there. The messages say what a mismatch *means* instead, and the tainted value
//! stays an operand, which that query does not treat as a sink. Do not put a `with_secret`-derived
//! value back into a format string here.
//!
//! # What this instrument can and cannot see
//!
//! * It sees a buffer abandoned by a `Vec`/`String` capacity change **only because**
//!   `GlobalAlloc::realloc` is not overridden: the default implementation is alloc + copy + dealloc,
//!   so the old block passes through `dealloc` where its bytes can be counted. That choice is what
//!   makes the measurement possible, and it also *forces* the copying path — so these numbers are
//!   the worst case rather than the typical one. With the real system allocator and no instrument,
//!   growing a full 1008-byte buffer by 96 (the exact pair `check_growth_orphan_retains_secret_vec`
//!   uses) extends the chunk in place and abandons nothing; on a fragmented heap the same growth
//!   moves and the abandoned chunk holds the secret. A true in-place resize leaves **no** residue,
//!   because nothing is abandoned: the old bytes are inside the allocation the wrapper still owns
//!   and still wipes at drop. `check_growth_orphan_*` therefore asserts the block *was* freed
//!   before reading anything into its contents — not as a formality, but because the abandoned
//!   buffer it measures does not exist in every run of the same code outside this instrument.
//! * It sees only blocks this process frees. Bytes already copied into a core dump, into swap, or
//!   into a caller's own buffer are out of reach, and so is the stack.
//! * It reads a block after the owner has released it but before `System.dealloc` is told about it,
//!   so the bytes observed are exactly what the next allocation of that address would find.
//! * `layout.size()` is the whole allocation, so a `Vec`'s spare capacity is inspected along with
//!   its initialized prefix. Each check asserts the observed size against the buffer's capacity,
//!   which is how it proves nothing was inspected only in part.

#![cfg(all(feature = "alloc", not(miri)))]
#![allow(clippy::undocumented_unsafe_blocks)]

use secure_gate::{dynamic_newtype, Dynamic, RevealSecret, RevealSecretMut, SecretLen};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// The newtypes under trace
//
// Three shapes, because the macro generates three different front ends, and one
// with `derive: [WrapperAccess]` so the role hand-off (`from_wrapper` /
// `into_wrapper`) can be traced as well as the contents hand-off
// (`into_inner`). `WrapperAccess` is not combined with a directional token:
// it expands to both, and adding `FromWrapper` or `IntoWrapper` alongside it
// would define the same methods twice (E0592).
// ---------------------------------------------------------------------------

dynamic_newtype!(pub Pw, String, "A password-shaped secret traced through the String arm.");
dynamic_newtype!(pub Tok, Vec<u8>, "A token-shaped secret traced through the Vec<u8> arm.");
dynamic_newtype!(pub Wide, generic Vec<u32>, "A non-byte inner type traced through the generic arm.");
dynamic_newtype!(
    pub Shared,
    Vec<u8>,
    "A secret whose base wrapper is reachable in both directions, for hand-off traces.",
    derive: [WrapperAccess]
);

// Fill patterns. Every byte of every pattern is non-zero, so "was it wiped" and
// "was it ever written" can never be confused, and a count of non-zero bytes in
// a freed block is a count of surviving secret bytes.
const PAYLOAD: u8 = 0xD7;
const GROWTH_TAIL: u8 = 0xE3;
const OVERWRITE: u8 = 0x5A;
const WIDE_PAYLOAD: u32 = 0xD7D7_D7D7;

// ---------------------------------------------------------------------------
// Asserting-mode gate — active only while one drop under test is running
// ---------------------------------------------------------------------------

/// Set to `true` only while the active check's closure is executing.
static CHECKING: AtomicBool = AtomicBool::new(false);

/// The exact byte count of the heap allocation currently under scrutiny.
/// Written before `CHECKING` is enabled.
static TARGET_SIZE: AtomicUsize = AtomicUsize::new(0);

// ---------------------------------------------------------------------------
// Watch-mode gate — pointer-keyed recording, never panics in `dealloc`
//
// Asserting mode can only express "this must be zero". Most of the lifecycle
// questions here are quantitative ("how much of the abandoned buffer survived")
// or negative ("this block must NOT be freed yet"), and some of them are asked
// about memory that is expected to be dirty. Recording and asserting afterwards
// answers all three without ever panicking inside the allocator.
// ---------------------------------------------------------------------------

/// `true` while one watch window is open; cleared on the first matching release.
static WATCH_ACTIVE: AtomicBool = AtomicBool::new(false);

/// The exact address being watched. Pointer matching, not size matching, so
/// harness allocations of the same size cannot be mistaken for the subject.
static WATCH_PTR: AtomicUsize = AtomicUsize::new(0);

/// Number of matching releases observed (0 or 1 — the gate closes on the first).
static WATCH_HITS: AtomicUsize = AtomicUsize::new(0);

/// `layout.size()` of the matching release: how many bytes were inspected.
static WATCH_SIZE: AtomicUsize = AtomicUsize::new(0);

/// How many of those bytes were still non-zero when the block was released.
static WATCH_NONZERO: AtomicUsize = AtomicUsize::new(0);

// ---------------------------------------------------------------------------
// Counting mode — "was anything copied?" expressed as an allocation count
// ---------------------------------------------------------------------------

/// Coarse gate: `true` while any thread is inside `count_allocs`. Threads that are
/// not counting take one atomic load and never touch thread-local storage from
/// inside the allocator.
static COUNTING: AtomicBool = AtomicBool::new(false);

thread_local! {
    /// `true` only on the thread currently inside `count_allocs`.
    ///
    /// Thread-scoping keeps harness allocations from being charged to the closure under test. It
    /// introduces one fail-open edge: a thread spawned inside the closure starts at these
    /// const-initialized defaults, so its allocations go uncounted. Undercounting is the direction
    /// that hides a regression, which is why `count_allocs` forbids spawning and nesting. No
    /// closure in this file spawns a thread.
    ///
    /// Both cells are `const`-initialized `Copy` types with no destructor, so no TLS destructor is
    /// registered and nothing lazily-initialized can be observed being torn down from inside
    /// `alloc`. First touch is handled by ordering in `count_allocs`, not by any promise about
    /// `thread_local!`: both cells are written before the global gate goes up and cleared before it
    /// comes down, so by the time `alloc` can read TLS this thread's block already exists.
    static THREAD_COUNTING: Cell<bool> = const { Cell::new(false) };

    /// Allocations observed on this thread while `THREAD_COUNTING` was set.
    static THREAD_ALLOC_COUNT: Cell<usize> = const { Cell::new(0) };
}

// ---------------------------------------------------------------------------
// ProxyAllocator — sibling of the one in tests/heap_zeroize.rs
//
// `realloc` and `alloc_zeroed` are deliberately NOT overridden, and here that is
// load-bearing rather than incidental: the growth checks below need `Vec`'s own
// reallocation to route through `alloc` + `dealloc` so the abandoned buffer can be
// read. The cost is that a growth reads as one `alloc` rather than an in-place
// resize, which over-counts relative to `System.realloc` — the conservative
// direction for every "nothing was copied" assertion here, since it can invent an
// allocation but never erase one.
// ---------------------------------------------------------------------------

struct ProxyAllocator;

unsafe impl GlobalAlloc for ProxyAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::SeqCst) && THREAD_COUNTING.with(Cell::get) {
            THREAD_ALLOC_COUNT.with(|c| c.set(c.get() + 1));
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // Asserting mode: panics on a non-zero byte. Never reached during unwind, because the
        // gate is only ever open around a drop that is not expected to panic.
        if CHECKING.load(Ordering::SeqCst) && layout.size() == TARGET_SIZE.load(Ordering::SeqCst) {
            for i in 0..layout.size() {
                let b = unsafe { core::ptr::read(ptr.add(i)) };
                assert_eq!(b, 0, "byte at offset {i} was not zeroed before dealloc");
            }
        }

        // Watch mode: record the first release of the watched address and close the gate, so a
        // later allocation that happens to reuse the address cannot overwrite the record. Never
        // panics — safe to run during unwind, as the allocator contract requires.
        if WATCH_ACTIVE.load(Ordering::SeqCst) && ptr as usize == WATCH_PTR.load(Ordering::SeqCst) {
            let nonzero = (0..layout.size())
                .filter(|&i| unsafe { core::ptr::read(ptr.add(i)) } != 0)
                .count();
            WATCH_SIZE.store(layout.size(), Ordering::SeqCst);
            WATCH_NONZERO.store(nonzero, Ordering::SeqCst);
            WATCH_HITS.fetch_add(1, Ordering::SeqCst);
            WATCH_ACTIVE.store(false, Ordering::SeqCst);
        }

        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static PROXY: ProxyAllocator = ProxyAllocator;

// ---------------------------------------------------------------------------
// Window helpers
// ---------------------------------------------------------------------------

/// RAII guard clearing the asserting gate on return or unwind.
///
/// Without it, a panic inside the closure would leave `CHECKING` set during unwinding and every
/// later release of `TARGET_SIZE` bytes — including panic-formatting buffers — would be inspected,
/// turning one failure into a cascade.
struct CheckGuard;

impl Drop for CheckGuard {
    fn drop(&mut self) {
        CHECKING.store(false, Ordering::SeqCst);
    }
}

/// Runs `f` with asserting mode open for allocations of exactly `size` bytes.
///
/// Assumes checks run sequentially from the single aggregate test: asserting mode is
/// process-global.
fn with_proxy_check<F: FnOnce()>(size: usize, f: F) {
    TARGET_SIZE.store(size, Ordering::SeqCst);
    CHECKING.store(true, Ordering::SeqCst);
    let _guard = CheckGuard;
    f();
}

/// RAII guard closing the watch window on return or unwind.
struct WatchGuard;

impl Drop for WatchGuard {
    fn drop(&mut self) {
        WATCH_ACTIVE.store(false, Ordering::SeqCst);
    }
}

/// What the allocator observed about one watched heap block.
#[derive(Debug, Clone, Copy)]
struct Witness {
    /// Whether the block was released inside the window at all.
    freed: bool,
    /// `layout.size()` at release — how many bytes were inspected.
    size: usize,
    /// How many of those bytes were still non-zero at release.
    nonzero: usize,
}

/// Runs `f` while watching one exact heap address, and reports what happened to it.
///
/// `ptr` must be the address of a live allocation at the time of the call; the caller is asserting
/// about *that block*, so a dangling or null pointer would make the result meaningless. The window
/// closes on the first matching release, so `freed` is never more than one observation.
fn watch_block<F: FnOnce()>(ptr: *const u8, f: F) -> Witness {
    assert!(
        !ptr.is_null(),
        "watch_block needs the address of a live allocation"
    );
    WATCH_HITS.store(0, Ordering::SeqCst);
    WATCH_SIZE.store(0, Ordering::SeqCst);
    WATCH_NONZERO.store(0, Ordering::SeqCst);
    WATCH_PTR.store(ptr as usize, Ordering::SeqCst);
    WATCH_ACTIVE.store(true, Ordering::SeqCst);
    let _guard = WatchGuard;
    f();
    Witness {
        freed: WATCH_HITS.load(Ordering::SeqCst) > 0,
        size: WATCH_SIZE.load(Ordering::SeqCst),
        nonzero: WATCH_NONZERO.load(Ordering::SeqCst),
    }
}

/// RAII guard lowering the counting gates on return or unwind.
struct CountGuard;

impl Drop for CountGuard {
    fn drop(&mut self) {
        // Thread-local first: once the global gate is down, `alloc` stops reading TLS at all.
        THREAD_COUNTING.with(|c| c.set(false));
        COUNTING.store(false, Ordering::SeqCst);
    }
}

/// Runs `f` on the calling thread and returns how many heap allocations *that thread* performed.
///
/// Two ways to break it, both undercounting and therefore silent: do not nest it (an inner call
/// resets this thread's counter and its guard lowers both gates on the way out), and do not call it
/// from two threads at once (`COUNTING` is a flag, not a refcount). The single aggregate test is
/// what keeps both true. Keep closures free of `assert!`/`format!`, which allocate and would be
/// charged to the code under test.
fn count_allocs<F: FnOnce()>(f: F) -> usize {
    THREAD_ALLOC_COUNT.with(|c| c.set(0));
    THREAD_COUNTING.with(|c| c.set(true));
    COUNTING.store(true, Ordering::SeqCst);
    let _guard = CountGuard;
    f();
    // Read before `_guard` runs; neither `with` nor `get` allocates, so this cannot self-count.
    THREAD_ALLOC_COUNT.with(Cell::get)
}

// ---------------------------------------------------------------------------
// Construction helpers — exact-capacity payloads
//
// Every trace below needs `capacity == len`, so that `layout.size()` at release
// equals a number the test knows and a partial inspection cannot pass unnoticed.
// `reserve_exact` / `with_capacity` give that; each helper asserts it rather than
// assuming it, because an allocator is free to round up.
// ---------------------------------------------------------------------------

/// A `Tok` holding `size` bytes of `PAYLOAD` in a buffer of capacity exactly `size`.
fn exact_tok(size: usize) -> Tok {
    let tok = Tok::new_with(|v| {
        v.reserve_exact(size);
        v.extend(std::iter::repeat(PAYLOAD).take(size));
    });
    assert_eq!(
        tok.with_secret(Vec::capacity),
        size,
        "Tok buffer capacity is not exactly {size}; every size assertion below would be vacuous"
    );
    tok
}

/// A `Pw` holding `size` ASCII bytes in a buffer of capacity exactly `size`.
fn exact_pw(size: usize) -> Pw {
    let pw = Pw::new_with(|s| {
        s.reserve_exact(size);
        s.extend(std::iter::repeat('q').take(size));
    });
    assert_eq!(
        pw.with_secret(String::capacity),
        size,
        "Pw buffer capacity is not exactly {size}; every size assertion below would be vacuous"
    );
    pw
}

/// A `Wide` holding `elems` copies of `WIDE_PAYLOAD` in a buffer of capacity exactly `elems`.
fn exact_wide(elems: usize) -> Wide {
    let mut v: Vec<u32> = Vec::with_capacity(elems);
    v.extend(std::iter::repeat(WIDE_PAYLOAD).take(elems));
    assert_eq!(
        v.capacity(),
        elems,
        "Vec<u32> capacity is not exactly {elems}; every size assertion below would be vacuous"
    );
    Wide::new(v)
}

// ---------------------------------------------------------------------------
// 1. CREATION
// ---------------------------------------------------------------------------

/// Pins that `Pw::new(String)` moves the caller's buffer instead of copying it, and that the moved
/// buffer — not some later copy of it — is the one the wrapper wipes.
///
/// This matters because the move is what makes `new` safe to hand a secret that is already in
/// memory: a copying constructor would leave a second, unprotected buffer behind that no `Drop`
/// would ever reach. One allocation (the `Box<String>` header) is the documented cost; a second
/// would be the copy.
fn check_string_new_moves_callers_buffer(size: usize) {
    let mut source = String::with_capacity(size);
    source.extend(std::iter::repeat('q').take(size));
    assert_eq!(
        source.capacity(),
        size,
        "String::with_capacity over-allocated; the size assertions below would be vacuous"
    );
    let buffer = source.as_ptr();

    let mut pw = None;
    let allocs = count_allocs(|| pw = Some(Pw::new(source)));
    let pw = pw.expect("Pw::new returned");

    assert_eq!(
        allocs, 1,
        "Pw::new(String) performed {allocs} allocations; exactly one (the Box<String> header) \
         means the payload buffer was moved, more than one means it was copied"
    );
    assert_eq!(
        pw.expose_secret().as_ptr(),
        buffer,
        "the secret is in a different buffer than the one handed to Pw::new: it was copied, and \
         the original copy is unprotected"
    );
    assert_eq!(
        pw.len(),
        size,
        "SecretLen forwarding disagrees with the payload"
    );

    let w = watch_block(buffer, move || drop(pw));
    assert!(
        w.freed,
        "the moved-in buffer was never released: the wrapper's Drop did not reach it"
    );
    assert_eq!(
        w.size, size,
        "the allocator inspected {} bytes of a {size}-byte buffer",
        w.size
    );
    assert_eq!(
        w.nonzero, 0,
        "{} of {} bytes were still non-zero when the moved-in buffer was freed",
        w.nonzero, w.size
    );
}

/// Pins that the `&str` and `&[u8]` conversions copy into a fresh protected buffer, that the fresh
/// buffer is exactly the payload's length, and that the caller's original is left untouched.
///
/// The last part is the point: `From<&str>` protects a *copy*. Code that reads a password into a
/// `String` and then converts it has two buffers and only one of them is wiped, which is a real
/// footgun and is invisible to any test that only checks the wrapper.
fn check_str_and_slice_conversions_copy_then_wipe(size: usize) {
    let plaintext: String = "p".repeat(size);

    let mut pw = None;
    let allocs = count_allocs(|| pw = Some(Pw::from(plaintext.as_str())));
    let pw = pw.expect("Pw::from returned");
    assert_eq!(
        allocs, 2,
        "Pw::from(&str) performed {allocs} allocations; the documented shape is two — the copied \
         String buffer and the Box<String> header"
    );
    let copy = pw.expose_secret().as_ptr();
    assert_ne!(
        copy,
        plaintext.as_ptr(),
        "Pw::from(&str) did not copy; a borrowed buffer cannot be wiped by the wrapper"
    );
    assert_eq!(
        pw.with_secret(String::capacity),
        size,
        "the copy over-allocated, so the size assertion below would be vacuous"
    );

    let w = watch_block(copy, move || drop(pw));
    assert!(w.freed, "the copied buffer was never released");
    assert_eq!(w.size, size, "the allocator inspected {} bytes", w.size);
    assert_eq!(
        w.nonzero, 0,
        "{} of {} bytes were still non-zero when the copy was freed",
        w.nonzero, w.size
    );

    // The source is still the caller's problem. Measured, not assumed: wrapping a copy protects
    // the copy only, and the mitigation is to build into the wrapper (`new_with`) or to move the
    // owned value in (`new`).
    assert!(
        plaintext.bytes().all(|b| b == b'p'),
        "the conversion mutated the caller's string"
    );

    // `From<&[u8]>` on the Vec<u8> arm takes the same route, with the same count.
    let bytes = vec![PAYLOAD; size];
    let mut tok = None;
    let allocs = count_allocs(|| tok = Some(Tok::from(bytes.as_slice())));
    let tok = tok.expect("Tok::from returned");
    assert_eq!(
        allocs, 2,
        "Tok::from(&[u8]) performed {allocs} allocations; expected the copied Vec buffer plus the \
         Box<Vec<u8>> header"
    );
    let copy = tok.expose_secret().as_ptr();
    assert_ne!(copy, bytes.as_ptr(), "Tok::from(&[u8]) did not copy");
    let cap = tok.with_secret(Vec::capacity);
    let w = watch_block(copy, move || drop(tok));
    assert!(w.freed, "the copied byte buffer was never released");
    assert_eq!(
        w.size, cap,
        "the watched block's size is not the buffer's capacity, so this check covered only part \
         of the allocation"
    );
    assert_eq!(
        w.nonzero, 0,
        "{} of {} bytes were still non-zero when the copied byte buffer was freed",
        w.nonzero, w.size
    );
    assert!(
        bytes.iter().all(|&b| b == PAYLOAD),
        "the conversion mutated the caller's slice"
    );
}

/// Pins that `new_with` hands the closure's own buffer to the wrapper — the address the closure
/// wrote into is the address the wrapper later wipes, with no intervening copy.
///
/// `new_with` exists so that secret bytes are written once, into the buffer that will be protected.
/// If the construction swapped in a copy, the closure's buffer would be freed unwiped at exactly
/// the moment the wrapper was built, which is the failure this address comparison would catch.
fn check_new_with_keeps_the_closures_buffer(size: usize) {
    let mut written = 0usize;
    let tok = Tok::new_with(|v| {
        v.reserve_exact(size);
        v.extend(std::iter::repeat(PAYLOAD).take(size));
        written = v.as_ptr() as usize;
    });
    assert_eq!(
        tok.expose_secret().as_ptr() as usize,
        written,
        "Tok::new_with moved the secret into a different buffer than the closure filled"
    );
    let cap = tok.with_secret(Vec::capacity);
    let w = watch_block(written as *const u8, move || drop(tok));
    assert!(w.freed, "the closure's buffer was never released");
    assert_eq!(
        w.size, cap,
        "the watched block's size is not the buffer's capacity, so this check covered only part \
         of the allocation"
    );
    assert_eq!(w.nonzero, 0, "{} bytes survived the drop", w.nonzero);

    let mut written = 0usize;
    let pw = Pw::new_with(|s| {
        s.reserve_exact(size);
        s.extend(std::iter::repeat('q').take(size));
        written = s.as_ptr() as usize;
    });
    assert_eq!(
        pw.expose_secret().as_ptr() as usize,
        written,
        "Pw::new_with moved the secret into a different buffer than the closure filled"
    );
    let cap = pw.with_secret(String::capacity);
    let w = watch_block(written as *const u8, move || drop(pw));
    assert!(w.freed, "the closure's buffer was never released");
    assert_eq!(
        w.size, cap,
        "the watched block's size is not the buffer's capacity, so this check covered only part \
         of the allocation"
    );
    assert_eq!(w.nonzero, 0, "{} bytes survived the drop", w.nonzero);
}

/// Pins that `from_random` and `from_rng` generate straight into the buffer that will be protected:
/// two allocations, no third buffer, exact capacity, and a wipe at drop.
///
/// A generator that filled a scratch buffer and then copied it would leave the scratch copy
/// unprotected. The allocation count is the observable that separates the two implementations;
/// the returned length alone cannot.
#[cfg(feature = "rand")]
fn check_random_constructors_fill_the_protected_buffer(len: usize) {
    let mut tok = None;
    let allocs = count_allocs(|| tok = Some(Tok::from_random(len)));
    let tok = tok.expect("from_random returned");
    assert_eq!(
        allocs, 2,
        "Tok::from_random performed {allocs} allocations; expected two — the payload buffer and \
         the Box<Vec<u8>> header — so the generated bytes were never copied between buffers"
    );
    assert_eq!(tok.len(), len, "from_random returned the wrong length");
    assert_eq!(
        tok.with_secret(Vec::capacity),
        len,
        "from_random over-allocated; the size assertion below would be vacuous"
    );
    // Positive control: there is something to wipe. All-zero output of `len` random bytes has
    // probability 2^-8len, which for the sizes used here is not a coincidence worth planning for.
    assert!(
        tok.with_secret(|v: &Vec<u8>| v.iter().any(|&b| b != 0)),
        "from_random produced an all-zero buffer; the drop assertion below would prove nothing"
    );
    let buffer = tok.expose_secret().as_ptr();
    let w = watch_block(buffer, move || drop(tok));
    assert!(w.freed, "the random buffer was never released");
    assert_eq!(
        w.size, len,
        "the allocator inspected {} of {len} bytes",
        w.size
    );
    assert_eq!(
        w.nonzero, 0,
        "{} of {} random bytes were still non-zero when freed",
        w.nonzero, w.size
    );

    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::from_seed([7u8; 32]);
    let mut tok = None;
    let allocs = count_allocs(|| tok = Some(Tok::from_rng(len, &mut rng).expect("rng fill")));
    let tok = tok.expect("from_rng returned");
    assert_eq!(
        allocs, 2,
        "Tok::from_rng performed {allocs} allocations; expected the same two as from_random"
    );
    let buffer = tok.expose_secret().as_ptr();
    let w = watch_block(buffer, move || drop(tok));
    assert!(w.freed, "the from_rng buffer was never released");
    assert_eq!(w.nonzero, 0, "{} bytes survived the drop", w.nonzero);
}

/// Pins that a decode constructor's output buffer is wiped at drop across its whole capacity.
///
/// The decode constructors are the paths that materialize a secret from text the caller already
/// has, and they allocate the buffer themselves, so the caller cannot pre-size it. Watching by
/// pointer (rather than by size, as asserting mode must) is what makes this checkable without
/// forcing a `shrink_to_fit` the real call site would not perform: whatever capacity the decoder
/// chose, the observed `layout.size()` is asserted against it, so a partially-wiped buffer cannot
/// pass.
#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base32",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
fn check_decoded_buffer_wiped(path: &str, size: usize, decode: impl FnOnce() -> Tok) {
    let tok = decode();
    assert_eq!(tok.len(), size, "{path}: decoded to the wrong length");
    assert!(
        tok.with_secret(|v: &Vec<u8>| v.iter().all(|&b| b == PAYLOAD)),
        "{path}: decoded to the wrong bytes, so the wipe assertion would prove nothing"
    );
    let cap = tok.with_secret(Vec::capacity);
    let buffer = tok.expose_secret().as_ptr();
    let w = watch_block(buffer, move || drop(tok));
    assert!(w.freed, "{path}: the decoded buffer was never released");
    assert_eq!(
        w.size, cap,
        "{path}: the watched block's size is not the decoded buffer's capacity, so this check \
         covered only part of the allocation"
    );
    assert_eq!(
        w.nonzero, 0,
        "{path}: {} of {} bytes were still non-zero when the decoded buffer was freed",
        w.nonzero, w.size
    );
}

// ---------------------------------------------------------------------------
// 2. DESTRUCTION — asserting mode, one shape per call
//
// Watch mode already proves zeroization by counting non-zero bytes. Asserting
// mode is kept for these three because it checks every byte individually and
// names the offending offset, and because it is the oracle `heap_zeroize.rs`
// established for this property; running it against the newtypes is what shows
// the macro's forwarded `Drop` reaches the same memory as the bare wrapper's.
// ---------------------------------------------------------------------------

/// Pins that dropping a `dynamic_newtype!` over `Dynamic<String>` leaves its backing buffer fully
/// zeroed before the allocator is told about it.
///
/// The generated type has no `Drop` of its own; it relies on the wrapped `Dynamic`'s. That is the
/// property here: a newtype is not a place where zeroization can quietly go missing.
fn check_drop_wipes_string_newtype(size: usize) {
    let pw = exact_pw(size);
    assert!(
        pw.with_secret(|s: &String| s.bytes().all(|b| b != 0)),
        "the buffer was already zero before the drop under test"
    );
    with_proxy_check(size, move || {
        core::hint::black_box(&pw);
        drop(pw);
    });
}

/// Pins the same property for a newtype over `Dynamic<Vec<u8>>`.
fn check_drop_wipes_vec_newtype(size: usize) {
    let tok = exact_tok(size);
    assert!(
        tok.with_secret(|v: &Vec<u8>| v.iter().all(|&b| b != 0)),
        "the buffer was already zero before the drop under test"
    );
    with_proxy_check(size, move || {
        core::hint::black_box(&tok);
        drop(tok);
    });
}

/// Pins the same property for the `generic` arm over a non-byte inner type.
///
/// `Vec<u32>` reaches zeroization through `Zeroize for Vec<Z>` rather than through any byte-wise
/// path, and the generic arm forwards a smaller API (no `SecretLen`, no encoders). Neither
/// difference is allowed to cost the wipe, and the allocator is the only place that shows it: the
/// check targets `elems * 4` bytes, so a per-element wipe that missed padding or spare capacity
/// would fail here.
fn check_drop_wipes_generic_vec_newtype(elems: usize) {
    let bytes = elems * core::mem::size_of::<u32>();
    let wide = exact_wide(elems);
    assert_eq!(
        wide.with_secret(|v: &Vec<u32>| v.len()),
        elems,
        "the generic newtype did not hold the payload"
    );
    with_proxy_check(bytes, move || {
        core::hint::black_box(&wide);
        drop(wide);
    });
}

/// Pins what the `Box<String>` header allocation does and does not contain when it is freed.
///
/// `Dynamic<T>` is `Box<T>`, so dropping it releases two blocks: the payload buffer, which is
/// wiped, and the small header holding the `String`'s pointer/length/capacity fields, which is
/// not. This is correct — the header is metadata, not secret material — but it is worth measuring
/// rather than asserting by prose, because "the wrapper zeroizes everything it owns" is the kind of
/// claim that invites a reader to assume more than is true. What survives is an address and a
/// capacity; `String::zeroize` does clear the length field to zero.
fn check_box_header_is_metadata_not_payload(size: usize) {
    let pw = exact_pw(size);
    let header = (pw.expose_secret() as *const String).cast::<u8>();
    let w = watch_block(header, move || drop(pw));
    assert!(w.freed, "the Box<String> header was never released");
    assert_eq!(
        w.size,
        core::mem::size_of::<String>(),
        "the watched block is {} bytes, not the size of a String header",
        w.size
    );
    // Not a weakness, and deliberately not a "must be zero": the surviving bytes are the freed
    // buffer's address and its capacity. The payload itself is covered by the checks above.
    assert!(
        w.nonzero > 0,
        "the String header was fully zeroed; that is harmless, but it contradicts the reasoning in \
         this check and in tests/heap_zeroize.rs, so the comment there needs revisiting"
    );
}

// ---------------------------------------------------------------------------
// 3. MUTATION
// ---------------------------------------------------------------------------

/// Pins that capacity-stable mutation through both mutable tiers rewrites the same buffer — no
/// reallocation, no second buffer, and the one buffer wiped at drop.
///
/// This is the pattern SECURITY.md recommends as the mitigation for realloc residue, so it has to
/// be measured rather than assumed: if `with_secret_mut` or `expose_secret_mut` allocated, the
/// advice would be wrong. Zero allocations plus an unchanged address is the whole claim.
fn check_capacity_stable_mutation_stays_in_one_buffer(size: usize) {
    let mut tok = exact_tok(size);
    let buffer = tok.expose_secret().as_ptr();
    let cap = tok.with_secret(Vec::capacity);

    let scoped = count_allocs(|| {
        tok.with_secret_mut(|v: &mut Vec<u8>| {
            for b in v.iter_mut() {
                *b = OVERWRITE;
            }
        });
    });
    let direct = count_allocs(|| {
        let v = tok.expose_secret_mut();
        v[0] = PAYLOAD;
        v[size - 1] = PAYLOAD;
    });
    assert_eq!(
        (scoped, direct),
        (0, 0),
        "capacity-stable mutation allocated ({scoped} via with_secret_mut, {direct} via \
         expose_secret_mut); in-place mutation must not move the secret to a new buffer"
    );
    assert_eq!(
        tok.expose_secret().as_ptr(),
        buffer,
        "the secret changed address during an in-place mutation"
    );
    assert_eq!(
        tok.with_secret(Vec::capacity),
        cap,
        "capacity changed during an in-place mutation"
    );
    assert!(
        tok.with_secret(|v: &Vec<u8>| v[0] == PAYLOAD && v[1] == OVERWRITE),
        "the mutations did not land in the buffer"
    );

    let w = watch_block(buffer, move || drop(tok));
    assert!(w.freed, "the mutated buffer was never released");
    assert_eq!(
        w.size, cap,
        "the watched block's size is not the buffer's capacity, so this check covered only part \
         of the allocation"
    );
    assert_eq!(
        w.nonzero, 0,
        "{} of {} bytes survived the drop of a mutated buffer",
        w.nonzero, w.size
    );
}

/// Pins that a *shrinking* mutation leaves nothing recoverable: the abandoned tail stays inside the
/// same allocation and is wiped with it, spare capacity included.
///
/// `truncate` drops the length but not the bytes, so between the mutation and the drop the tail is
/// still in memory. What must hold is that the wipe covers the whole capacity rather than the
/// surviving prefix — the difference is invisible through the API and visible only here.
fn check_truncating_mutation_wipes_the_abandoned_tail(size: usize) {
    let mut tok = exact_tok(size);
    let buffer = tok.expose_secret().as_ptr();
    let cap = tok.with_secret(Vec::capacity);

    let allocs = count_allocs(|| tok.with_secret_mut(|v: &mut Vec<u8>| v.truncate(size / 2)));
    assert_eq!(allocs, 0, "truncate allocated {allocs} times");
    assert_eq!(tok.len(), size / 2, "truncate did not shorten the secret");
    assert_eq!(
        tok.expose_secret().as_ptr(),
        buffer,
        "truncate moved the secret to a new buffer"
    );
    assert_eq!(
        tok.with_secret(Vec::capacity),
        cap,
        "truncate released capacity; the tail would then be freed outside this window"
    );

    // Positive control, as in check_spare_capacity_wiped_string: the truncated tail is still the
    // payload at this point, so the wipe below has something to do.
    let dirty_tail = (size / 2..cap).all(|i| unsafe { core::ptr::read(buffer.add(i)) } == PAYLOAD);
    assert!(
        dirty_tail,
        "the truncated tail was not holding the payload before the drop"
    );
    let w = watch_block(buffer, move || drop(tok));
    assert!(w.freed, "the truncated buffer was never released");
    assert_eq!(
        w.size, cap,
        "the watched block's size is not the buffer's capacity, so the abandoned tail was not \
         part of the measurement"
    );
    assert_eq!(
        w.nonzero, 0,
        "{} of {} bytes survived, so the wipe did not cover the truncated tail or the spare \
         capacity",
        w.nonzero, w.size
    );
}

/// Pins that a `String`-shaped newtype's wipe covers spare capacity, not just the bytes the length
/// admits.
///
/// Both the wrapper and the macro promise "zeroize on drop including spare capacity". The API
/// cannot show the difference: an over-allocated buffer reports the same `len()` either way, and
/// the uninitialized tail is exactly where an earlier, longer value would still be sitting after a
/// shorter one replaced it. The allocator is the only witness — `layout.size()` is the whole
/// allocation, so asserting it against `capacity()` is what makes the tail part of the measurement.
fn check_spare_capacity_wiped_string(len: usize, capacity: usize) {
    assert!(
        capacity > len,
        "this check is only meaningful with spare capacity to wipe"
    );
    let pw = Pw::new_with(|s| {
        s.reserve_exact(capacity);
        // Write the full capacity first, then shorten, so the tail holds real bytes rather than
        // whatever the allocator handed back.
        s.extend(std::iter::repeat('q').take(capacity));
        s.truncate(len);
    });
    assert_eq!(pw.len(), len, "the payload is not the expected length");
    assert_eq!(
        pw.with_secret(String::capacity),
        capacity,
        "the buffer capacity is not exactly {capacity}; the size assertion below would be vacuous"
    );

    let buffer = pw.expose_secret().as_ptr();
    // Positive control: the tail really is dirty going into the drop, so `nonzero == 0` below is a
    // measurement of the wipe rather than of memory that was never written. Reading `len`..`capacity`
    // is reading initialized bytes inside a live allocation the test wrote itself; no reference to
    // the String is alive across the read.
    let dirty_tail = (len..capacity).all(|i| unsafe { core::ptr::read(buffer.add(i)) } == b'q');
    assert!(
        dirty_tail,
        "the spare capacity was not holding the payload before the drop; this check would pass \
         against a wipe that ignored it"
    );
    let w = watch_block(buffer, move || drop(pw));
    assert!(w.freed, "the buffer was never released");
    assert_eq!(
        w.size, capacity,
        "the allocator inspected {} bytes of a {capacity}-byte allocation",
        w.size
    );
    assert_eq!(
        w.nonzero, 0,
        "{} of {} bytes survived, so the wipe stopped short of the spare capacity",
        w.nonzero, w.size
    );
}

/// Pins the documented realloc-residue weakness as a measured number: growing a live secret past
/// its capacity through `with_secret_mut` frees the old buffer with the secret still in it.
///
/// `SECURITY.md` § "Heap-reallocation residue" (and the same caveat on `Dynamic`'s module docs)
/// states that `with_secret_mut` / `expose_secret_mut` growth reallocates outside this crate's
/// control and "remains a real limitation". This check turns that sentence into an assertion: the
/// abandoned buffer IS released, and EVERY one of its bytes is still the payload when it is. The
/// mitigation is the one the docs give — pre-size the buffer before wrapping and keep mutations
/// capacity-stable (see `check_capacity_stable_mutation_stays_in_one_buffer`), replace the whole
/// wrapper instead of growing it, or install a zero-on-free global allocator in the final binary.
///
/// Should this ever fail with `nonzero == 0`, the crate has started wiping the orphan and the
/// documented caveat has gone stale — that is a documentation bug in the other direction and should
/// be reported, not accommodated. The `freed` assertion comes first for a related reason: if a
/// future allocator resized in place, the residue would still exist but this instrument could no
/// longer see it, and a silent zero would be the wrong conclusion to draw.
fn check_growth_orphan_retains_secret_vec(initial: usize, extra: usize) {
    let mut tok = exact_tok(initial);
    let old = tok.expose_secret().as_ptr();
    let tail = vec![GROWTH_TAIL; extra];

    let w = watch_block(old, || {
        tok.with_secret_mut(|v: &mut Vec<u8>| v.extend_from_slice(&tail));
    });

    assert!(
        w.freed,
        "the pre-growth buffer was not released during growth: the allocation was resized in \
         place, so its residue is real but invisible to this instrument"
    );
    assert_eq!(
        w.size, initial,
        "the allocator inspected {} bytes of the {initial}-byte orphan",
        w.size
    );
    assert_eq!(
        w.nonzero, initial,
        "{} of {initial} secret bytes were left in the freed buffer; the documented weakness says \
         all {initial} are, so this measurement no longer matches the documentation",
        w.nonzero
    );
    let new = tok.expose_secret().as_ptr();
    assert_ne!(
        new, old,
        "growth did not move the buffer, so nothing was orphaned"
    );

    // The *current* buffer is still protected; the weakness is confined to the abandoned one.
    let cap = tok.with_secret(Vec::capacity);
    let w = watch_block(new, move || drop(tok));
    assert!(w.freed, "the grown buffer was never released");
    assert_eq!(
        w.size, cap,
        "the watched block's size is not the buffer's capacity, so this check covered only part \
         of the allocation"
    );
    assert_eq!(
        w.nonzero, 0,
        "{} of {} bytes survived the drop of the grown buffer",
        w.nonzero, w.size
    );
}

/// The same measurement for the other mutable tier: growth through `expose_secret_mut` abandons the
/// buffer with the secret in it too.
///
/// `SECURITY.md` names both `with_secret_mut` and `expose_secret_mut` in the caveat, and the two go
/// through different code in the generated newtype — one forwards a closure, the other hands out a
/// long-lived `&mut Vec<u8>`. Pinning only the scoped tier would leave the escape hatch, the one the
/// docs ask callers to audit most closely, unmeasured.
fn check_growth_orphan_via_expose_secret_mut(initial: usize, extra: usize) {
    let mut tok = exact_tok(initial);
    let old = tok.expose_secret().as_ptr();
    let tail = vec![GROWTH_TAIL; extra];

    let w = watch_block(old, || {
        tok.expose_secret_mut().extend_from_slice(&tail);
    });

    assert!(
        w.freed,
        "the pre-growth buffer was not released during growth through expose_secret_mut: resized \
         in place, residue invisible to this instrument"
    );
    assert_eq!(
        w.nonzero, initial,
        "{} of {initial} secret bytes were left in the buffer abandoned through expose_secret_mut; \
         the documented weakness says all {initial} are",
        w.nonzero
    );

    let cap = tok.with_secret(Vec::capacity);
    let new = tok.expose_secret().as_ptr();
    let w = watch_block(new, move || drop(tok));
    assert!(w.freed, "the grown buffer was never released");
    assert_eq!(
        w.size, cap,
        "the watched block's size is not the buffer's capacity, so this check covered only part \
         of the allocation"
    );
    assert_eq!(w.nonzero, 0, "{} bytes survived the drop", w.nonzero);
}

/// The same measurement for `Dynamic<String>` growth via `push_str`.
///
/// `String` is the shape most likely to be grown by accident — appending to a password or token
/// string reads as harmless — so the residue is measured separately rather than inferred from the
/// `Vec<u8>` case.
fn check_growth_orphan_retains_secret_string(initial: usize, extra: usize) {
    let mut pw = exact_pw(initial);
    let old = pw.expose_secret().as_ptr();
    let tail: String = "z".repeat(extra);

    let w = watch_block(old, || {
        pw.with_secret_mut(|s: &mut String| s.push_str(&tail));
    });

    assert!(
        w.freed,
        "the pre-growth String buffer was not released during growth: resized in place, residue \
         invisible to this instrument"
    );
    assert_eq!(w.size, initial, "the allocator inspected {} bytes", w.size);
    assert_eq!(
        w.nonzero, initial,
        "{} of {initial} secret bytes were left in the freed String buffer; the documented \
         weakness says all {initial} are",
        w.nonzero
    );

    let new = pw.expose_secret().as_ptr();
    assert_ne!(new, old, "growth did not move the String buffer");
    let cap = pw.with_secret(String::capacity);
    let w = watch_block(new, move || drop(pw));
    assert!(w.freed, "the grown String buffer was never released");
    assert_eq!(
        w.size, cap,
        "the watched block's size is not the buffer's capacity, so this check covered only part \
         of the allocation"
    );
    assert_eq!(w.nonzero, 0, "{} bytes survived the drop", w.nonzero);
}

/// The same measurement for the `generic` arm, where the residue is counted in elements.
///
/// Nothing about the generic arm changes the outcome — it is the inner collection that
/// reallocates, not the wrapper — and that is the point worth pinning: opting into the reduced API
/// does not opt out of the realloc caveat, even though the generic arm's documentation describes
/// only what it omits.
fn check_growth_orphan_retains_secret_generic(initial_elems: usize, extra_elems: usize) {
    let initial_bytes = initial_elems * core::mem::size_of::<u32>();
    let mut wide = exact_wide(initial_elems);
    let old = wide.with_secret(|v: &Vec<u32>| v.as_ptr()).cast::<u8>();
    let tail = vec![WIDE_PAYLOAD; extra_elems];

    let w = watch_block(old, || {
        wide.with_secret_mut(|v: &mut Vec<u32>| v.extend_from_slice(&tail));
    });

    assert!(
        w.freed,
        "the pre-growth Vec<u32> buffer was not released during growth: resized in place, residue \
         invisible to this instrument"
    );
    assert_eq!(
        w.size, initial_bytes,
        "the allocator inspected {} of {initial_bytes} bytes",
        w.size
    );
    assert_eq!(
        w.nonzero, initial_bytes,
        "{} of {initial_bytes} secret bytes were left in the freed buffer",
        w.nonzero
    );

    let new = wide.with_secret(|v: &Vec<u32>| v.as_ptr()).cast::<u8>();
    assert_ne!(new, old, "growth did not move the Vec<u32> buffer");
    let cap_bytes = wide.with_secret(|v: &Vec<u32>| v.capacity()) * core::mem::size_of::<u32>();
    let w = watch_block(new, move || drop(wide));
    assert!(w.freed, "the grown Vec<u32> buffer was never released");
    assert_eq!(
        w.size, cap_bytes,
        "the watched block's size is not the Vec<u32> buffer's capacity in bytes, so this check \
         covered only part of the allocation"
    );
    assert_eq!(w.nonzero, 0, "{} bytes survived the drop", w.nonzero);
}

/// Pins the contrast that makes the weakness above a choice rather than a fact of life: the same
/// newtype, grown past capacity through its forwarded `std::io::Write` impl, wipes the abandoned
/// buffer before releasing it.
///
/// `SECURITY.md` distinguishes growth the crate owns from growth the caller owns — `Write` on
/// `Dynamic<Vec<u8>>` allocates the larger buffer, copies, zeroizes the old one including its spare
/// capacity, and only then drops it, while `with_secret_mut` hands out a `&mut Vec<u8>` and cannot.
/// The newtype forwards that impl, so the guarantee has to survive the forwarding; measured here on
/// the generated type rather than inferred from the base wrapper's own regression test. Read with
/// `check_growth_orphan_retains_secret_vec`, the two results say that appending to a byte-shaped
/// secret through `Write` is the safe spelling of the same operation.
#[cfg(feature = "std")]
fn check_write_growth_wipes_the_orphan(initial: usize, extra: usize) {
    use std::io::Write;

    let mut tok = exact_tok(initial);
    let old = tok.expose_secret().as_ptr();
    let tail = vec![GROWTH_TAIL; extra];

    let w = watch_block(old, || {
        tok.write_all(&tail).expect("write into the newtype");
    });

    assert!(
        w.freed,
        "the pre-growth buffer was not released during a Write growth, so nothing can be said \
         about its contents"
    );
    assert_eq!(
        w.size, initial,
        "the allocator inspected {} bytes of the {initial}-byte orphan",
        w.size
    );
    assert_eq!(
        w.nonzero, 0,
        "{} of {initial} secret bytes were left in the buffer the Write path abandoned; that path \
         is documented to zeroize the outgoing allocation before releasing it",
        w.nonzero
    );
    let new = tok.expose_secret().as_ptr();
    assert_ne!(new, old, "the Write growth did not move the buffer");
    assert_eq!(
        tok.len(),
        initial + extra,
        "the Write growth lost or duplicated bytes"
    );

    let cap = tok.with_secret(Vec::capacity);
    let w = watch_block(new, move || drop(tok));
    assert!(w.freed, "the grown buffer was never released");
    assert_eq!(
        w.size, cap,
        "the watched block's size is not the buffer's capacity, so this check covered only part \
         of the allocation"
    );
    assert_eq!(w.nonzero, 0, "{} bytes survived the drop", w.nonzero);
}

// ---------------------------------------------------------------------------
// 4. HAND-OFF
// ---------------------------------------------------------------------------

/// Pins the whole `into_inner` hand-off at the allocator: the caller receives the original buffer
/// (nothing copied), the wrapper's `Drop` then wipes a sentinel instead of the secret, and the
/// plain value that comes back is where protection ends.
///
/// Three separate claims, each with its own observable. "Nothing is copied" is the returned
/// pointer matching the pre-call address plus a single allocation (the documented sentinel `Box`).
/// "The wrapper wipes a sentinel, not the secret" is the payload buffer *not* being released while
/// the wrapper drops. "Protection ends here" is the last measurement: the returned `Vec` has no
/// zeroize-on-drop, so its buffer is freed with every byte intact. That is documented behaviour,
/// not a leak — tier 3 of the access model hands ownership over — and the positive control at the
/// end shows protection can be resumed explicitly with `zeroize::Zeroizing`.
fn check_into_inner_moves_the_buffer_and_ends_protection(size: usize) {
    let tok = exact_tok(size);
    let buffer = tok.expose_secret().as_ptr();
    let cap = tok.with_secret(Vec::capacity);

    let mut out: Option<Vec<u8>> = None;
    let mut allocs = 0usize;
    let w = watch_block(buffer, || {
        // The wrapper is consumed here, so its Drop also runs inside this window.
        allocs = count_allocs(|| out = Some(tok.into_inner()));
    });
    let out = out.expect("into_inner returned");

    assert_eq!(
        allocs, 1,
        "into_inner performed {allocs} allocations; the documented cost is exactly one small \
         sentinel Box, and a second allocation would mean the payload was copied"
    );
    assert!(
        !w.freed,
        "the payload buffer was released during into_inner: the wrapper wiped and freed the secret \
         the caller was supposed to receive"
    );
    assert_eq!(
        out.as_ptr(),
        buffer,
        "into_inner returned a different buffer: the secret was copied, leaving an unprotected \
         original behind"
    );
    assert_eq!(
        out.capacity(),
        cap,
        "the returned Vec has a different capacity"
    );
    assert_eq!(out.len(), size, "the returned Vec has the wrong length");
    assert!(
        out.iter().all(|&b| b == PAYLOAD),
        "the caller received an altered or partially wiped secret"
    );

    // End of protection, pinned as such: an ordinary Vec, freed with the secret in it.
    let w = watch_block(buffer, move || drop(out));
    assert!(w.freed, "the moved-out buffer was never released");
    assert_eq!(
        w.nonzero,
        w.size,
        "{} of {} bytes were zeroed when the plain Vec dropped; into_inner is documented to hand \
         protection over to the caller, so a wipe here would mean the documentation understates \
         what the crate does",
        w.size - w.nonzero,
        w.size
    );

    // Positive control for the mitigation: the same plain value, wrapped in Zeroizing, is wiped.
    let resumed = exact_tok(size).into_inner();
    let buffer = resumed.as_ptr();
    let w = watch_block(buffer, move || drop(zeroize::Zeroizing::new(resumed)));
    assert!(w.freed, "the Zeroizing-wrapped buffer was never released");
    assert_eq!(
        w.nonzero, 0,
        "{} of {} bytes survived a Zeroizing drop, so the documented way to resume protection \
         after into_inner does not work",
        w.nonzero, w.size
    );
}

/// Pins that `into_wrapper` drops the label and nothing else: no allocation, the same payload
/// buffer at the same address, the same `Box` header, and the base wrapper still wiping it at drop.
///
/// The macro's documentation draws a hard line between a *label* drop (`into_wrapper`) and a
/// *protection* drop (`into_inner`), and says confusing the two is the main way the model gets
/// misread. At the allocator, the distinction is exactly this: `into_inner` costs a sentinel
/// allocation and ends the wipe, `into_wrapper` costs nothing and keeps it.
fn check_into_wrapper_drops_the_label_not_the_protection(size: usize) {
    let shared = Shared::new(vec![PAYLOAD; size]);
    let buffer = shared.expose_secret().as_ptr();
    let header = (shared.expose_secret() as *const Vec<u8>).cast::<u8>();

    let mut base: Option<Dynamic<Vec<u8>>> = None;
    let allocs = count_allocs(|| base = Some(shared.into_wrapper()));
    let base = base.expect("into_wrapper returned");

    assert_eq!(
        allocs, 0,
        "into_wrapper performed {allocs} allocations; dropping a #[repr(transparent)] label is a \
         move, not a rebuild"
    );
    assert_eq!(
        base.expose_secret().as_ptr(),
        buffer,
        "into_wrapper moved the payload to a new buffer"
    );
    assert_eq!(
        (base.expose_secret() as *const Vec<u8>).cast::<u8>(),
        header,
        "into_wrapper re-boxed the inner value; the label drop should not touch the Box"
    );

    let cap = base.with_secret(Vec::capacity);
    let w = watch_block(buffer, move || drop(base));
    assert!(w.freed, "the unlabelled buffer was never released");
    assert_eq!(
        w.size, cap,
        "the watched block's size is not the buffer's capacity, so this check covered only part \
         of the allocation"
    );
    assert_eq!(
        w.nonzero, 0,
        "{} of {} bytes survived: dropping the label cost the secret its wipe",
        w.nonzero, w.size
    );
}

/// Pins the inbound half of the same wall: `from_wrapper` relabels in place, and the borrowing
/// accessors reach the same buffer without moving or copying it.
///
/// `from_wrapper` is the direction the macro's documentation calls the relabelling path and warns
/// against on boundary-guarding types. Whatever the policy, the mechanics must be free and
/// lossless: a relabelling that reallocated would leave the pre-label buffer unwiped.
fn check_from_wrapper_relabels_in_place(size: usize) {
    let base: Dynamic<Vec<u8>> = Dynamic::new(vec![PAYLOAD; size]);
    let buffer = base.expose_secret().as_ptr();

    let mut shared: Option<Shared> = None;
    let allocs = count_allocs(|| shared = Some(Shared::from_wrapper(base)));
    let mut shared = shared.expect("from_wrapper returned");

    assert_eq!(
        allocs, 0,
        "from_wrapper performed {allocs} allocations; taking on a label is a move, not a rebuild"
    );
    assert_eq!(
        shared.expose_secret().as_ptr(),
        buffer,
        "from_wrapper moved the payload to a new buffer"
    );
    assert_eq!(
        shared.as_wrapper().expose_secret().as_ptr(),
        buffer,
        "as_wrapper borrows a different buffer than the newtype holds"
    );
    let allocs = count_allocs(|| {
        shared
            .as_wrapper_mut()
            .with_secret_mut(|v: &mut Vec<u8>| v[0] = OVERWRITE);
    });
    assert_eq!(
        allocs, 0,
        "a capacity-stable write through as_wrapper_mut allocated {allocs} times"
    );
    assert_eq!(
        shared.expose_secret().as_ptr(),
        buffer,
        "the write through as_wrapper_mut moved the buffer"
    );

    let cap = shared.with_secret(Vec::capacity);
    let w = watch_block(buffer, move || drop(shared));
    assert!(w.freed, "the relabelled buffer was never released");
    assert_eq!(
        w.size, cap,
        "the watched block's size is not the buffer's capacity, so this check covered only part \
         of the allocation"
    );
    assert_eq!(
        w.nonzero, 0,
        "{} of {} bytes survived: taking on a label cost the secret its wipe",
        w.nonzero, w.size
    );
}

// ---------------------------------------------------------------------------
// Aggregate test
// ---------------------------------------------------------------------------

/// Traces the heap lifecycle of `dynamic_newtype!` secrets end to end: every allocating
/// constructor, destruction for all three inner shapes, capacity-stable and capacity-growing
/// mutation, and both hand-off walls.
///
/// One aggregate test on purpose. Asserting mode (`CHECKING` + `TARGET_SIZE`) and watch mode
/// (`WATCH_*`) are both process-global, and `heap_zeroize.rs` records a CI false positive caused by
/// splitting such checks into parallel test functions. Sequential execution from a single test is
/// what keeps every window exclusive.
#[test]
fn newtype_heap_lifecycle_traced() {
    // --- 1. CREATION -------------------------------------------------------
    check_string_new_moves_callers_buffer(1040);
    check_str_and_slice_conversions_copy_then_wipe(1072);
    check_new_with_keeps_the_closures_buffer(1104);

    #[cfg(feature = "rand")]
    check_random_constructors_fill_the_protected_buffer(1136);

    // Decode constructors. Each encodes a known payload outside the watched window, then decodes
    // through the newtype's own constructor; the window covers only the resulting drop.
    #[cfg(feature = "encoding-hex")]
    {
        let hex: String = "d7".repeat(1168);
        check_decoded_buffer_wiped("hex", 1168, || Tok::try_from_hex(&hex).expect("valid hex"));
    }
    #[cfg(feature = "encoding-base32")]
    {
        use secure_gate::ToBase32;
        let encoded = vec![PAYLOAD; 1168].to_base32().into_inner();
        check_decoded_buffer_wiped("base32", 1168, || {
            Tok::try_from_base32(&encoded).expect("valid base32")
        });
    }
    #[cfg(feature = "encoding-base64")]
    {
        use secure_gate::ToBase64Url;
        let encoded = vec![PAYLOAD; 1168].to_base64url().into_inner();
        check_decoded_buffer_wiped("base64url", 1168, || {
            Tok::try_from_base64url(&encoded).expect("valid base64url")
        });
    }
    #[cfg(feature = "encoding-bech32")]
    {
        use secure_gate::{ToBech32, ToBech32m};
        // bech32's default code-length budget is smaller than the sizes above, so these two use a
        // payload that fits it; the property under test is indifferent to the length.
        let payload = vec![PAYLOAD; 48];
        let b32 = payload
            .try_to_bech32("trace", secure_gate::Case::Lower)
            .expect("valid hrp")
            .into_inner();
        check_decoded_buffer_wiped("bech32", 48, || {
            Tok::try_from_bech32(&b32, "trace").expect("valid bech32")
        });
        let b32m = payload
            .try_to_bech32m("tracem", secure_gate::Case::Lower)
            .expect("valid hrp")
            .into_inner();
        check_decoded_buffer_wiped("bech32m", 48, || {
            Tok::try_from_bech32m(&b32m, "tracem").expect("valid bech32m")
        });
    }

    // --- 2. DESTRUCTION ----------------------------------------------------
    // Asserting-mode sizes, kept clear of the harness's own small-allocation traffic and of each
    // other: 1200 bytes (String), 2400 bytes (Vec<u8>), 900 * 4 = 3600 bytes (Vec<u32>).
    check_drop_wipes_string_newtype(1200);
    check_drop_wipes_vec_newtype(2400);
    check_drop_wipes_generic_vec_newtype(900);
    check_box_header_is_metadata_not_payload(1200);
    check_spare_capacity_wiped_string(700, 1400);

    // --- 3. MUTATION -------------------------------------------------------
    check_capacity_stable_mutation_stays_in_one_buffer(1008);
    check_truncating_mutation_wipes_the_abandoned_tail(1008);
    check_growth_orphan_retains_secret_vec(1008, 96);
    check_growth_orphan_via_expose_secret_mut(1024, 96);
    check_growth_orphan_retains_secret_string(1040, 96);
    check_growth_orphan_retains_secret_generic(260, 24);
    // The same growth through the forwarded `Write` impl, which the crate does own.
    #[cfg(feature = "std")]
    check_write_growth_wipes_the_orphan(1008, 96);

    // --- 4. HAND-OFF -------------------------------------------------------
    check_into_inner_moves_the_buffer_and_ends_protection(1168);
    check_into_wrapper_drops_the_label_not_the_protection(1232);
    check_from_wrapper_relabels_in_place(1264);
}
