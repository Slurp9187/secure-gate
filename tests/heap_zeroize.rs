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
//! the *asserting* mode (`CHECKING` + `TARGET_SIZE`) is global process state, and parallel tests
//! can interleave allocator activity, causing false positives in CI.
//!
//! The *counting* mode is the exception: its counter is thread-local, so allocations made by the
//! libtest harness thread or any other thread are not attributed to the closure under test. That
//! removes a source of false failures; it is not a licence to parallelize -- an over-count made
//! `check_bech32_hrp_mismatch_materializes_nothing` fail once in CI against code that was
//! byte-identical to the passing runs.
//!
//! The panic-path positive-control test (`check_panic_path_bytes_zeroed`) uses a separate
//! recording mode (PANIC_CHECK_*) that records without asserting inside `dealloc`, then checks
//! after `catch_unwind` returns — safe because `dealloc` must never panic (allocator contract).
//! Size 8192 is used to avoid collision with small Rust panic-machinery allocations (message
//! formatting, backtrace, TLS) that may occur during unwind.
//!
//! The `PANIC_CHECK_*` name is now narrower than the mechanism it gates.
//! `check_try_new_with_err_zeroed_vec` and its `dynamic_newtype!` sibling use the same
//! recording mode on a path that never unwinds: the buffer is released by an ordinary early
//! return out of `try_new_with`. What the mode records is the fate of *one pinned pointer*,
//! whichever way its scope is left. The names are kept because the allocator hook and this
//! file's prose all refer to them, and a rename buys nothing that this paragraph does not.

// NOTE ON MIRI: the `not(miri)` gate below compiles this entire file away under `cargo miri
// test`, which `.github/workflows/miri.yml` is the only job to run. The gate is necessary --
// a `#[global_allocator]` that inspects freed memory is not something Miri can execute -- but it
// means the thread-local reasoning below is checked by review and by the suite passing on a real
// allocator, never by Miri. Weigh that when editing the TLS path.
#![cfg(all(feature = "alloc", not(miri)))]
#![allow(clippy::undocumented_unsafe_blocks)]

use secure_gate::{Dynamic, RevealSecretMut, dynamic_newtype};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// Asserting-mode gate — active only while one happy-path check is running
// ---------------------------------------------------------------------------

/// Set to `true` only while the active test's closure is executing.
static CHECKING: AtomicBool = AtomicBool::new(false);

/// The exact byte count of the heap allocation currently under scrutiny.
/// Written before `CHECKING` is enabled.
static TARGET_SIZE: AtomicUsize = AtomicUsize::new(0);

/// How many deallocations the asserting gate has inspected (and found zeroed) since
/// [`with_proxy_check_counted`] last reset it. Lets a check prove it was not vacuous where
/// the buffer under test has no `capacity()` to assert on from outside.
static CHECK_HITS: AtomicUsize = AtomicUsize::new(0);

// ---------------------------------------------------------------------------
// Recording-mode gate — used by the checks that follow one specific buffer to its grave
//
// Unlike the asserting mode, the recording mode never panics inside `dealloc`
// (which would be UB per the allocator contract). Instead it silently records
// whether the first matching deallocation was fully zeroed, then the test
// checks the result once the scope that owned the buffer has been left — by an
// unwind for the three panic checks, by an ordinary `?` for the two
// `try_new_with` error-path checks.
// ---------------------------------------------------------------------------

/// Set to `true` before entering the region under test — a `catch_unwind` for the panic
/// checks, a plain call for the `Err`-path ones; cleared by `dealloc` on first match.
static PANIC_CHECK_ACTIVE: AtomicBool = AtomicBool::new(false);

/// The exact backing-buffer pointer of the allocation being tracked in recording mode.
/// Matching by pointer rather than by size makes the test immune to same-size
/// allocations from panic machinery (backtrace, symbol resolution, TLS).
static PANIC_CHECK_PTR: AtomicUsize = AtomicUsize::new(0);

/// `true` iff the tracked allocation was fully zeroed when its dealloc was observed.
static PANIC_CHECK_ZEROED: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// Counting mode — used to prove a code path allocates nothing at all
// ---------------------------------------------------------------------------

/// Coarse gate: `true` while any thread is inside `count_allocs`.
///
/// This exists so that threads which are *not* counting take a single atomic load and never touch
/// thread-local storage from inside the global allocator. It says a count is in progress;
/// `THREAD_COUNTING` says whether it is *this* thread's.
static COUNTING: AtomicBool = AtomicBool::new(false);

thread_local! {
    /// `true` only on the thread currently inside `count_allocs`.
    ///
    /// The counter used to be a process-global `AtomicUsize`, which meant every allocation made by
    /// the libtest harness thread while the gate was open was charged to the closure under test.
    /// For a zero-allocation assertion that over-count is *fail-closed*, not fail-open: it cannot
    /// hide a real allocation, only invent one, so the failure mode is a spurious red rather than
    /// a silent pass. It still had to go. One CI run reported 4 allocations for an HRP mismatch
    /// whose decode path was byte-identical to four green runs, and an oracle that fails at random
    /// teaches people to re-run it until it is green, which retires it as surely as deleting it.
    ///
    /// Thread-scoping is what introduces a genuine *fail-open* edge, and it is the one the
    /// `count_allocs` docs guard: a thread spawned inside `f` starts at these const-initialized
    /// defaults, so its allocations are silently uncounted. Undercounting is the direction that
    /// hides a regression. Hence the prohibition there on spawning and on nesting.
    ///
    /// Both cells are `const`-initialized and hold `Copy` types with no destructor, so no TLS
    /// destructor is registered and there is no lazily-initialized state that could be observed
    /// torn down from inside `alloc`.
    ///
    /// First touch is a separate question, and the ordering in `count_allocs` is what settles it
    /// rather than any promise about `thread_local!`. On some targets the first access to a
    /// thread's TLS block does allocate -- Mach-O resolves `#[thread_local]` through
    /// `tlv_get_addr`, which materializes the block lazily. That is harmless here only because
    /// `count_allocs` writes both cells *before* raising the global `COUNTING` gate, and
    /// `CountGuard::drop` clears them *before* lowering it. By the time `alloc` can reach a TLS
    /// read, this thread's block already exists; and a thread that never counts never touches TLS
    /// from inside the allocator at all. Preserve that ordering if you edit either function.
    static THREAD_COUNTING: Cell<bool> = const { Cell::new(false) };

    /// Number of `alloc` calls observed on this thread while `THREAD_COUNTING` was set.
    static THREAD_ALLOC_COUNT: Cell<usize> = const { Cell::new(0) };
}

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

// `realloc` and `alloc_zeroed` are deliberately NOT overridden. Both `GlobalAlloc` defaults are
// written in terms of `self.alloc` / `self.dealloc`, so a resize still flows through the two
// hooks below and nothing escapes observation. The consequence for counting is that a growth
// reads as one `alloc` rather than as a native in-place resize -- an over-count relative to what
// `System.realloc` might do, which is the conservative direction for a zero-allocation assertion:
// it can add a phantom allocation, never erase a real one.
//
// No check in this file depends on that choice. `check_write_growth_orphan_zeroed` looks like it
// would -- it watches for the orphaned buffer released while a `Dynamic<Vec<u8>>` grows -- but
// the `Write` impl in src/dynamic.rs grows by hand (`Vec::with_capacity`, `extend_from_slice`,
// `zeroize` the old buffer, replace) rather than through `Vec`'s own reallocation, so the orphan
// is dropped explicitly and reaches `dealloc` either way. Measured, not assumed: instrumenting
// the asserting gate with a hit counter and forwarding `realloc` to `System.realloc` leaves the
// hit count at 1 per call, unchanged from the default.
//
// Revisit only if an assertion is added that needs "zero new heap blocks, including in-place
// resizes", or one that relies on `Vec`'s own growth path -- both are different properties from
// the ones measured here.
unsafe impl GlobalAlloc for ProxyAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Two gates: the global one keeps non-counting threads out of TLS entirely, the
        // thread-local one is what actually attributes the allocation.
        if COUNTING.load(Ordering::SeqCst) && THREAD_COUNTING.with(Cell::get) {
            THREAD_ALLOC_COUNT.with(|c| c.set(c.get() + 1));
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // Asserting mode: panic on non-zeroed bytes (never called during unwind)
        if CHECKING.load(Ordering::SeqCst) && layout.size() == TARGET_SIZE.load(Ordering::SeqCst) {
            for i in 0..layout.size() {
                let b = unsafe { core::ptr::read(ptr.add(i)) };
                assert_eq!(b, 0, "byte at offset {i} was not zeroed before dealloc");
            }
            CHECK_HITS.fetch_add(1, Ordering::SeqCst);
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

/// [`with_proxy_check`], and returns how many deallocations of exactly `size` bytes the
/// gate inspected. Every one of them was all-zero, or the allocator would have panicked.
///
/// For buffers whose size cannot be asserted from outside (an `EncodedSecret` exposes no
/// capacity; a sealed type's plaintext temporary is never visible at all). The existing
/// checks guard against a vacuous pass with `assert_eq!(capacity, size)`; these assert on
/// the returned count instead: zero means nothing of that size was freed and the check
/// observed nothing.
fn with_proxy_check_counted<F: FnOnce()>(size: usize, f: F) -> usize {
    CHECK_HITS.store(0, Ordering::SeqCst);
    with_proxy_check(size, f);
    CHECK_HITS.load(Ordering::SeqCst)
}

/// RAII guard that clears the counting gate on drop (normal return or unwind).
#[cfg(feature = "encoding-bech32")]
struct CountGuard;

#[cfg(feature = "encoding-bech32")]
impl Drop for CountGuard {
    fn drop(&mut self) {
        // Thread-local first: once the global gate is down, `alloc` stops reading TLS at all.
        THREAD_COUNTING.with(|c| c.set(false));
        COUNTING.store(false, Ordering::SeqCst);
    }
}

/// Runs `f` on the calling thread and returns how many heap allocations *that thread* performed.
///
/// Allocations made concurrently by the libtest harness or any other thread are not counted, so a
/// zero-allocation assertion cannot be broken by unrelated activity. The flip side, and the reason
/// `f` must stay single-threaded: allocations made by a thread `f` spawns are *also* not counted,
/// because that thread's cells start at their const-initialized defaults. That would undercount,
/// which is the direction that hides a regression. No closure here spawns a thread, and none
/// should be added.
///
/// Two ways to break it, both undercounting and therefore silent:
///
/// - **Do not nest.** An inner `count_allocs` resets this thread's counter to zero and its
///   `CountGuard` lowers both gates on the way out, so the outer call loses its tally and stops
///   counting for the rest of its closure.
/// - **Do not call it from two threads at once.** `COUNTING` is a plain flag, not a refcount;
///   whichever call finishes first lowers it and mutes the other.
///
/// The file's single aggregate test is what keeps both true today. The sequential-only caveat on
/// `with_proxy_check` is unaffected: asserting mode is still process-global.
#[cfg(feature = "encoding-bech32")]
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
// bech32 decode: the HRP is checked BEFORE the payload is materialized
//
// This is a claim about internal ordering, and adversarial review showed every
// existing test was black-box: swapping the two statements (materialize the Vec,
// then compare the HRP and discard it) left all of them passing, because the
// only observable was still `Err(UnexpectedHrp)`. Allocation count is the
// observable that distinguishes the two orderings: with the HRP compared first,
// a mismatch never allocates the payload `Vec`.
// ---------------------------------------------------------------------------

#[cfg(feature = "encoding-bech32")]
fn check_bech32_hrp_mismatch_materializes_nothing() {
    use secure_gate::{Bech32Error, Fixed, ToBech32, ToBech32m, bech32_code_length};

    const N: usize = bech32_code_length(3, 900);
    let secret = vec![0x5Au8; 900];
    let b32 = secret
        .try_to_bech32_sized::<N>("age", secure_gate::Case::Lower)
        .expect("encode")
        .into_inner();
    let b32m = secret
        .try_to_bech32m_sized::<N>("age", secure_gate::Case::Lower)
        .expect("encode")
        .into_inner();

    // Every HRP-checked decode path, sized, on both checksums and both surfaces.
    let wrong = count_allocs(|| {
        assert!(matches!(
            Dynamic::<Vec<u8>>::try_from_bech32_sized::<N>(&b32, "kem"),
            Err(Bech32Error::UnexpectedHrp)
        ));
        assert!(matches!(
            Dynamic::<Vec<u8>>::try_from_bech32m_sized::<N>(&b32m, "kem"),
            Err(Bech32Error::UnexpectedHrp)
        ));
        assert!(matches!(
            Fixed::<[u8; 900]>::try_from_bech32_sized::<N>(&b32, "kem"),
            Err(Bech32Error::UnexpectedHrp)
        ));
        assert!(matches!(
            Fixed::<[u8; 900]>::try_from_bech32m_sized::<N>(&b32m, "kem"),
            Err(Bech32Error::UnexpectedHrp)
        ));
    });
    assert_eq!(
        wrong, 0,
        "an HRP mismatch performed {wrong} heap allocation(s): \
         the payload was materialized before the HRP was compared"
    );

    // Positive control: a correct decode into a Dynamic must allocate, or the counter
    // above proved nothing.
    let right = count_allocs(|| {
        let d = Dynamic::<Vec<u8>>::try_from_bech32_sized::<N>(&b32, "age").expect("decode");
        core::hint::black_box(&d);
    });
    assert!(
        right >= 1,
        "positive control: a successful Dynamic decode must allocate"
    );

    // And Fixed decodes onto the stack: zero allocations even on success (the
    // no-alloc path is the same code on every target).
    let fixed_ok = count_allocs(|| {
        let f = Fixed::<[u8; 900]>::try_from_bech32_sized::<N>(&b32, "age").expect("decode");
        core::hint::black_box(&f);
    });
    assert_eq!(
        fixed_ok, 0,
        "Fixed::try_from_bech32_sized allocated {fixed_ok} time(s)"
    );
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
            v.extend(std::iter::repeat_n(0xBBu8, size));
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
// Dynamic<Vec<u8>> — REALLOC-ORPHAN test (growth of a *live* wrapper)
//
// Every other check in this file calls `shrink_to_fit` and only ever inspects
// the allocation that Drop releases. That leaves a blind spot: when a live
// wrapper grows, `Vec` reallocates, and the *previous* buffer is freed with the
// secret still in it. Drop later wipes the new buffer, so a drop-only oracle
// reports success while a copy of the secret has already been handed back to
// the allocator.
//
// The gate asserts on every dealloc of exactly `initial` bytes, so it observes
// the orphan at the moment `write` grows the buffer — before Drop runs at all.
//
// Note this only works because `ProxyAllocator` does not override
// `GlobalAlloc::realloc`: the default implementation is alloc + copy + dealloc,
// so the orphaned buffer passes through `dealloc` where it can be inspected.
// ---------------------------------------------------------------------------

/// Grows a live `Dynamic<Vec<u8>>` past its capacity via `std::io::Write` and
/// asserts the orphaned buffer was zeroized before being freed.
#[cfg(feature = "std")]
fn check_write_growth_orphan_zeroed(initial: usize) {
    use std::io::Write;

    let mut secret: Dynamic<Vec<u8>> = Dynamic::new({
        let mut v = Vec::with_capacity(initial);
        v.extend(std::iter::repeat_n(0xD7u8, initial));
        v.shrink_to_fit();
        assert_eq!(
            v.capacity(),
            initial,
            "allocator rounded up capacity — orphan check would be skipped"
        );
        v
    });

    with_proxy_check(initial, || {
        // Exceeds the remaining capacity (which is zero), forcing a grow.
        secret
            .write_all(&[0xE3u8; 64])
            .expect("write into Dynamic<Vec<u8>> failed");
        core::hint::black_box(&secret);
    });

    drop(secret);
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
            s.extend(std::iter::repeat_n('A', size));
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
// different decode path (hex, base32, base64url, bech32, bech32m) to confirm
// that all seven constructors using `from_protected_bytes` produce a correctly
// zeroized result on the happy path.
//
// The error path (invalid input) is covered separately, by `check_decode_rejected_zeroed`
// below.
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

#[cfg(feature = "encoding-base32")]
fn check_decode_base32_zeroed(data: &[u8]) {
    use secure_gate::ToBase32;
    let encoded = data.to_base32().into_inner();
    let mut secret = Dynamic::<Vec<u8>>::try_from_base32(&encoded).expect("valid base32");
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

#[cfg(feature = "encoding-base64")]
fn check_decode_base64_zeroed(data: &[u8]) {
    use secure_gate::ToBase64Url;
    let encoded = data.to_base64url().into_inner();
    let mut secret = Dynamic::<Vec<u8>>::try_from_base64url(&encoded).expect("valid base64url");
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
    let encoded = data
        .try_to_bech32("test", secure_gate::Case::Lower)
        .expect("valid hrp")
        .into_inner();
    let mut secret = Dynamic::<Vec<u8>>::try_from_bech32(&encoded, "test").expect("valid bech32");
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
fn check_decode_bech32m_zeroed(data: &[u8]) {
    use secure_gate::ToBech32m;
    let encoded = data
        .try_to_bech32m("testm", secure_gate::Case::Lower)
        .expect("valid hrp")
        .into_inner();
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
    let mut secret =
        Dynamic::<Vec<u8>>::deserialize_with_limit(&mut de, size).expect("within limit");
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
    let mut secret =
        Dynamic::<String>::deserialize_with_limit(&mut de, size).expect("within limit");
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
// Panic-path positive-control test
//
// Verifies that `Zeroizing::drop` actually zeroes the backing buffer when a
// panic fires while a `Zeroizing<Vec<u8>>` is in scope — the exact guarantee
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
    assert!(
        result.is_err(),
        "catch_unwind should have captured the panic"
    );
    assert!(
        PANIC_CHECK_ZEROED.load(Ordering::SeqCst),
        "Zeroizing must zero its backing buffer even when a panic fires before Box::new"
    );
}

// ---------------------------------------------------------------------------
// `Dynamic::<Vec<u8>>::new_with` closure-panic regression test
//
// Regression: prior to the Finding 1 fix, `new_with` constructed the
// intermediate buffer as a plain `Vec<u8>` and only wrapped it after the
// closure returned. A closure that wrote secret bytes and then panicked
// would leak those bytes — the plain `Vec` dropped during unwind without
// zeroization. After the fix, the intermediate buffer is `Zeroizing<Vec<u8>>`
// for the entire lifetime of the closure, so unwind triggers zeroize → dealloc.
//
// The 0.9.0-rc.12 signature change moved the allocation earlier without moving the
// protection. `new_with(len, f)` allocates and zeroes the slot *before* calling `f`, and
// `f` sees it as a `&mut [u8]` rather than as a `Vec` it fills itself — but the slot
// still lives inside one `Zeroizing<Vec<u8>>` for the whole call, so the property under
// test is word-for-word the one above. Only the pin changes shape, from `Vec::as_ptr` to
// the slot slice's `as_ptr`; both name the same address, and under the new signature that
// address cannot move mid-closure because there is no growth to reallocate it.
//
// Test shape mirrors `check_panic_path_bytes_zeroed`: poison-fill the slot,
// pin its backing-buffer pointer in `PANIC_CHECK_PTR`, then panic. The
// proxy allocator records whether the matching dealloc saw all-zero bytes.
// ---------------------------------------------------------------------------

fn check_new_with_panic_zeroed_vec(size: usize) {
    PANIC_CHECK_PTR.store(0, Ordering::SeqCst);
    PANIC_CHECK_ZEROED.store(false, Ordering::SeqCst);
    PANIC_CHECK_ACTIVE.store(true, Ordering::SeqCst);

    let result = std::panic::catch_unwind(|| {
        let _secret: Dynamic<Vec<u8>> = Dynamic::<Vec<u8>>::new_with(size, |slot: &mut [u8]| {
            // Poison every byte. The slot arrives all-zero by contract, so without this
            // the recorded dealloc would read as "clean" against a constructor that
            // protected nothing at all — the oracle needs something to have wiped.
            slot.fill(0xAAu8);
            // Pin the slot's own pointer before panicking. The slot *is* the wrapper's
            // storage here, so there is no second buffer to confuse it with.
            PANIC_CHECK_PTR.store(slot.as_ptr() as usize, Ordering::SeqCst);
            panic!("simulated closure failure after writing secret bytes");
        });
        // Unreachable: closure always panics. Reference the binding so the
        // optimizer cannot lift it out of the protected region.
        core::hint::black_box(&_secret);
    });

    PANIC_CHECK_ACTIVE.store(false, Ordering::SeqCst);
    assert!(
        result.is_err(),
        "catch_unwind should have captured the panic"
    );
    assert!(
        PANIC_CHECK_ZEROED.load(Ordering::SeqCst),
        "Dynamic::<Vec<u8>>::new_with must zero its slot on closure panic"
    );
}

// ---------------------------------------------------------------------------
// `Dynamic::<Vec<u8>>::try_new_with` — the partial write is wiped on `Err`
//
// This is a claim only the allocator proxy can settle. Every other route to the error
// path observes the same two facts from outside: `Err` came back, and no `Dynamic` was
// produced. Those hold just as well for a constructor that dropped a half-written secret
// un-wiped, because a freed buffer is not something a test can name afterwards — unless
// it watches the free itself, which is what this file exists to do.
//
// The claim is load-bearing rather than tidiness. Decoders that write into a
// caller-supplied buffer routinely leave real plaintext in it when they fail:
// `miniz_oxide`'s `decompress_slice_iter_to_slice` documents precisely that ("in that
// case the output buffer will still contain the partial decompression"). A constructor
// that wrapped only on success would therefore abandon a partial secret on every
// malformed input — and malformed input is the case an attacker picks.
//
// Shape mirrors the panic check above, minus the unwind: poison the slot, pin its
// pointer, return `Err`. `try_new_with`'s `?` drops the `Zeroizing` on the way out, so
// the recorded dealloc must see all zeros. Nothing panics here, so `catch_unwind` would
// only blur where a failure came from; the recording mode, matching by pointer, does not
// care which way the scope was left.
// ---------------------------------------------------------------------------

fn check_try_new_with_err_zeroed_vec(size: usize) {
    /// A caller's own error type, implementing nothing at all — not `Debug`, not `Error`.
    ///
    /// `E` being free is part of what `try_new_with` promises: a consumer returns their own
    /// error straight out of the closure. A bound added to `E` later would stop this file
    /// compiling, which is the cheapest alarm available for an API promise of that shape.
    struct CallerGaveUp;

    PANIC_CHECK_PTR.store(0, Ordering::SeqCst);
    PANIC_CHECK_ZEROED.store(false, Ordering::SeqCst);
    PANIC_CHECK_ACTIVE.store(true, Ordering::SeqCst);

    let result: Result<Dynamic<Vec<u8>>, CallerGaveUp> =
        Dynamic::<Vec<u8>>::try_new_with(size, |slot: &mut [u8]| {
            // A *partial* fill, because that is the realistic failure shape: the decoder
            // got some way in and then hit a bad byte. The tail stays at the slot's zeros,
            // so the only bytes this can catch are the ones the closure actually wrote —
            // which is exactly the leak being guarded against.
            slot[..size / 2].fill(0xC7u8);
            PANIC_CHECK_PTR.store(slot.as_ptr() as usize, Ordering::SeqCst);
            Err(CallerGaveUp)
        });

    PANIC_CHECK_ACTIVE.store(false, Ordering::SeqCst); // defensive cleanup
    assert!(
        result.is_err(),
        "the closure returned Err, so try_new_with must not have produced a Dynamic"
    );
    assert!(
        PANIC_CHECK_ZEROED.load(Ordering::SeqCst),
        "Dynamic::<Vec<u8>>::try_new_with must zero the partially written slot before \
         releasing it on the Err path"
    );
}

// ---------------------------------------------------------------------------
// `Dynamic::<Vec<u8>>::try_new_with` — the partial write is wiped on closure PANIC
//
// `try_new_with`'s rustdoc inherits `new_with`'s "# Panics" promise by declaring the two
// "identical in every respect but the closure's return type". In src/dynamic.rs that is a
// statement about two *duplicated bodies*, not about a call: `try_new_with` allocates its
// own `Zeroizing<Vec<u8>>` and runs its own `f(&mut v[..])?` rather than routing through
// `new_with`. Nothing makes the two move together, so the inherited promise is the one
// guarantee here that rests on prose alone.
//
// The `Err` check above is not a substitute, and the concrete rewrite that separates them
// is short enough to spell out:
//
//     let mut v = alloc::vec![0u8; len];
//     if let Err(e) = f(&mut v) { v.zeroize(); return Err(e); }
//
// A plain `Vec` wiped by hand on the error branch. `check_try_new_with_err_zeroed_vec`
// passes against that body exactly as it passes against the real one — it only ever leaves
// through the `Err` branch, where the hand-written wipe is. A closure that *unwinds*
// instead of returning skips that branch entirely, and a plain `Vec` has no destructor
// that zeroes, so the whole partial write reaches `dealloc` intact. One check apart, two
// implementations that are indistinguishable from outside.
//
// The unwind is not a hypothetical either, and it is worst precisely where `try_new_with`
// is recommended: the fills its own rustdoc names are a foreign decoder and
// `Read::read_exact`. A `Read` impl may panic anywhere it likes — the trait forbids
// nothing — and a decoder that indexes into its output buffer panics on exactly the
// malformed input it was handed to reject, after having written the part it understood.
//
// Shape mirrors `check_new_with_panic_zeroed_vec`: poison the slot, pin its pointer, panic
// under `catch_unwind`, then read what the allocator recorded. The closure body names no
// error value of its own, so `E` is fixed by the binding's type annotation instead.
// ---------------------------------------------------------------------------

fn check_try_new_with_panic_zeroed_vec(size: usize) {
    /// The closure's error type, never constructed: the body panics before it can return
    /// anything at all.
    ///
    /// It implements nothing, for the same reason `CallerGaveUp` above implements nothing —
    /// a bound appearing on `E` would break this file's compile, which is the cheapest
    /// available alarm for an API promise of that shape. Here it also pins the promise on
    /// the *diverging* path, where `E` is inferred from the signature rather than from any
    /// value the closure produces.
    struct NeverReturned;

    PANIC_CHECK_PTR.store(0, Ordering::SeqCst);
    PANIC_CHECK_ZEROED.store(false, Ordering::SeqCst);
    PANIC_CHECK_ACTIVE.store(true, Ordering::SeqCst);

    let result = std::panic::catch_unwind(|| {
        let outcome: Result<Dynamic<Vec<u8>>, NeverReturned> =
            Dynamic::<Vec<u8>>::try_new_with(size, |slot: &mut [u8]| {
                // Poison every byte. The slot arrives all-zero by contract, so a
                // constructor that protected nothing would still hand the recorder a
                // clean-looking block unless something non-zero was written first.
                //
                // A *full* fill rather than the half-fill the `Err` check uses: there the
                // untouched tail was the point (it proves only written bytes are being
                // caught), here the point is that an unwind must not leave any of it, and a
                // whole-slot poison is the strictest version of that.
                slot.fill(0x9Eu8);
                // Pin the slot's own pointer before panicking. Under this signature the
                // slot cannot be reallocated mid-closure — there is no growth to move it —
                // so this address is the one the unwind has to wipe.
                PANIC_CHECK_PTR.store(slot.as_ptr() as usize, Ordering::SeqCst);
                panic!("simulated closure panic after writing secret bytes");
            });
        // Unreachable: the closure always panics. Referencing the binding keeps the
        // optimizer from lifting the call out of the protected region.
        core::hint::black_box(&outcome);
    });

    PANIC_CHECK_ACTIVE.store(false, Ordering::SeqCst);
    assert!(
        result.is_err(),
        "catch_unwind should have captured the panic"
    );
    assert!(
        PANIC_CHECK_ZEROED.load(Ordering::SeqCst),
        "Dynamic::<Vec<u8>>::try_new_with must zero its slot when the closure unwinds, not \
         only when it returns Err"
    );
}

// ---------------------------------------------------------------------------
// `dynamic_newtype!`'s `Vec<u8>` arm — the `Err`-path wipe survives the forward
//
// The macro does not delegate transparently. Its `try_new_with` calls the inner
// `Dynamic`'s, applies `?`, and re-wraps the `Ok` in `Self` — a second body, in a second
// file, that can be rewritten to build its own buffer or to take the `Ok` value apart
// without the inner constructor changing by a character. A macro body only ever runs where
// someone instantiated it, so it is measured wherever someone instantiated it and watched
// what happened; that is here or nowhere. tests/lifecycle_trace_heap.rs traces
// macro-generated newtypes through the heap but never through `try_new_with`, and both
// `try_new_with` checks above drive the bare `Dynamic`.
//
// Cheap because the instrument is already standing. Same recording mode, same pointer pin,
// the same half-fill and the same 0xC7 poison as `check_try_new_with_err_zeroed_vec` —
// only the front door changes, which is what makes a difference in the result attributable
// to the forward rather than to the fill.
// ---------------------------------------------------------------------------

dynamic_newtype!(
    pub SlotToken,
    Vec<u8>,
    "A Vec<u8>-arm newtype, declared so the macro's own `try_new_with` forward is measured \
     rather than assumed to inherit the inner constructor's wipe."
);

fn check_newtype_try_new_with_err_zeroed(size: usize) {
    /// As in the bare-`Dynamic` check: a caller's own error type implementing nothing.
    ///
    /// The macro's forward declares `E` free too, and re-stating it through the generated
    /// signature is what catches a forward that quietly added a bound while the inner
    /// constructor kept none.
    struct CallerGaveUp;

    PANIC_CHECK_PTR.store(0, Ordering::SeqCst);
    PANIC_CHECK_ZEROED.store(false, Ordering::SeqCst);
    PANIC_CHECK_ACTIVE.store(true, Ordering::SeqCst);

    let result: Result<SlotToken, CallerGaveUp> =
        SlotToken::try_new_with(size, |slot: &mut [u8]| {
            // Half-fill, tail left at the slot's zeros: the only bytes this can catch are the
            // ones the closure actually wrote.
            slot[..size / 2].fill(0xC7u8);
            PANIC_CHECK_PTR.store(slot.as_ptr() as usize, Ordering::SeqCst);
            Err(CallerGaveUp)
        });

    PANIC_CHECK_ACTIVE.store(false, Ordering::SeqCst); // defensive cleanup
    assert!(
        result.is_err(),
        "the closure returned Err, so the newtype's try_new_with must not have produced a \
         SlotToken"
    );
    assert!(
        PANIC_CHECK_ZEROED.load(Ordering::SeqCst),
        "dynamic_newtype!'s try_new_with forward must release the partially written slot \
         zeroed, exactly as the Dynamic it wraps does"
    );
}

// ---------------------------------------------------------------------------
// Decode error path — a rejected input leaves no decoded bytes behind
//
// base16ct, base32ct and base64ct decode in constant time: they write every output byte
// and report a bad character only at the end. So an input that is a valid encoding
// followed by junk (a hex key with a CRLF line ending, Base64url with `=` padding) is
// rejected with the whole decoded secret already written. Through 0.9.0-rc.17 that buffer
// was the backend's own plain `Vec` (`decode_vec`), dropped unwiped; a 40-byte key was
// measured coming back from the allocator intact. The crate now allocates the buffer
// itself, inside `Zeroizing`, and decodes through the slice API (src/decode_staging.rs).
//
// The secret is 40 bytes of 0xC4 and the junk tails are sized so each staging buffer has
// a length of its own (41, 45, 43), clear of the 16/32/64/128 classes used above and of
// each other. Nothing else in the gate allocates: the errors are heap-free. Both the
// `Dynamic` and the `Fixed` (alloc) constructors go through the same staging, and both
// are exercised because they are separate call sites.
// ---------------------------------------------------------------------------

#[cfg(all(
    feature = "encoding-hex",
    feature = "encoding-base32",
    feature = "encoding-base64"
))]
fn check_decode_rejected_zeroed() {
    use secure_gate::{Fixed, ToBase32, ToBase64Url, ToHex};

    const SECRET: [u8; 40] = [0xC4; 40];

    // Built outside the gate. `into_inner` is deliberate: these are test inputs.
    let hex = format!("{}\r\n", SECRET.to_hex().into_inner());
    let base32 = format!("{}!!!!!!!!", SECRET.to_base32().into_inner());
    let base64 = format!("{}====", SECRET.to_base64url().into_inner());
    assert_eq!(
        (hex.len() / 2, base32.len() * 5 / 8, base64.len() * 3 / 4),
        (41, 45, 43)
    );

    with_proxy_check(41, || {
        assert!(Dynamic::<Vec<u8>>::try_from_hex(&hex).is_err());
        assert!(Fixed::<[u8; 40]>::try_from_hex(&hex).is_err());
    });
    with_proxy_check(45, || {
        assert!(Dynamic::<Vec<u8>>::try_from_base32(&base32).is_err());
        assert!(Fixed::<[u8; 40]>::try_from_base32(&base32).is_err());
    });
    with_proxy_check(43, || {
        assert!(Dynamic::<Vec<u8>>::try_from_base64url(&base64).is_err());
        assert!(Fixed::<[u8; 40]>::try_from_base64url(&base64).is_err());
    });
}

// ---------------------------------------------------------------------------
// EncodedSecret::into_zeroizing — the buffer keeps wiping after the hand-off
//
// `into_zeroizing` moves the inner `Zeroizing<String>` out of the wrapper. The
// claim is that zeroize-on-drop survives the move (only the redacted `Debug` is
// lost). Nothing observed that: the single existing test called it on an empty
// string, where a buffer that was never wiped and a buffer that never existed
// look identical. This encodes a known-nonzero secret, checks the text really is
// in the buffer, then lets it drop under the asserting allocator.
//
// Hex is two chars per byte, so a 24-byte secret gives a 48-byte String -- off the
// 16/32/64/128 size classes the checks above use, so nothing else in this file can be
// mistaken for it.
// ---------------------------------------------------------------------------

#[cfg(feature = "encoding-hex")]
fn check_into_zeroizing_string_zeroed<const N: usize>() {
    use secure_gate::ToHex;

    let size = N * 2;

    with_proxy_check(size, || {
        // The subject is `EncodedSecret`, not the wrapper that produced it, so this
        // encodes a bare array: the String under test is then the only heap allocation
        // inside the gate.
        let protected = [0xC4u8; N].to_hex().into_zeroizing();

        // Test realism guard: the allocator matches on layout size, so a String that
        // over-allocated would slip past the check entirely.
        assert_eq!(
            protected.capacity(),
            size,
            "hex String capacity {} != {size}; the dealloc check would not match it",
            protected.capacity()
        );
        // Positive control: prove there was something to wipe. Hex is ASCII, never NUL.
        assert!(
            protected.bytes().all(|b| b != 0),
            "the encoded buffer was already zero before the drop under test"
        );

        drop(protected);
    });
}

// ---------------------------------------------------------------------------
// Dynamic<[u8]> — the exact-capacity boxed slice
//
// The runtime-length shape whose buffer can never grow. Its drop had no allocator-level
// check: the array, `Vec` and `String` shapes above each have one, and this is a separate
// `Zeroize` path (`Box<[u8]>`). 72 bytes, clear of every size used above.
// ---------------------------------------------------------------------------

fn check_boxed_slice_zeroed() {
    const LEN: usize = 72;
    let hits = with_proxy_check_counted(LEN, || {
        let secret: Dynamic<[u8]> = Dynamic::from(vec![0xAAu8; LEN].into_boxed_slice());
        core::hint::black_box(&secret);
        drop(secret);
    });
    assert_eq!(
        hits, 1,
        "expected exactly the one {LEN}-byte slice to be freed"
    );
}

// ---------------------------------------------------------------------------
// EncodedSecret — dropped directly, for every encoder
//
// `check_into_zeroizing_string_zeroed` above follows the buffer through `into_zeroizing`,
// for hex only. This is the ordinary case: an `EncodedSecret` that is simply dropped, from
// each encoder, since each builds its `String` separately. An encoded secret is a second
// full copy of the secret, so a buffer freed unwiped here is the secret freed unwiped.
//
// The subject is a bare 28-byte array, so the encoded `String` is the only allocation in
// the gate. The gate matches on allocation size and `EncodedSecret` exposes no capacity,
// so each check asserts the gate inspected exactly one block: an encoder that allocated
// more than the text needs would otherwise pass by observing nothing.
// ---------------------------------------------------------------------------

#[cfg(all(
    feature = "encoding-hex",
    feature = "encoding-base32",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
fn check_encoded_secret_drop_zeroed() {
    use secure_gate::{Case, EncodedSecret, ToBase32, ToBase64Url, ToBech32, ToBech32m, ToHex};

    const SECRET: [u8; 28] = [0xC4; 28];

    fn encode(name: &str) -> EncodedSecret {
        match name {
            "hex" => SECRET.to_hex(),
            "hex upper" => SECRET.to_hex_upper(),
            "base32" => SECRET.to_base32(),
            "base64url" => SECRET.to_base64url(),
            "bech32" => SECRET.try_to_bech32("key", Case::Lower).expect("fits"),
            "bech32m" => SECRET.try_to_bech32m("key", Case::Lower).expect("fits"),
            other => unreachable!("{other}"),
        }
    }

    for name in [
        "hex",
        "hex upper",
        "base32",
        "base64url",
        "bech32",
        "bech32m",
    ] {
        // Encoded once outside the gate, only to learn the length the gate should match.
        let len = encode(name).len();
        let hits = with_proxy_check_counted(len, || {
            let encoded = encode(name);
            // Positive control: every alphabet here is ASCII, never NUL.
            assert!(encoded.bytes().all(|b| b != 0), "{name}: nothing to wipe");
            drop(encoded);
        });
        assert_eq!(
            hits, 1,
            "{name}: expected exactly one {len}-byte buffer freed (and zeroed)"
        );
    }
}

// ---------------------------------------------------------------------------
// SealedDynamic — the plaintext copies made by seal, read, mutate and unseal
//
// Every sealed access decrypts into a heap temporary and promises to wipe it when the call
// returns (`SECURITY.md` §3, `src/sealed/dynamic.rs`). Nothing watched that at the
// allocator. Each step below runs in its own gate and frees exactly one 200-byte plaintext
// buffer, which must be zero:
//
//   seal             the plain `Dynamic` that was consumed
//   with_secret      the decrypted temporary
//   with_secret_mut  the decrypted temporary (the ciphertext is rewritten in place)
//   unseal           the returned `Dynamic`, dropped in a gate of its own: `unseal` also
//                    frees the consumed ciphertext buffer, which is the same size
//   (panic)          the temporary, when the `with_secret` closure unwinds
//
// The sealed value itself is dropped outside every gate: its buffer is ciphertext, the
// same size as the plaintext, and correctly not zero.
// ---------------------------------------------------------------------------

#[cfg(feature = "sealed")]
fn check_sealed_dynamic_plaintext_zeroed() {
    use secure_gate::{Prekey, SealedDynamic};

    const LEN: usize = 200;
    let prekey = Prekey::new();

    let plain = Dynamic::<Vec<u8>>::new_with(LEN, |slot| slot.fill(0xC4));
    let mut sealed = None;
    let hits = with_proxy_check_counted(LEN, || {
        sealed = Some(SealedDynamic::seal(plain, &prekey));
    });
    assert_eq!(hits, 1, "seal: the consumed plain buffer was not observed");
    let mut sealed = sealed.expect("sealed above");

    let hits = with_proxy_check_counted(LEN, || {
        sealed.with_secret(|v| assert!(v.iter().all(|&b| b == 0xC4)));
    });
    assert_eq!(
        hits, 1,
        "with_secret: the plaintext temporary was not observed"
    );

    let hits = with_proxy_check_counted(LEN, || {
        sealed.with_secret_mut(|v| v.fill(0xC5));
    });
    assert_eq!(
        hits, 1,
        "with_secret_mut: the plaintext temporary was not observed"
    );

    // A panic inside the closure must wipe the temporary too.
    let hits = with_proxy_check_counted(LEN, || {
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sealed.with_secret(|_| std::panic::resume_unwind(Box::new(())));
        }));
        assert!(caught.is_err());
    });
    assert_eq!(
        hits, 1,
        "with_secret panic: the plaintext temporary was not observed"
    );

    // unseal: the plaintext comes back as an ordinary `Dynamic`. `unseal` itself runs outside
    // the gate because it frees the ciphertext buffer, which is the same size and not zero.
    let unsealed = sealed.unseal();
    let hits = with_proxy_check_counted(LEN, || drop(unsealed));
    assert_eq!(
        hits, 1,
        "unseal: the returned buffer was not observed on drop"
    );

    // The `String` payload reuses the decrypted buffer (`String::from_utf8`), a separate
    // code path from `Vec<u8>`.
    const TEXT_LEN: usize = 216;
    let sealed = SealedDynamic::seal(Dynamic::<String>::new("p".repeat(TEXT_LEN)), &prekey);
    let hits = with_proxy_check_counted(TEXT_LEN, || {
        sealed.with_secret(|s| assert!(s.bytes().all(|b| b == b'p')));
    });
    assert_eq!(
        hits, 1,
        "String with_secret: the plaintext temporary was not observed"
    );
}

// ---------------------------------------------------------------------------
// Aggregate test
// ---------------------------------------------------------------------------

/// Verifies `Dynamic<[u8; N]>`, `Dynamic<Vec<u8>>`, `Dynamic<String>`, all
/// decode paths, all deserialize paths, the panic-path positive control, and both
/// of `try_new_with`'s failure paths — an `Err` return and a closure unwind, plus
/// the `Err` path again through a `dynamic_newtype!` newtype — all zeroize heap
/// memory before deallocation.
///
/// This stays as one aggregate test by design to avoid parallel test interleaving
/// with the global ProxyAllocator state.
#[test]
fn all_heap_zeroed() {
    #[cfg(feature = "encoding-bech32")]
    check_bech32_hrp_mismatch_materializes_nothing();

    // EncodedSecret::into_zeroizing keeps wiping after the hand-off
    #[cfg(feature = "encoding-hex")]
    {
        check_into_zeroizing_string_zeroed::<24>();
        check_into_zeroizing_string_zeroed::<40>();
    }

    // Dynamic<[u8]> — the exact-capacity boxed slice
    check_boxed_slice_zeroed();

    // EncodedSecret dropped directly, one check per encoder
    #[cfg(all(
        feature = "encoding-hex",
        feature = "encoding-base32",
        feature = "encoding-base64",
        feature = "encoding-bech32"
    ))]
    check_encoded_secret_drop_zeroed();

    // SealedDynamic's plaintext copies: seal, read, mutate, panic, unseal
    #[cfg(feature = "sealed")]
    check_sealed_dynamic_plaintext_zeroed();

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

    // Realloc-orphan zeroization when a *live* wrapper grows (SGC-002).
    // Sizes chosen to avoid the 16/32/64/128 classes used above.
    #[cfg(feature = "std")]
    {
        check_write_growth_orphan_zeroed(96);
        check_write_growth_orphan_zeroed(192);
    }

    // Decode-path backing-buffer zeroization (#96 / from_protected_bytes fix)
    #[cfg(feature = "encoding-hex")]
    {
        check_decode_hex_zeroed("deadbeef", 4);
        check_decode_hex_zeroed("0102030405060708090a0b0c0d0e0f10", 16);
    }

    #[cfg(feature = "encoding-base32")]
    {
        check_decode_base32_zeroed(&[0xAAu8; 16]);
        check_decode_base32_zeroed(&[0xBBu8; 32]);
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

    #[cfg(feature = "encoding-bech32")]
    {
        check_decode_bech32m_zeroed(&[0xAAu8; 16]);
        check_decode_bech32m_zeroed(&[0xBBu8; 32]);
    }

    // Decode error path: a rejected input must not leave the decoded bytes in a freed block.
    #[cfg(all(
        feature = "encoding-hex",
        feature = "encoding-base32",
        feature = "encoding-base64"
    ))]
    check_decode_rejected_zeroed();

    // Deserialize-path backing-buffer zeroization (deserialize_with_limit fix)
    #[cfg(feature = "serde-deserialize")]
    {
        check_vec_deserialized_zeroed(16);
        check_vec_deserialized_zeroed(32);
        check_string_deserialized_zeroed(16);
        check_string_deserialized_zeroed(32);
    }

    // Panic-path positive control: proves Zeroizing zeroes bytes on unwind.
    // Size 8192 avoids collision with panic-machinery allocations (see comment above).
    check_panic_path_bytes_zeroed(8192);

    // Finding 1 regression: Dynamic::new_with closure-panic leak.
    // Verifies that a closure panicking after writing secret bytes does not
    // leak those bytes — the slot must be Zeroizing-protected for the entire
    // lifetime of the closure. Same size rationale as above.
    check_new_with_panic_zeroed_vec(8192);

    // try_new_with wipes the partial write when the fill returns Err. This allocator
    // proxy is the only instrument in the repo that can watch a buffer being wiped, so
    // it is the only place the guarantee can be tested at all: from outside, a
    // constructor that wiped and one that abandoned a half-written secret both just
    // return Err. Guards against "wrap only on success", which would leak partial
    // plaintext on every malformed input — the routine behaviour of decoders that write
    // into a caller-supplied buffer.
    //
    // 8192 again, though nothing unwinds on this path: the pin is by pointer, so the
    // size only keeps the check clear of the 16/32/64/128 classes used above.
    check_try_new_with_err_zeroed_vec(8192);

    // The same constructor's *panic* path, which the `Err` check immediately above cannot
    // reach. `try_new_with` is a duplicated body in src/dynamic.rs rather than a call into
    // `new_with`, so it does not inherit `new_with`'s panic-safety by construction — only
    // by the rustdoc calling the two identical. Rewrite it to hold a plain `Vec` and wipe
    // it by hand on the error branch and the `Err` check stays green while an unwinding
    // closure leaks the entire partial write, which is the failure shape the fills that
    // rustdoc recommends (a foreign decoder, `read_exact`) can actually produce.
    check_try_new_with_panic_zeroed_vec(8192);

    // And the `Err`-path wipe as seen through `dynamic_newtype!`'s `Vec<u8>` arm, whose
    // `try_new_with` re-wraps the inner result instead of delegating transparently. That
    // forward is a separate body in src/macros/dynamic_newtype.rs, and nothing else in the
    // repo follows a macro-generated newtype's bytes through the fallible constructor.
    check_newtype_try_new_with_err_zeroed(8192);
}
