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
//! is a fail-safe correction, not a licence to parallelize -- an over-count made
//! `check_bech32_hrp_mismatch_materializes_nothing` fail once in CI against code that was
//! byte-identical to the passing runs.
//!
//! The panic-path positive-control test (`check_panic_path_bytes_zeroed`) uses a separate
//! recording mode (PANIC_CHECK_*) that records without asserting inside `dealloc`, then checks
//! after `catch_unwind` returns — safe because `dealloc` must never panic (allocator contract).
//! Size 8192 is used to avoid collision with small Rust panic-machinery allocations (message
//! formatting, backtrace, TLS) that may occur during unwind.

// NOTE ON MIRI: the `not(miri)` gate below compiles this entire file away under `cargo miri
// test`, which `.github/workflows/fuzz-miri.yml` is the only job to run. The gate is necessary --
// a `#[global_allocator]` that inspects freed memory is not something Miri can execute -- but it
// means the thread-local reasoning below is checked by review and by the suite passing on a real
// allocator, never by Miri. Weigh that when editing the TLS path.
#![cfg(all(feature = "alloc", not(miri)))]
#![allow(clippy::undocumented_unsafe_blocks)]

use secure_gate::{Dynamic, RevealSecretMut};
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
    /// That is fail-open in the dangerous direction for a zero-allocation assertion: it cannot
    /// hide a real allocation, but it can invent one, and it did -- one CI run reported 4
    /// allocations for an HRP mismatch whose decode path was byte-identical to four green runs.
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
/// The sequential-only caveat on `with_proxy_check` is unaffected: asserting mode is still
/// process-global, so this file still runs as one aggregate test.
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
    use secure_gate::{
        Bech32Error, Fixed, FromBech32Str, FromBech32mStr, ToBech32, ToBech32m, bech32_code_length,
    };

    const N: usize = bech32_code_length(3, 900);
    let secret = vec![0x5Au8; 900];
    let b32 = secret
        .try_to_bech32_sized::<N>("age")
        .expect("encode")
        .into_inner();
    let b32m = secret
        .try_to_bech32m_sized::<N>("age")
        .expect("encode")
        .into_inner();

    // Every HRP-checked decode path, sized, on both checksums and all three surfaces.
    let wrong = count_allocs(|| {
        assert!(matches!(
            b32.try_from_bech32_sized::<N>("kem"),
            Err(Bech32Error::UnexpectedHrp)
        ));
        assert!(matches!(
            b32m.try_from_bech32m_sized::<N>("kem"),
            Err(Bech32Error::UnexpectedHrp)
        ));
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

    // Positive control: a correct decode into a Vec must allocate, or the counter
    // above proved nothing.
    let right = count_allocs(|| {
        let v = b32.try_from_bech32_sized::<N>("age").expect("decode");
        core::hint::black_box(&v);
    });
    assert!(
        right >= 1,
        "positive control: a successful Vec decode must allocate"
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
// Note: on the error path (invalid input) no `Vec` reaches our code — the `?`
// propagates before we ever hold bytes, so there is no buffer of ours to zeroize.
// The decoders' own scratch buffers are a separate matter and outside this crate's
// control: base16ct/base32ct/base64ct decode into a plain `Vec` and only check the
// accumulated error flag at the end, so a near-miss input leaves decoded plaintext
// in a buffer they drop un-zeroized. That is an upstream property, identical across
// all three formats, and these checks deliberately cover only our own buffers.
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
    let encoded = data.try_to_bech32("test").expect("valid hrp").into_inner();
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
        .try_to_bech32m("testm")
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
// Test shape mirrors `check_panic_path_bytes_zeroed`: poison-fill the buffer,
// pin its backing-buffer pointer in `PANIC_CHECK_PTR`, then panic. The
// proxy allocator records whether the matching dealloc saw all-zero bytes.
// ---------------------------------------------------------------------------

fn check_new_with_panic_zeroed_vec(size: usize) {
    PANIC_CHECK_PTR.store(0, Ordering::SeqCst);
    PANIC_CHECK_ZEROED.store(false, Ordering::SeqCst);
    PANIC_CHECK_ACTIVE.store(true, Ordering::SeqCst);

    let result = std::panic::catch_unwind(|| {
        let _secret: Dynamic<Vec<u8>> = Dynamic::<Vec<u8>>::new_with(|v: &mut Vec<u8>| {
            v.reserve_exact(size);
            v.extend(std::iter::repeat_n(0xAAu8, size));
            // Pin the backing-buffer pointer before panicking.
            PANIC_CHECK_PTR.store(v.as_ptr() as usize, Ordering::SeqCst);
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
        "Dynamic::<Vec<u8>>::new_with must zero its intermediate buffer on closure panic"
    );
}

fn check_new_with_panic_zeroed_string(size: usize) {
    PANIC_CHECK_PTR.store(0, Ordering::SeqCst);
    PANIC_CHECK_ZEROED.store(false, Ordering::SeqCst);
    PANIC_CHECK_ACTIVE.store(true, Ordering::SeqCst);

    let result = std::panic::catch_unwind(|| {
        let _secret: Dynamic<String> = Dynamic::<String>::new_with(|s: &mut String| {
            s.reserve_exact(size);
            s.extend(std::iter::repeat_n('A', size));
            PANIC_CHECK_PTR.store(s.as_ptr() as usize, Ordering::SeqCst);
            panic!("simulated closure failure after writing secret bytes");
        });
        core::hint::black_box(&_secret);
    });

    PANIC_CHECK_ACTIVE.store(false, Ordering::SeqCst);
    assert!(
        result.is_err(),
        "catch_unwind should have captured the panic"
    );
    assert!(
        PANIC_CHECK_ZEROED.load(Ordering::SeqCst),
        "Dynamic::<String>::new_with must zero its intermediate buffer on closure panic"
    );
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
    #[cfg(feature = "encoding-bech32")]
    check_bech32_hrp_mismatch_materializes_nothing();

    // EncodedSecret::into_zeroizing keeps wiping after the hand-off
    #[cfg(feature = "encoding-hex")]
    {
        check_into_zeroizing_string_zeroed::<24>();
        check_into_zeroizing_string_zeroed::<40>();
    }

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
    // leak those bytes — the intermediate buffer must be Zeroizing-protected
    // for the entire lifetime of the closure. Same size rationale as above.
    check_new_with_panic_zeroed_vec(8192);
    check_new_with_panic_zeroed_string(8192);
}
