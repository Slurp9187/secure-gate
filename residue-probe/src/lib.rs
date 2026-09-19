//! Measure whether a byte pattern you planted is still present in heap blocks at the moment
//! they are released.
//!
//! This crate is a [`GlobalAlloc`] wrapper — a *spy* — that reads each block as it passes
//! through `dealloc` and counts occurrences of a known pattern. It does not know anything
//! about your program: you supply the closure, you plant the pattern, you decide what the
//! numbers have to be. It has no dependencies.
//!
//! The measurement it supports is: *when my program abandons a buffer, does the data still
//! live in the block that goes back to the allocator?* That is a question about your program
//! and about whichever allocator you install above the spy, and it can be asked of any Rust
//! project.
//!
//! # The three-configuration discipline
//!
//! A `#[global_allocator]` is process-wide, so each configuration is its own test binary.
//! You need **three**, and the two-configuration version of this experiment is the mistake
//! this crate exists to stop you making.
//!
//! | binary | allocator | what it must report |
//! |---|---|---|
//! | `residue_control` | [`Spy`] alone | the pattern **is** released — there is something to find |
//! | `residue_nowipe` | [`NoWipe`]`<`[`Spy`]`>` | the pattern is still found **in the composed position** |
//! | `residue_subject` | `YourAlloc<`[`Spy`]`>` | whatever you are measuring |
//!
//! **Two configurations cannot tell a working wipe from a probe that is not looking.** If
//! the subject reports zero hits, that result is consistent with three different worlds: the
//! wipe worked; the blocks were never released; or the spy is reading memory other than the
//! memory it believes it is reading. The control binary rules out the second. The no-wipe
//! binary rules out the third, because it has the subject's *composition* and its `realloc`
//! route and differs from the subject in exactly one thing — the wipe. A spy reading the
//! wrong position would report clean under the subject **and** clean here.
//!
//! So: **the no-wipe leg MUST report dirty, or the subject's zero means nothing.** Assert it;
//! do not print it and read it later.
//!
//! ```ignore
//! // tests/residue_support/mod.rs — shared by all three binaries, so the subject and its
//! // controls cannot drift apart. (A subdirectory is not built as a test target.)
//! use secure_gate_residue_probe::{plant, planted_hits, Measurement};
//!
//! pub const SECRET_LEN: usize = 4096;
//!
//! /// Your program's own shape. Plant, abandon the buffer, and prove it was abandoned.
//! pub fn workload() {
//!     let mut buf = vec![0u8; SECRET_LEN];
//!     plant(&mut buf);
//!     let before = buf.as_ptr().addr();
//!     buf.push(0); // a capacity change: the old block is abandoned outside your control
//!     assert_ne!(
//!         before,
//!         buf.as_ptr().addr(),
//!         "nothing was abandoned, so this window measured nothing"
//!     );
//!     std::hint::black_box(&buf);
//! }
//!
//! /// Every configuration checks this much, so only the final expectation differs.
//! pub fn sanity(m: &Measurement) {
//!     assert!(m.blocks > 0, "no block released -- the workload did not run");
//!     assert_eq!(m.foreign_deallocs, 0, "another thread deallocated during the window");
//! }
//!
//! pub fn expected_hits() -> usize {
//!     planted_hits(SECRET_LEN)
//! }
//! ```
//!
//! ```ignore
//! // tests/residue_control.rs — CONTROL 1: there is something to find.
//! mod residue_support;
//! use residue_support::{expected_hits, sanity, workload};
//! use secure_gate_residue_probe::{measure, Spy};
//! use std::alloc::System;
//!
//! #[global_allocator]
//! static ALLOC: Spy<System> = Spy(System);
//!
//! #[test]
//! fn the_pattern_is_released() {
//!     let m = measure("control", workload);
//!     sanity(&m);
//!     assert!(
//!         m.pattern_hits >= expected_hits(),
//!         "the probe is not observing what it believes it is"
//!     );
//! }
//! ```
//!
//! ```ignore
//! // tests/residue_nowipe.rs — CONTROL 2: the probe sees it in the composed position.
//! mod residue_support;
//! use residue_support::{expected_hits, sanity, workload};
//! use secure_gate_residue_probe::{measure, NoWipe, Spy};
//! use std::alloc::System;
//!
//! #[global_allocator]
//! static ALLOC: NoWipe<Spy<System>> = NoWipe(Spy(System));
//!
//! #[test]
//! fn the_composed_position_still_sees_the_pattern_when_nothing_wipes() {
//!     let m = measure("no-wipe", workload);
//!     sanity(&m);
//!     // MUST be dirty. If this ever goes quiet, residue_subject.rs proves nothing.
//!     assert!(
//!         m.pattern_hits >= expected_hits(),
//!         "clean here means the subject's zero is untested, not that anything was wiped"
//!     );
//! }
//! ```
//!
//! ```ignore
//! // tests/residue_subject.rs — SUBJECT: your allocator, in the same position.
//! mod residue_support;
//! use my_alloc::WipeOnFree; // whatever you are measuring
//! use residue_support::{sanity, workload};
//! use secure_gate_residue_probe::{measure, Spy};
//! use std::alloc::System;
//!
//! #[global_allocator]
//! static ALLOC: WipeOnFree<Spy<System>> = WipeOnFree(Spy(System));
//!
//! #[test]
//! fn nothing_the_workload_abandons_survives() {
//!     let m = measure("subject", workload);
//!     sanity(&m); // blocks > 0, or this is a blind probe rather than a clean one
//!     assert_eq!(m.pattern_hits, 0);
//! }
//! ```
//!
//! Read all three or none. A subject binary quoted on its own is not a result.
//!
//! # What a probe of this shape structurally cannot prove
//!
//! **It cannot detect optimizer elimination of a wipe.** The volatile read in
//! [`Spy::dealloc`] is what makes the observation possible, and it is *the same thing* that
//! keeps a wipe's stores live: a store the compiler can see is followed by a volatile read is
//! not a dead store. So this harness is not merely silent about dead-store elimination — it
//! is structurally incapable of detecting it, and no number of extra configurations fixes
//! that. `cargo test` is also opt-level 0 by default, which is a second, smaller reason not
//! to read a result here as a statement about your release build.
//!
//! What these three binaries establish is that the blocks your workload abandons pass through
//! the allocator carrying, or not carrying, your pattern **in this build**. Whether a wipe
//! survives an optimizing build is a *different question* needing a different instrument (an
//! optimized build compared under PGO and LTO, or inspection of the emitted code). The two
//! claims are not the same sentence and should not be merged into one.
//!
//! # Correctness rules you must not break
//!
//! These are not style. Each one is the difference between a measurement and a number.
//!
//! 1. [`Spy::realloc`] is **move-always** and never forwards to the inner `realloc`; see its
//!    documentation for the defect class that a forwarding probe structurally cannot see.
//! 2. [`NoWipe`] leaves `realloc` to the [`GlobalAlloc`] default, because that is the route a
//!    wrapper that does not implement `realloc` actually takes.
//! 3. The spy reads at **offset 0**, at the `dealloc` boundary, through `read_volatile`.
//! 4. The spy never allocates inside `dealloc`.
//! 5. One measuring thread; anything else is counted separately and must be asserted zero.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![warn(clippy::undocumented_unsafe_blocks)]

use std::alloc::{GlobalAlloc, Layout};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// The planted pattern
// ---------------------------------------------------------------------------

/// The byte pattern [`plant`] writes and [`Spy`] counts — the only thing counted as residue.
///
/// **Why a planted pattern rather than non-zero bytes.** Counting every non-zero byte
/// measures the workload as much as the hazard: allocator bookkeeping, `Vec` headers and
/// harness scratch all read as non-zero, so the figure is an upper bound that has to be
/// explained away afterwards. Counting occurrences of a pattern you put there yourself
/// cannot be inflated by incidental data, and it survives a change of workload. A
/// configuration's `0` then means "none of it came back", not "not much came back".
///
/// Eight distinct non-zero bytes. Distinctness matters twice: no proper prefix of the pattern
/// is also a suffix of it, so tiled payload yields exactly one occurrence per eight bytes with
/// no unaligned extras; and an accidental match in unrelated memory costs `2^-64` rather than
/// the `2^-8` a single sentinel byte would.
pub const PATTERN: [u8; 8] = [0x5A, 0xC3, 0x17, 0xE9, 0x42, 0x8B, 0xD6, 0x71];

/// [`PATTERN`] as the big-endian word the sliding window in [`scan`] compares against.
const PATTERN_WORD: u64 = u64::from_be_bytes(PATTERN);

/// Tiles [`PATTERN`] across `buf`, starting at offset 0.
///
/// Plant into the buffer you are about to abandon, then use [`planted_hits`] for the count a
/// non-wiping configuration has to report.
pub fn plant(buf: &mut [u8]) {
    for (i, byte) in buf.iter_mut().enumerate() {
        *byte = PATTERN[i % PATTERN.len()];
    }
}

/// Occurrences of [`PATTERN`] that [`plant`] leaves in a buffer of `len` bytes.
///
/// Compare with `>=`, never `==`: how many blocks a run abandons, and how many copies of the
/// payload are live at once, is a property of the build as well as of your source. One
/// harness this was ported from recorded 405 dirty blocks at `--release` against 521 at
/// opt-level 0 for the same workload. The floor is what you can assert; the exact count is
/// not.
#[must_use]
pub fn planted_hits(len: usize) -> usize {
    len / PATTERN.len()
}

/// Counts occurrences of [`PATTERN`] in a slice you still own, at every offset.
///
/// The safe counterpart of what [`Spy`] does at the `dealloc` boundary — useful for asserting
/// that your workload really planted what you think it planted, before you abandon the
/// buffer.
#[must_use]
pub fn count_pattern(bytes: &[u8]) -> usize {
    scan(bytes.iter().copied())
}

/// One `u64` sliding window, no allocation, one pass.
///
/// Shared by [`count_pattern`] and the volatile raw-pointer scan so the two can never
/// disagree about what an occurrence is.
fn scan(bytes: impl Iterator<Item = u8>) -> usize {
    let mut window: u64 = 0;
    let mut hits = 0usize;
    for (i, byte) in bytes.enumerate() {
        window = (window << 8) | u64::from(byte);
        if i + 1 >= PATTERN.len() && window == PATTERN_WORD {
            hits += 1;
        }
    }
    hits
}

/// Counts occurrences of [`PATTERN`] in the `len` bytes at `ptr`, at every offset.
///
/// One `u64` sliding window on the stack, one volatile read per byte, no allocation. Volatile
/// because this reads a block the program has finished with, and a plain read would be
/// entitled to disappear.
///
/// # Safety
///
/// `ptr` must be valid for reads of `len` bytes. Called only from [`Spy::dealloc`], on a block
/// the caller is in the middle of releasing and which the inner allocator has not been told
/// about yet.
unsafe fn count_pattern_raw(ptr: *const u8, len: usize) -> usize {
    scan((0..len).map(|i| {
        // SAFETY: the caller guarantees `ptr` is valid for reads of `len` bytes, and `i <
        // len`, so `ptr.add(i)` is in bounds and readable. Volatile so the read cannot be
        // elided as dead.
        unsafe { std::ptr::read_volatile(ptr.add(i)) }
    }))
}

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

/// Count only while a measured window runs, or the harness's own allocations dominate.
static ARMED: AtomicBool = AtomicBool::new(false);

/// Mutual exclusion for [`measure`], kept separate from [`ARMED`] so the counters can be
/// reset before the counting gate opens.
static MEASURING: AtomicBool = AtomicBool::new(false);

/// Blocks released on the arming thread while armed — the denominator.
static BLOCKS: AtomicUsize = AtomicUsize::new(0);

/// Of those, how many carried at least one occurrence of [`PATTERN`].
static BLOCKS_WITH_PATTERN: AtomicUsize = AtomicUsize::new(0);

/// Total occurrences of [`PATTERN`] recovered across all released blocks.
static PATTERN_HITS: AtomicUsize = AtomicUsize::new(0);

/// Bytes the probe read — the size of the evidence the counts above rest on.
static BYTES_INSPECTED: AtomicUsize = AtomicUsize::new(0);

/// Deallocations that arrived from a thread other than the one that armed the gate.
static FOREIGN_DEALLOCS: AtomicUsize = AtomicUsize::new(0);

/// Whether a measured window is currently open.
///
/// Assert `!is_armed()` after your measurements: a window left armed means a panic escaped
/// [`measure`], and every later number in the process is contaminated.
#[must_use]
pub fn is_armed() -> bool {
    ARMED.load(Ordering::SeqCst)
}

// ---------------------------------------------------------------------------
// Foreign-thread detection
// ---------------------------------------------------------------------------

thread_local! {
    /// True only on the thread inside [`measure`], and only while the gate is armed.
    ///
    /// **Why this exists, and why it must not be tidied away.** Every counter above is
    /// process-wide state, so the measurement is sound only if one thread is allocating
    /// during the armed window. The usual answer is `--test-threads=1`, which is a property
    /// of how one run was invoked rather than of the technique: it is not inheritable, and a
    /// CI job that runs bare `cargo test` does not have it. So the requirement has to be
    /// structural, which is why each configuration is one binary with one aggregate
    /// `#[test]`. That reads as style and will be consolidated away by someone tidying files
    /// unless the reason travels with it.
    ///
    /// **One test per binary is still not sufficient on its own.** libtest's default harness
    /// runs even a single test body on a *spawned* thread, with the main thread parked
    /// waiting for it. So the armed window always has another live thread in it. That thread
    /// is blocked and the risk is low — which is worse than high, because it passes for
    /// months and then produces one inexplicable count nobody can reproduce. This flag turns
    /// that silent skew into a named failure: anything deallocating from elsewhere lands in
    /// [`Measurement::foreign_deallocs`] instead of in the measurement, and every binary
    /// asserts that count is zero. A measurement of zero foreign deallocations taken under
    /// `--test-threads=1` is a fact about that run, not a property of the technique, so it is
    /// not inheritable either.
    ///
    /// `const`-initialized and `Copy` with no destructor, so no TLS destructor is registered
    /// and [`Spy::dealloc`] cannot observe it being torn down. [`measure`] sets it *before*
    /// raising [`ARMED`] and clears it *after* lowering it, so on the measuring thread the
    /// TLS block already exists by the time the allocator can read it, and is still valid
    /// when the last armed `dealloc` lands — preserve that ordering if you edit [`measure`].
    /// A genuinely foreign thread may touch its own block for the first time inside
    /// `dealloc`; on targets that materialize TLS lazily that can allocate, which is harmless
    /// here because it routes through `alloc`, never back into `dealloc`, so it can neither
    /// recurse nor perturb a counter.
    static ON_ARMING_THREAD: Cell<bool> = const { Cell::new(false) };
}

/// Reads [`ON_ARMING_THREAD`] without ever unwinding.
///
/// `LocalKey::with` panics if the slot is being destroyed, and a panic out of `dealloc`
/// violates the allocator contract. `try_with` cannot panic; and both of its outcomes on a
/// foreign thread mean the same thing here — not the arming thread — so the fallback is a
/// correct answer rather than a guess.
fn on_arming_thread() -> bool {
    ON_ARMING_THREAD.try_with(Cell::get).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Spy — the probe
// ---------------------------------------------------------------------------

/// Observes each block at the moment it is released, after any wrapper above has had it.
///
/// Generic over the allocator it sits on, so it composes with whatever you actually use:
/// `Spy(System)`, `Spy(Jemalloc)`, `Spy(MyArena)`. Install it *beneath* the allocator you are
/// measuring — `YourAlloc<Spy<System>>` — so the order on release is `YourAlloc::dealloc` →
/// whatever it does → `Spy::dealloc` → **read** → `System::dealloc`.
///
/// # Why the spy reads from offset 0
///
/// In that composition the inner allocator has not been told about the block yet, so nothing
/// has written free-list links into its first bytes and the whole block is honest to read. A
/// probe that inspects a block *after* free must skip a prefix — two words in a small glibc
/// bin, four once it is sorted into a large one — and a skipped prefix is where residue could
/// hide.
///
/// If the spy is ever repositioned, re-derive that rather than inheriting "offset 0" as a
/// constant: it is a consequence of where in the composition the read happens, not a fact
/// about heap layout.
///
/// # The spy must not allocate
///
/// Anything allocating inside `dealloc` re-enters the allocator. Counting into atomics
/// allocates nothing, and the pattern scan works out of one `u64` on the stack. Keep it that
/// way: a logging line added here "just for debugging" recurses or deadlocks.
#[repr(transparent)]
pub struct Spy<A: GlobalAlloc>(pub A);

impl<A: GlobalAlloc> Spy<A> {
    /// Wraps `inner`. `const` so it can initialize a `#[global_allocator]` static.
    pub const fn new(inner: A) -> Self {
        Self(inner)
    }
}

// SAFETY: every method forwards to the inner allocator with the layout it was given; the
// counting path reads only within `layout.size()` of a block the caller is releasing, and
// allocates nothing.
unsafe impl<A: GlobalAlloc> GlobalAlloc for Spy<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: `layout` is the caller's, forwarded unchanged; the caller upholds
        // `GlobalAlloc::alloc`'s contract on our behalf.
        unsafe { self.0.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as `alloc`; `layout` is forwarded unchanged.
        unsafe { self.0.alloc_zeroed(layout) }
    }

    /// Deliberately **not** a forward to the inner `realloc`.
    ///
    /// libc's `realloc` releases the old block inside the C allocator, so it never reaches
    /// `dealloc` and this probe cannot see it — which hides precisely the
    /// reallocation-abandoned blocks the measurement is usually about. Measured in the
    /// harness this was ported from: forwarding here reported zero dirty blocks for a defect
    /// whose abandoned buffers were already documented and already known to be released. A
    /// forwarding probe does not report that defect class *weakly*; it is structurally unable
    /// to see it at all.
    ///
    /// The general rule, which cost an afternoon to learn: **a control must release memory by
    /// the same route as the subject.** A wrapper that does not implement `realloc` takes
    /// [`GlobalAlloc`]'s default — allocate, copy, release through `dealloc` — so mirroring
    /// that here keeps the thing under test as the only difference between the three
    /// configurations.
    ///
    /// A second consequence worth knowing, because assertions rest on it: the old block is
    /// released *after* its replacement has been allocated, so the replacement cannot be
    /// handed back the old block's address. That is what makes "did the buffer move?"
    /// decisive rather than vulnerable to address reuse. [`GlobalAlloc`]'s default `realloc`,
    /// which the other configurations use, has the same ordering.
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: `GlobalAlloc::realloc`'s contract guarantees `new_size` is greater than
        // zero and that it, rounded up to `layout.align()`, does not overflow `isize::MAX`;
        // `layout.align()` is a valid alignment because `layout` itself is valid.
        let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
        // SAFETY: `new_layout` has a non-zero size, which is what `alloc` requires.
        let new_ptr = unsafe { self.alloc(new_layout) };
        if !new_ptr.is_null() {
            let copy = std::cmp::min(layout.size(), new_size);
            // SAFETY: `ptr` is valid for reads of `layout.size()` bytes and `new_ptr` for
            // writes of `new_size`, so both are valid for `copy` bytes; the two blocks cannot
            // overlap because `new_ptr` was allocated while `ptr` was still live.
            unsafe { std::ptr::copy_nonoverlapping(ptr, new_ptr, copy) };
            // SAFETY: `ptr` was allocated by this allocator with `layout`, and its contents
            // have been copied out, so the caller's block can be released. Routed through
            // `self.dealloc`, never the inner one, so the abandoned block is observed.
            unsafe { self.dealloc(ptr, layout) };
        }
        new_ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::Relaxed) {
            if on_arming_thread() {
                // SAFETY: `ptr` is a live block of `layout.size()` bytes that the caller is
                // releasing; the inner allocator has not been told about it yet, so the whole
                // block is readable and nothing else can be writing to it.
                let hits = unsafe { count_pattern_raw(ptr, layout.size()) };
                BLOCKS.fetch_add(1, Ordering::Relaxed);
                BYTES_INSPECTED.fetch_add(layout.size(), Ordering::Relaxed);
                if hits > 0 {
                    BLOCKS_WITH_PATTERN.fetch_add(1, Ordering::Relaxed);
                    PATTERN_HITS.fetch_add(hits, Ordering::Relaxed);
                }
            } else {
                // Not ours to measure, and recording it separately is the whole point: a
                // block counted here would otherwise have been folded silently into the
                // numbers above.
                FOREIGN_DEALLOCS.fetch_add(1, Ordering::Relaxed);
            }
        }
        // SAFETY: `ptr` and `layout` are the caller's, forwarded unchanged to the allocator
        // that produced the block; the scan above only read from it.
        unsafe { self.0.dealloc(ptr, layout) }
    }
}

// ---------------------------------------------------------------------------
// NoWipe — the control that makes a zero a measurement
// ---------------------------------------------------------------------------

/// A wrapper with a releasing allocator's *composition* and no behaviour of its own.
///
/// This is a synthetic construct that exists only to be the second control. It is not a model
/// of, or a stand-in for, any real allocator: it forwards everything and does nothing, and
/// whatever it reports is a property of this construct alone.
///
/// What it buys you is the difference between a silence and a measurement. `blocks > 0` shows
/// the counter ran; it does not show that the spy reads the bytes it claims to *in the
/// position it claims to*. A spy observing the wrong memory would report clean under the
/// subject and nothing would contradict it — but it would also report clean here, and this
/// must report hits.
///
/// Compose it exactly where the subject goes: `NoWipe<Spy<System>>` against
/// `YourAlloc<Spy<System>>`.
#[repr(transparent)]
pub struct NoWipe<A: GlobalAlloc>(pub A);

impl<A: GlobalAlloc> NoWipe<A> {
    /// Wraps `inner`. `const` so it can initialize a `#[global_allocator]` static.
    pub const fn new(inner: A) -> Self {
        Self(inner)
    }
}

// SAFETY: a pure forwarder; every method passes the caller's arguments through unchanged.
unsafe impl<A: GlobalAlloc> GlobalAlloc for NoWipe<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged; the caller upholds the contract.
        unsafe { self.0.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged; the caller upholds the contract.
        unsafe { self.0.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded unchanged; `ptr` came from this allocator with `layout`.
        unsafe { self.0.dealloc(ptr, layout) }
    }

    // `realloc` deliberately left to the `GlobalAlloc` default -- allocate, copy, release
    // through `dealloc` -- because that is the route a wrapper which does not implement
    // `realloc` actually takes, and a control has to release memory the same way the subject
    // does.
}

// ---------------------------------------------------------------------------
// measure
// ---------------------------------------------------------------------------

/// One armed window's worth of counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Measurement {
    /// Blocks released on the measuring thread while armed.
    ///
    /// Zero means a blind probe: a configuration reporting `pattern_hits == 0` must also
    /// report `blocks > 0`, or the clean result says nothing.
    pub blocks: usize,
    /// How many of those blocks carried at least one occurrence of [`PATTERN`].
    pub blocks_with_pattern: usize,
    /// Total occurrences of [`PATTERN`] recovered from released blocks.
    ///
    /// Compare against [`planted_hits`] with `>=`, never `==`.
    pub pattern_hits: usize,
    /// Bytes the probe actually read — the size of the evidence behind the counts above.
    pub bytes_inspected: usize,
    /// Deallocations seen from any other thread.
    ///
    /// **Every configuration must assert this is zero.** A non-zero value invalidates the run
    /// rather than merely annotating it: the counters are process-wide, so another thread's
    /// blocks would otherwise be folded silently into the numbers.
    pub foreign_deallocs: usize,
}

/// Runs `f` with the spy counting, and reports what was released.
///
/// `label` is printed alongside the counts, so a binary running several workloads can say
/// which window a line came from.
///
/// The ordering here is load-bearing: the thread flag is raised before the counting gate and
/// lowered after it, so this thread's TLS block exists before the allocator can read it and is
/// still valid when the last armed `dealloc` lands. `println!` allocates, so it happens
/// outside the armed window.
///
/// # Panics
///
/// If another window is already open. The counters are process-wide singletons, so nested or
/// concurrent windows would silently blend two measurements into one, and failing loudly is
/// the only honest option. A panic out of `f` leaves the window open instead — which
/// [`is_armed`] will then report.
pub fn measure(label: &str, f: impl FnOnce()) -> Measurement {
    assert!(
        MEASURING
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok(),
        "measure() is already running: the counters are process-wide, so windows cannot nest \
         or overlap"
    );

    for counter in [
        &BLOCKS,
        &BLOCKS_WITH_PATTERN,
        &PATTERN_HITS,
        &BYTES_INSPECTED,
        &FOREIGN_DEALLOCS,
    ] {
        counter.store(0, Ordering::Relaxed);
    }

    // Released on unwind as well as on return. Without this, a workload that panics leaves
    // MEASURING set, and the next measure() dies with "already running" -- burying the real
    // cause under a complaint about the instrument.
    struct Disarm;
    impl Drop for Disarm {
        fn drop(&mut self) {
            ARMED.store(false, Ordering::SeqCst);
            ON_ARMING_THREAD.set(false);
            MEASURING.store(false, Ordering::SeqCst);
        }
    }

    ON_ARMING_THREAD.set(true);
    ARMED.store(true, Ordering::SeqCst);
    let disarm = Disarm;
    f();
    drop(disarm);

    let out = Measurement {
        blocks: BLOCKS.load(Ordering::Relaxed),
        blocks_with_pattern: BLOCKS_WITH_PATTERN.load(Ordering::Relaxed),
        pattern_hits: PATTERN_HITS.load(Ordering::Relaxed),
        bytes_inspected: BYTES_INSPECTED.load(Ordering::Relaxed),
        foreign_deallocs: FOREIGN_DEALLOCS.load(Ordering::Relaxed),
    };

    println!(
        "{}: released {} blocks ({} bytes inspected), {} carrying the planted pattern, {} \
         pattern occurrences recovered, {} deallocations from other threads",
        label,
        out.blocks,
        out.bytes_inspected,
        out.blocks_with_pattern,
        out.pattern_hits,
        out.foreign_deallocs
    );

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plant_fills_with_the_pattern_and_the_count_matches() {
        let mut buf = [0u8; 64];
        plant(&mut buf);
        assert_eq!(&buf[..PATTERN.len()], &PATTERN);
        assert_eq!(count_pattern(&buf), planted_hits(buf.len()));
    }

    #[test]
    fn a_buffer_shorter_than_the_pattern_holds_no_occurrence() {
        let mut buf = [0u8; 7];
        plant(&mut buf);
        assert_eq!(count_pattern(&buf), 0);
        assert_eq!(planted_hits(buf.len()), 0);
    }

    #[test]
    fn unaligned_occurrences_are_counted_too() {
        let mut buf = [0u8; 16];
        buf[3..3 + PATTERN.len()].copy_from_slice(&PATTERN);
        assert_eq!(count_pattern(&buf), 1);
    }

    #[test]
    fn no_window_is_open_by_default() {
        assert!(!is_armed());
    }
}
