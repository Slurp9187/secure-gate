//! The spy allocator and workloads shared by the three residue tests, so the subject and
//! its controls cannot drift apart.
//!
//! `heap_residue.rs`, `heap_residue_nowipe.rs` and `heap_residue_wiped.rs` differ from each
//! other in exactly one line — the `#[global_allocator]` — and everything measured lives
//! here. A `#[global_allocator]` is process-wide, so each is its own binary; Cargo builds
//! one per `tests/*.rs`, and a subdirectory like this one is not built as a test.
//!
//! Nothing here tests `secure-gate`. The crate is `#![forbid(unsafe_code)]` and can never
//! install an allocator. What is measured is the hazard `SECURITY.md` §2 documents — a
//! capacity change through `with_secret_mut` reallocates outside the crate, and the
//! abandoned block is freed with the secret still in it — and whether a zero-on-deallocate
//! global allocator, installed the way an application installs one, covers it. This file
//! doubles as the worked example a consumer copies.
//!
//! # Why the spy reads from offset 0
//!
//! Composed as `ZeroAlloc<Spy>`, the order is
//! `ZeroAlloc::dealloc` → wipe → `Spy::dealloc` → **read here** → `System::dealloc`. The
//! system allocator has not been told about the block yet, so nothing has written free-list
//! links into its first bytes and the whole block is honest to read. A probe that inspects
//! a block *after* free must skip a prefix — two words in a small glibc bin, four once it
//! is sorted into a large one — and a skipped prefix is where residue could hide.
//!
//! If the spy is ever repositioned, re-derive that rather than inheriting "offset 0" as a
//! constant: it is a consequence of where in the composition the read happens, not a fact
//! about heap layout.
//!
//! # The spy must not allocate
//!
//! Anything allocating inside `dealloc` re-enters the allocator. Counting into atomics
//! allocates nothing, and the pattern scan below works out of one `u64` on the stack.
//!
//! # What this harness cannot prove
//!
//! The volatile read that makes the observation possible is exactly what keeps a wipe's
//! stores live, so a runtime probe of this shape is not merely silent about dead-store
//! elimination — it is structurally incapable of detecting it. `cargo test` is also
//! opt-level 0. What these three binaries establish is that a zeroizing allocator wipes the
//! blocks §2's hazard abandons, including the reallocation-abandoned ones. Whether such a
//! wipe survives an optimizing build is a separate question, answered separately under PGO
//! and LTO by `tools/pgo_allocator_compare.sh`; the two claims are not the same sentence and
//! should not be merged into one.

#![allow(unreachable_pub, dead_code)]
#![allow(clippy::undocumented_unsafe_blocks)]

use secure_gate::{Dynamic, RevealSecretMut};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

/// Count only while the workload runs, or the harness's own allocations dominate.
pub static ARMED: AtomicBool = AtomicBool::new(false);

/// Blocks released on the arming thread while armed — the denominator.
pub static BLOCKS: AtomicUsize = AtomicUsize::new(0);

/// Of those, how many carried at least one occurrence of [`PATTERN`].
pub static PATTERN_BLOCKS: AtomicUsize = AtomicUsize::new(0);

/// Total occurrences of [`PATTERN`] recovered across all released blocks.
pub static PATTERN_HITS: AtomicUsize = AtomicUsize::new(0);

/// Deallocations that arrived from a thread other than the one that armed the gate.
///
/// See [`ON_ARMING_THREAD`] for why this counter has to exist.
pub static FOREIGN_DEALLOCS: AtomicUsize = AtomicUsize::new(0);

// ---------------------------------------------------------------------------
// The planted pattern
// ---------------------------------------------------------------------------

/// The byte pattern planted into the secret, and the only thing counted as residue.
///
/// **Why a planted pattern rather than non-zero bytes.** Counting every non-zero byte
/// measures the workload as much as the hazard: allocator bookkeeping, `Vec` headers and
/// harness scratch all read as non-zero, so the figure is an upper bound that has to be
/// explained away afterwards. Counting occurrences of a pattern this file put into the
/// secret cannot be inflated by incidental data, and it survives a change of workload. A
/// configuration's `0` then means "none of the secret came back", not "not much came back".
///
/// Eight distinct non-zero bytes. Distinctness matters twice: no proper prefix of the
/// pattern is also a suffix of it, so tiled payload yields exactly one occurrence per eight
/// bytes with no unaligned extras; and an accidental match in unrelated memory costs `2^-64`
/// rather than the `2^-8` a single sentinel byte would.
pub const PATTERN: [u8; 8] = [0x5A, 0xC3, 0x17, 0xE9, 0x42, 0x8B, 0xD6, 0x71];

/// [`PATTERN`] as the big-endian word the sliding window in [`count_pattern`] compares against.
const PATTERN_WORD: u64 = u64::from_be_bytes(PATTERN);

/// Payload size of the secret in both workloads: 4 KiB, matching `SECURITY.md` §2.
pub const SECRET_LEN: usize = 4096;

/// Occurrences of [`PATTERN`] each workload plants into its secret.
///
/// Both workloads abandon one block holding the whole payload, so a configuration that does
/// not wipe should release at least this many. Assert `>=`, not `==`: how many blocks a
/// given run abandons is a property of the build as well as of the source — the harness this
/// was ported from (msoffice-crypto, branch experiment/zeroizing-alloc) recorded 405 dirty
/// blocks at `--release` against 521 at opt-level 0 for one workload; see
/// `docs/design/heap-residue.md`'s "Scope limits" section.
pub const PLANTED_HITS: usize = SECRET_LEN / PATTERN.len();

// ---------------------------------------------------------------------------
// Foreign-thread detection
// ---------------------------------------------------------------------------

thread_local! {
    /// True only on the thread inside [`measure`], and only while the gate is armed.
    ///
    /// **Why this exists, and why it must not be tidied away.** Every counter above is
    /// process-wide state, so the measurement is sound only if one thread is allocating
    /// during the armed window. The usual answer is `--test-threads=1`, and secure-gate's CI
    /// does not pass it: `test`, `test-release` and `msrv` all run bare `cargo test`, and
    /// `.cargo/config.toml` does not set it. So the requirement has to be structural,
    /// which is why each of these binaries has exactly one aggregate `#[test]` — the same
    /// reason `tests/heap_zeroize.rs` gives for `all_heap_zeroed`. That reads as style and
    /// will be consolidated away by someone tidying files unless the reason travels with it.
    ///
    /// **One test per binary is still not sufficient on its own.** libtest's default harness
    /// runs even a single test body on a *spawned* thread, with the main thread parked
    /// waiting for it. So the armed window always has another live thread in it. That thread
    /// is blocked and the risk is low — which is worse than high, because it passes for
    /// months and then produces one inexplicable count nobody can reproduce. This flag turns
    /// that silent skew into a named failure: anything deallocating from elsewhere lands in
    /// [`FOREIGN_DEALLOCS`] instead of in the measurement, and each binary asserts that count
    /// is zero. A measurement of zero foreign deallocations taken under `--test-threads=1`
    /// is a fact about that run, not a property of the technique, so it is not inheritable.
    ///
    /// `const`-initialized and `Copy` with no destructor, so no TLS destructor is registered
    /// and `Spy::dealloc` cannot observe it being torn down. [`measure`] sets it *before*
    /// raising `ARMED` and clears it *after* lowering `ARMED`, so on the measuring thread the
    /// TLS block already exists by the time the allocator can read it, and is still valid
    /// when the last armed `dealloc` lands — preserve that ordering if you edit `measure`. A
    /// genuinely foreign thread may touch its own block for the first time inside `dealloc`;
    /// on targets that materialize TLS lazily that can allocate, which is harmless here
    /// because it routes through `alloc`, never back into `dealloc`, so it can neither
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
pub struct Spy;

// SAFETY: every method forwards to `System` with the layout it was given; the counting path
// reads only within `layout.size()` of a block the caller is releasing, and allocates nothing.
unsafe impl GlobalAlloc for Spy {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    /// Deliberately **not** `System.realloc`.
    ///
    /// libc's `realloc` releases the old block inside the C allocator, so it never reaches
    /// `dealloc` and this probe cannot see it — which hides precisely the
    /// reallocation-abandoned blocks the measurement is about. Measured in the harness this
    /// was ported from: forwarding here reported zero dirty blocks for a defect whose
    /// abandoned buffers were already documented and already known to be released.
    ///
    /// The general rule, which cost an afternoon to learn: **a control must release memory
    /// by the same route as the subject.** A zero-on-deallocate allocator that does not
    /// implement `realloc` takes `GlobalAlloc`'s default — allocate, copy, release through
    /// `dealloc` — so mirroring that here keeps the wipe as the only difference between the
    /// three binaries.
    ///
    /// A second consequence worth knowing, because two assertions below rest on it: the old
    /// block is released *after* its replacement has been allocated, so the replacement
    /// cannot be handed back the old block's address. That is what makes "did the buffer
    /// move?" decisive rather than vulnerable to address reuse. `GlobalAlloc`'s default
    /// `realloc`, which the other two configurations use, has the same ordering.
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
        let new_ptr = unsafe { self.alloc(new_layout) };
        if !new_ptr.is_null() {
            let copy = core::cmp::min(layout.size(), new_size);
            unsafe { core::ptr::copy_nonoverlapping(ptr, new_ptr, copy) };
            unsafe { self.dealloc(ptr, layout) };
        }
        new_ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::Relaxed) {
            if on_arming_thread() {
                let hits = unsafe { count_pattern(ptr, layout.size()) };
                BLOCKS.fetch_add(1, Ordering::Relaxed);
                if hits > 0 {
                    PATTERN_BLOCKS.fetch_add(1, Ordering::Relaxed);
                    PATTERN_HITS.fetch_add(hits, Ordering::Relaxed);
                }
            } else {
                // Not ours to measure, and recording it separately is the whole point: a
                // block counted here would otherwise have been folded silently into the
                // numbers above.
                FOREIGN_DEALLOCS.fetch_add(1, Ordering::Relaxed);
            }
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

/// Counts occurrences of [`PATTERN`] in the `len` bytes at `ptr`, at every offset.
///
/// One `u64` sliding window on the stack, one volatile read per byte, no allocation.
/// Volatile because this reads a block the program has finished with, and a plain read would
/// be entitled to disappear.
///
/// # Safety
///
/// `ptr` must be valid for reads of `len` bytes. Called only from `Spy::dealloc`, on a block
/// the caller is in the middle of releasing and which `System` has not been told about yet.
unsafe fn count_pattern(ptr: *const u8, len: usize) -> usize {
    let mut window: u64 = 0;
    let mut hits = 0usize;
    for i in 0..len {
        let byte = unsafe { core::ptr::read_volatile(ptr.add(i)) };
        window = (window << 8) | u64::from(byte);
        if i + 1 >= PATTERN.len() && window == PATTERN_WORD {
            hits += 1;
        }
    }
    hits
}

// ---------------------------------------------------------------------------
// NoWipe — the control that makes a zero a measurement
// ---------------------------------------------------------------------------

/// A wrapper with a zeroizing allocator's composition and **no wipe**.
///
/// The control that turns a subject's `0 hits` from a silence into a measurement.
/// `blocks > 0` shows the counter ran; it does not show the spy reads the bytes it claims
/// to *in the position it claims to*. A spy observing the wrong memory would report clean
/// under the subject and nothing would contradict it — but it would also report clean here,
/// and this must report hits. Contributed by a reviewer who pointed out that a
/// two-configuration version of this harness cannot tell a working wipe from a probe that is
/// looking in the wrong place.
pub struct NoWipe<A: GlobalAlloc>(pub A);

// SAFETY: a pure forwarder; every method passes the caller's arguments through unchanged.
unsafe impl<A: GlobalAlloc> GlobalAlloc for NoWipe<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { self.0.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { self.0.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { self.0.dealloc(ptr, layout) }
    }
    // `realloc` deliberately left to the `GlobalAlloc` default -- allocate, copy, release
    // through `dealloc` -- which is exactly what a zeroizing allocator relies on.
}

// ---------------------------------------------------------------------------
// measure
// ---------------------------------------------------------------------------

/// One armed window's worth of counters.
#[derive(Clone, Copy, Debug)]
pub struct Measurement {
    /// The workload's name, so a binary can report which window these numbers came from.
    pub label: &'static str,
    /// Blocks released on the measuring thread while armed. Zero means a blind probe: a
    /// configuration reporting `pattern_hits == 0` must also report `blocks > 0`, or the
    /// clean result says nothing.
    pub blocks: usize,
    /// How many of those blocks carried at least one occurrence of [`PATTERN`].
    pub pattern_blocks: usize,
    /// Total occurrences of [`PATTERN`] recovered from released blocks.
    pub pattern_hits: usize,
    /// Deallocations seen from any other thread. **Every binary must assert this is zero**;
    /// see [`ON_ARMING_THREAD`] for why a non-zero value invalidates the run rather than
    /// merely annotating it.
    pub foreign_deallocs: usize,
}

/// Runs `f` with the spy counting and reports what was released.
///
/// The ordering here is load-bearing: the thread flag is raised before `ARMED` and lowered
/// after it, so this thread's TLS block exists before the allocator can read it and is still
/// valid when the last armed `dealloc` lands. `println!` allocates, so it happens outside the
/// armed window.
pub fn measure(label: &'static str, f: impl FnOnce()) -> Measurement {
    for counter in [&BLOCKS, &PATTERN_BLOCKS, &PATTERN_HITS, &FOREIGN_DEALLOCS] {
        counter.store(0, Ordering::Relaxed);
    }

    ON_ARMING_THREAD.set(true);
    ARMED.store(true, Ordering::SeqCst);
    f();
    ARMED.store(false, Ordering::SeqCst);
    ON_ARMING_THREAD.set(false);

    let out = Measurement {
        label,
        blocks: BLOCKS.load(Ordering::Relaxed),
        pattern_blocks: PATTERN_BLOCKS.load(Ordering::Relaxed),
        pattern_hits: PATTERN_HITS.load(Ordering::Relaxed),
        foreign_deallocs: FOREIGN_DEALLOCS.load(Ordering::Relaxed),
    };
    println!(
        "{}: released {} blocks, {} carrying the planted pattern, {} pattern occurrences \
         recovered, {} deallocations from other threads",
        out.label, out.blocks, out.pattern_blocks, out.pattern_hits, out.foreign_deallocs
    );
    out
}

// ---------------------------------------------------------------------------
// Workloads — secure-gate's own §2 shapes
// ---------------------------------------------------------------------------

/// Tiles [`PATTERN`] across `buf`, starting at offset 0.
fn plant(buf: &mut [u8]) {
    for (i, byte) in buf.iter_mut().enumerate() {
        *byte = PATTERN[i % PATTERN.len()];
    }
}

/// The address of the secret's backing buffer, so a capacity change can be shown to have
/// moved it.
fn buffer_addr(secret: &mut Dynamic<Vec<u8>>) -> usize {
    secret.with_secret_mut(|v| v.as_ptr().addr())
}

/// **Growth-move** — `SECURITY.md` §2: a 4 KiB secret grown one byte past its capacity
/// through `with_secret_mut`, with an allocated neighbour behind it so the reallocation has
/// to move rather than extend in place. The abandoned block is the hazard: the crate
/// zeroizes the buffer it *holds*, and the one it no longer holds is released outside the
/// crate entirely.
pub fn workload_growth_move() {
    let payload = vec![0u8; SECRET_LEN];

    // Allocated immediately after the payload buffer, so it sits behind it on a fresh heap.
    // `Dynamic::new` then *moves* that buffer in rather than copying it, so the buffer the
    // wrapper holds is the one the neighbour is behind. `Spy` forces the copying path anyway
    // (see `Spy::realloc`), so this neighbour does not decide the outcome — it keeps the
    // workload the same shape as the one SECURITY.md measures, and the assertion below is
    // what actually establishes that a block was abandoned.
    let neighbour = vec![0u8; SECRET_LEN];

    let mut secret: Dynamic<Vec<u8>> = Dynamic::new(payload);
    secret.with_secret_mut(|v| plant(v));
    let before = buffer_addr(&mut secret);

    secret.with_secret_mut(|v| v.push(PATTERN[0]));
    let after = buffer_addr(&mut secret);

    // Assert the abandonment happened. If the buffer did not move there is no abandoned
    // block, the pattern is never released, and a clean count would report success for a run
    // in which nothing happened — a false pass arriving through the workload instead of
    // through the probe. Same discipline as `NoWipe`: establish there was something to find
    // before reporting that you did not find it.
    assert_ne!(
        before, after,
        "growth did not move the buffer, so no block was abandoned and this window measured \
         nothing"
    );

    std::hint::black_box((&secret, &neighbour));
}

/// **Truncate-then-shrink** — `SECURITY.md` §2: a pre-sized 4096-byte buffer truncated to
/// 2048 and then shrunk, which abandons a block holding the live prefix *and* the discarded
/// tail. §2's point is that the property is *capacity-changing*, not growing; a buffer that
/// never grew at all can release its whole contents this way, so omitting this shape would
/// under-test the section.
pub fn workload_truncate_shrink() {
    let mut secret: Dynamic<Vec<u8>> = Dynamic::new(Vec::<u8>::with_capacity(SECRET_LEN));
    secret.with_secret_mut(|v| {
        v.resize(SECRET_LEN, 0);
        plant(v);
    });

    let before = buffer_addr(&mut secret);
    secret.with_secret_mut(|v| {
        v.truncate(SECRET_LEN / 2);
        v.shrink_to_fit();
    });
    let after = buffer_addr(&mut secret);

    // `Vec::shrink_to_fit` is documented as *may* reduce the capacity — whether it
    // reallocates is an allocator and standard-library implementation detail. If it ever
    // declines, nothing is abandoned and a clean count would be a false pass. Require the
    // move rather than assuming it.
    assert_ne!(
        before, after,
        "shrink_to_fit declined to reallocate, so no block was abandoned and this window \
         measured nothing"
    );

    std::hint::black_box(&secret);
}

/// Every workload, so the three binaries stay identical apart from their allocator.
pub const WORKLOADS: [(&str, fn()); 2] = [
    ("growth-move", workload_growth_move as fn()),
    ("truncate-then-shrink", workload_truncate_shrink as fn()),
];
