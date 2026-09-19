//! secure-gate's own workloads for the three residue tests, so the subject and its controls
//! cannot drift apart.
//!
//! `heap_residue.rs`, `heap_residue_nowipe.rs` and `heap_residue_wiped.rs` are each one
//! `residue_binary!` invocation and differ from each other in exactly one argument — the
//! role, which is the `#[global_allocator]` each installs — and everything measured here is
//! secure-gate's own shape. A `#[global_allocator]` is process-wide, so each is its own
//! binary; Cargo builds one per `tests/*.rs`, and a subdirectory like this one is not built
//! as a test.
//!
//! Nothing here tests `secure-gate`. The crate is `#![forbid(unsafe_code)]` and can never
//! install an allocator. What is measured is the hazard `SECURITY.md` §2 documents — a
//! capacity change through `with_secret_mut` reallocates outside the crate, and the
//! abandoned block is freed with the secret still in it — and whether a zero-on-deallocate
//! global allocator, installed the way an application installs one, covers it. This file
//! doubles as the worked example a consumer copies.
//!
//! The spy allocator, the planted pattern, the foreign-thread guard, `measure()` and the
//! `residue_binary!` macro that generates each binary's allocator and its single test all
//! live in `secure-gate-residue-probe` (`residue-probe/`), a dev-dependency of this crate.
//! That crate's own docs cover why the spy reads from offset 0, why it must not allocate,
//! and what a probe of this shape structurally cannot prove (dead-store elimination under an
//! optimizing build) — see `residue-probe/src/lib.rs`. This file is only the two workload
//! shapes and the plumbing to run them against that probe.

#![allow(unreachable_pub, dead_code)]

use secure_gate::{Dynamic, RevealSecretMut};
use secure_gate_residue_probe::plant;

// ---------------------------------------------------------------------------
// Workloads — secure-gate's own §2 shapes
// ---------------------------------------------------------------------------

/// Payload size of the secret in both workloads: 4 KiB, matching `SECURITY.md` §2.
pub const SECRET_LEN: usize = 4096;

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
    // wrapper holds is the one the neighbour is behind. The probe's spy forces the copying
    // path anyway (see `secure_gate_residue_probe::Spy::realloc`), so this neighbour does
    // not decide the outcome — it keeps the workload the same shape as the one
    // SECURITY.md measures, and the assertion below is what actually establishes that a
    // block was abandoned.
    let neighbour = vec![0u8; SECRET_LEN];

    let mut secret: Dynamic<Vec<u8>> = Dynamic::new(payload);
    secret.with_secret_mut(|v| plant(v));
    let before = buffer_addr(&mut secret);

    secret.with_secret_mut(|v| v.push(secure_gate_residue_probe::PATTERN[0]));
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
