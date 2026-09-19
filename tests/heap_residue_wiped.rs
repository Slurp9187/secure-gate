//! SUBJECT: nothing secure-gate's §2 hazard abandons survives a zeroizing global allocator.
//!
//! The same probe as `heap_residue.rs`, composed under `zeroizing-alloc`'s `ZeroAlloc`.
//! `ZeroAlloc::dealloc` wipes and then forwards, so the spy beneath it observes each block
//! after the wipe and before the system allocator is told about it.
//!
//! **This asserts zero hits, and that is only meaningful because of the two controls.**
//! `heap_residue.rs` establishes the pattern exists to find; `heap_residue_nowipe.rs`
//! establishes the probe sees it in *this* position. Read all three or none.
//!
//! See `tests/residue_support/mod.rs` for the spy, the workloads and why each binary is
//! exactly one aggregate `#[test]`.
//!
//! # What this does not test
//!
//! Whether the wipe survives an optimizer. The volatile read that makes this measurement
//! possible is exactly what keeps the store it observes live, so a runtime probe of this
//! shape is structurally incapable of detecting dead-store elimination — and `cargo test` is
//! opt-level 0 besides. That question is answered separately, under PGO and fat LTO, by
//! `tools/pgo_allocator_compare.sh`, with the captured run recorded in
//! `docs/design/receipts/`. The two claims are not the same sentence and should not be
//! merged into one.
#![cfg(all(feature = "alloc", not(miri)))]

mod residue_support;

use residue_support::{ARMED, Spy, WORKLOADS, measure};
use std::sync::atomic::Ordering;
use zeroizing_alloc::ZeroAlloc;

#[global_allocator]
static ALLOC: ZeroAlloc<Spy> = ZeroAlloc(Spy);

#[test]
fn nothing_the_hazard_abandons_survives_the_wipe() {
    for (label, workload) in WORKLOADS {
        let m = measure(label, workload);
        assert_eq!(
            m.pattern_hits, 0,
            "{label}: {} of {} released blocks still carried the planted pattern ({} \
             occurrences)",
            m.pattern_blocks, m.blocks, m.pattern_hits
        );
        assert!(
            m.blocks > 0,
            "{label}: zero pattern hits with zero blocks inspected is a blind probe, not a \
             wipe"
        );
        assert_eq!(
            m.foreign_deallocs, 0,
            "{label}: {} deallocations arrived from a thread other than the one that armed \
             the gate; the measurement above is not trustworthy",
            m.foreign_deallocs
        );
    }
    assert!(
        !ARMED.load(Ordering::SeqCst),
        "gate left armed after the loop"
    );
}
