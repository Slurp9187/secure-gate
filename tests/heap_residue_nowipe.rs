//! CONTROL 2: the wrapper's composition with **no wipe**, so a clean subject means something.
//!
//! `NoWipe<Spy>` has a zeroizing allocator's composition and its `realloc` route, and does
//! not wipe. It therefore differs from `heap_residue_wiped.rs` by exactly one thing, and it
//! is what distinguishes "the wipe worked" from "the probe was not looking".
//!
//! A spy reading the wrong memory, or reading after something else had cleared it, would
//! report clean under the wiped build **and** clean here. It must report the planted pattern
//! here.
//!
//! See `tests/residue_support/mod.rs` for the spy, the workloads and why each binary is
//! exactly one aggregate `#[test]`.
#![cfg(all(feature = "alloc", not(miri)))]

mod residue_support;

use residue_support::{ARMED, NoWipe, PLANTED_HITS, Spy, WORKLOADS, measure};
use std::sync::atomic::Ordering;

#[global_allocator]
static ALLOC: NoWipe<Spy> = NoWipe(Spy);

#[test]
fn the_composed_position_still_sees_the_pattern_when_nothing_wipes() {
    for (label, workload) in WORKLOADS {
        let m = measure(label, workload);
        assert!(
            m.blocks > 0,
            "{label}: no block released -- the workload did not run"
        );
        assert!(
            m.pattern_hits >= PLANTED_HITS,
            "{label}: composed under a non-wiping wrapper, {} blocks released and only {} \
             occurrences of the planted pattern were recovered (expected at least \
             {PLANTED_HITS}). The probe is not observing the position it claims to, so a \
             clean result from heap_residue_wiped.rs proves nothing",
            m.blocks,
            m.pattern_hits
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
