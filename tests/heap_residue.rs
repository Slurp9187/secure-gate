//! CONTROL: secure-gate's own §2 hazard abandons the planted pattern with no wiping allocator.
//!
//! One of three binaries that differ only in their `#[global_allocator]`:
//!
//! | binary | allocator | asserts |
//! |---|---|---|
//! | `heap_residue.rs` | bare `Spy` | the planted pattern **is** released |
//! | `heap_residue_nowipe.rs` | `NoWipe<Spy>` | the probe sees it *in the composed position* |
//! | `heap_residue_wiped.rs` | `ZeroAlloc<Spy>` | none of it survives |
//!
//! This one establishes that there is something to wipe. Without it a clean result from
//! `heap_residue_wiped.rs` is equally consistent with the wipe working, the blocks never
//! being released, or the workload never running — which is why it asserts rather than
//! reports.
//!
//! See `tests/residue_support/mod.rs` for the spy, the workloads and why each binary is
//! exactly one aggregate `#[test]`.
#![cfg(all(feature = "alloc", not(miri)))]

mod residue_support;

use residue_support::{SECRET_LEN, WORKLOADS};
use secure_gate_residue_probe::{Spy, is_armed, measure, planted_hits};
use std::alloc::System;

#[global_allocator]
static ALLOC: Spy<System> = Spy::new(System);

#[test]
fn planted_pattern_is_released_with_no_wiping_allocator() {
    let expected_hits = planted_hits(SECRET_LEN);
    for (label, workload) in WORKLOADS {
        let m = measure(label, workload);
        assert!(
            m.blocks > 0,
            "{label}: no block released -- the workload did not run"
        );
        assert!(
            m.pattern_hits >= expected_hits,
            "{label}: {} blocks released and only {} occurrences of the planted pattern were \
             recovered (expected at least {expected_hits}): this probe is no longer observing \
             what it believes it is, so a clean result from heap_residue_wiped.rs would be \
             UNTESTED",
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
    assert!(!is_armed(), "gate left armed after the loop");
}
