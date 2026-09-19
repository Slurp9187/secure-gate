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
//! See `tests/residue_support/mod.rs` for the workloads, and `residue_binary!`'s own
//! documentation for what the invocation expands to and why each binary is exactly one
//! aggregate `#[test]`.
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

use secure_gate_residue_probe::Spy;
use std::alloc::System;
use zeroizing_alloc::ZeroAlloc;

secure_gate_residue_probe::residue_binary! {
    subject: ZeroAlloc<Spy<System>> = ZeroAlloc(Spy::new(System)),
    workloads: residue_support::WORKLOADS,
}
