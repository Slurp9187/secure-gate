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
//! See `tests/residue_support/mod.rs` for the workloads, and `residue_binary!`'s own
//! documentation for what the invocation expands to and why each binary is exactly one
//! aggregate `#[test]`.
#![cfg(all(feature = "alloc", not(miri)))]

mod residue_support;

secure_gate_residue_probe::residue_binary! {
    nowipe,
    workloads: residue_support::WORKLOADS,
    planted_len: residue_support::SECRET_LEN,
}
