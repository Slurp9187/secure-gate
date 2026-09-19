//! CONTROL: secure-gate's own §2 hazard abandons the planted pattern with no wiping allocator.
//!
//! One of three binaries that differ only in their role argument to `residue_binary!`, which
//! is to say in their `#[global_allocator]`:
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
//! See `tests/residue_support/mod.rs` for the workloads, and `residue_binary!`'s own
//! documentation for what the invocation expands to and why each binary is exactly one
//! aggregate `#[test]`.
#![cfg(all(feature = "alloc", not(miri)))]

mod residue_support;

secure_gate_residue_probe::residue_binary! {
    control,
    workloads: residue_support::WORKLOADS,
    planted_len: residue_support::SECRET_LEN,
}
