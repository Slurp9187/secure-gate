//! SUBJECT: nothing the workloads abandon survives a wipe-on-free allocator.
//!
//! The subject is `residue_support::WipeOnFree`, the smallest allocator that zeroes a block
//! before forwarding it, composed with the spy beneath it. This asserts zero hits, and that
//! is only meaningful because of `residue_control.rs` and `residue_nowipe.rs`.

mod residue_support;

use residue_support::WipeOnFree;
use secure_gate_residue_probe::Spy;
use std::alloc::System;

secure_gate_residue_probe::residue_binary! {
    subject: WipeOnFree<Spy<System>> = WipeOnFree(Spy::new(System)),
    workloads: residue_support::WORKLOADS,
}
