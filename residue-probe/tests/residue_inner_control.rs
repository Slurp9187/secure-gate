//! The `inner:` argument on the control role: the spy on an allocator other than `System`.
//!
//! `NoWipe<System>` stands in for "some other allocator", being the only one a
//! dependency-free crate has to hand. Composed as `Spy<NoWipe<System>>` this must report
//! exactly what `residue_control.rs` does.

mod residue_support;

use secure_gate_residue_probe::NoWipe;
use std::alloc::System;

secure_gate_residue_probe::residue_binary! {
    control,
    workloads: residue_support::WORKLOADS,
    planted_len: residue_support::SECRET_LEN,
    inner: NoWipe<System> = NoWipe::new(System),
}
