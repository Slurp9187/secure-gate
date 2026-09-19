//! The `inner:` argument on the no-wipe role: `NoWipe<Spy<NoWipe<System>>>`.
//!
//! Same stand-in as `residue_inner_control.rs`, on the other control. Must report exactly
//! what `residue_nowipe.rs` does.

mod residue_support;

use secure_gate_residue_probe::NoWipe;
use std::alloc::System;

secure_gate_residue_probe::residue_binary! {
    nowipe,
    workloads: residue_support::WORKLOADS,
    planted_len: residue_support::SECRET_LEN,
    inner: NoWipe<System> = NoWipe::new(System),
}
