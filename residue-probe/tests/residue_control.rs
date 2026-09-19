//! CONTROL 1: the planted pattern **is** released when nothing wipes.
//!
//! One of the binaries that differ only in their role argument to `residue_binary!`. This
//! one establishes there is something to find; without it a clean result from
//! `residue_subject.rs` is equally consistent with the wipe working, the blocks never being
//! released, or the workload never running.

mod residue_support;

secure_gate_residue_probe::residue_binary! {
    control,
    workloads: residue_support::WORKLOADS,
    planted_len: residue_support::SECRET_LEN,
}
