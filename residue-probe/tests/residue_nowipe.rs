//! CONTROL 2: the wrapper's composition with **no wipe**, so a clean subject means something.
//!
//! `NoWipe<Spy>` has the subject's composition and its `realloc` route and does not wipe, so
//! it differs from `residue_subject.rs` by exactly one thing. A spy reading the wrong memory
//! would report clean under the subject **and** clean here. It must report the pattern here.

mod residue_support;

secure_gate_residue_probe::residue_binary! {
    nowipe,
    workloads: residue_support::WORKLOADS,
    planted_len: residue_support::SECRET_LEN,
}
