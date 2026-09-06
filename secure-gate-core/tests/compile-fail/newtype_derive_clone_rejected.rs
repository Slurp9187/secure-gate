//! `derive: [Clone]` must be rejected with an explanatory error.
//!
//! Cloning a secret cannot be forwarded — the wrapper's `Clone` requires
//! `CloneableSecret` on the inner type, which downstream crates cannot
//! implement — so a generated impl would route around the opt-in marker
//! system. Callers who want it write the impl by hand, in their own code.
use secure_gate::{Fixed, __sg_newtype_base};

__sg_newtype_base!(pub EncKey(Fixed<[u8; 32]>), derive: [Clone]);

fn main() {}
