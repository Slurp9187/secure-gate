//! `fixed_newtype!` must reject `N = 0` at the declaration.
//!
//! A zero-byte secret is valid Rust but has no cryptographic utility. `Fixed`
//! also refuses to construct one, but that fires at the first construction;
//! this guard fires here, on the declaration, which is the earlier report.
use secure_gate::fixed_newtype;

fixed_newtype!(pub Bad, 0);

fn main() {}
