//! Assembly-inspection target for DSE (dead-store elimination) verification.
//!
//! This binary exists solely so the integration test `tests/asm_dse_check.rs`
//! can compile it with `--emit=asm` and inspect the resulting assembly for
//! volatile store instructions that prove zeroization survives LLVM optimization.
//!
//! It is NOT a user-facing tool.

use secure_gate::Fixed;

/// Creates a `Fixed<[u8; 32]>` initialized with non-zero data, then drops it.
///
/// `#[inline(never)]` ensures LLVM emits a discrete function body we can locate
/// in the assembly output. `#[no_mangle]` makes the symbol name predictable so
/// we don't need rustfilt or any demangling logic in the test harness.
#[inline(never)]
#[no_mangle]
pub fn make_and_drop_fixed() {
    let secret = Fixed::new([0xAAu8; 32]);
    // Prevent LLVM from proving the value is never observed and eliminating
    // the entire allocation (and thus the drop glue) as dead code.
    std::hint::black_box(&secret);
    drop(secret);
}

fn main() {
    make_and_drop_fixed();
}
