//! Assembly-inspection target for DSE (dead-store elimination) verification.
//!
//! This binary exists solely so the integration test `tests/asm_dse_check.rs`
//! can compile it with `--emit=asm` and inspect the resulting assembly for
//! volatile store instructions that prove zeroization survives LLVM optimization.
//!
//! It is NOT a user-facing tool.

use secure_gate::{Fixed, fixed_newtype};

fixed_newtype!(pub NewtypeKey, 32);

/// Creates a `Fixed<[u8; 32]>` initialized with non-zero data, then drops it.
///
/// `#[inline(never)]` ensures LLVM emits a discrete function body we can locate
/// in the assembly output. `#[no_mangle]` makes the symbol name predictable so
/// we don't need rustfilt or any demangling logic in the test harness.
#[inline(never)]
#[unsafe(no_mangle)]
pub fn make_and_drop_fixed() {
    let secret = Fixed::new([0xAAu8; 32]);
    // Prevent LLVM from proving the value is never observed and eliminating
    // the entire allocation (and thus the drop glue) as dead code.
    std::hint::black_box(&secret);
    drop(secret);
}

/// Same shape, but through a `fixed_newtype!`-generated wrapper.
///
/// The newtype is `#[repr(transparent)]` over `Fixed<[u8; 32]>` and adds no
/// `Drop` of its own, so the zeroization guarantee must survive the extra
/// layer unchanged — `tests/asm_dse_check.rs` asserts the same store patterns
/// against this symbol as against `make_and_drop_fixed`.
#[inline(never)]
#[unsafe(no_mangle)]
pub fn make_and_drop_newtype() {
    let secret = NewtypeKey::new([0xAAu8; 32]);
    std::hint::black_box(&secret);
    drop(secret);
}

fn main() {
    make_and_drop_fixed();
    make_and_drop_newtype();
}
