//! Finding 5 regression tests — `SecretBox::init_with` / `try_init_with`
//! must zero the original closure return value on `S::clone()` panic.
//!
//! Pre-fix: the closure return value was a plain `S` on the stack. If
//! `S::clone()` panicked, the original was dropped without zeroization
//! because the `Zeroize` bound alone does not imply zero-on-drop.
//!
//! Post-fix: the closure return value is wrapped in `Zeroizing<S>` before
//! `clone()` is called. A panic in `S::clone()` triggers `Zeroizing::drop`
//! during unwind, which calls `S::zeroize()` on the original.
//!
//! These tests use a custom `S` whose `Clone` impl always panics. A static
//! flag is set when `Zeroize::zeroize` runs on the original. After
//! `catch_unwind` returns, the flag must be set.
//!
//! Note: these tests do NOT cover the residual best-effort window (the
//! stack temporary held by `Box::new` after a successful clone). That window
//! is documented in `init_with`'s rustdoc and is irreducible without
//! tightening the trait bound to `ZeroizeOnDrop` (which would be an API
//! break vs. `secrecy::SecretBox`).

#![cfg(feature = "secrecy-compat")]

use secure_gate_compat::compat::v10::SecretBox;
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroize;

static ORIGINAL_ZEROIZED: AtomicBool = AtomicBool::new(false);

struct PanicOnClone(Vec<u8>);

impl Zeroize for PanicOnClone {
    fn zeroize(&mut self) {
        self.0.zeroize();
        ORIGINAL_ZEROIZED.store(true, Ordering::SeqCst);
    }
}

impl Clone for PanicOnClone {
    fn clone(&self) -> Self {
        panic!("simulated S::clone() failure");
    }
}

#[test]
fn init_with_zeros_original_on_clone_panic() {
    ORIGINAL_ZEROIZED.store(false, Ordering::SeqCst);

    let result = std::panic::catch_unwind(|| {
        let _: SecretBox<PanicOnClone> = SecretBox::init_with(|| PanicOnClone(vec![0xAAu8; 64]));
    });

    assert!(
        result.is_err(),
        "catch_unwind should have captured the clone panic"
    );
    assert!(
        ORIGINAL_ZEROIZED.load(Ordering::SeqCst),
        "Zeroizing<S> must call S::zeroize() on the original during unwind from S::clone() panic"
    );
}

#[test]
fn try_init_with_zeros_original_on_clone_panic() {
    ORIGINAL_ZEROIZED.store(false, Ordering::SeqCst);

    let result = std::panic::catch_unwind(|| {
        let _: Result<SecretBox<PanicOnClone>, ()> =
            SecretBox::try_init_with(|| Ok(PanicOnClone(vec![0xBBu8; 64])));
    });

    assert!(
        result.is_err(),
        "catch_unwind should have captured the clone panic"
    );
    assert!(
        ORIGINAL_ZEROIZED.load(Ordering::SeqCst),
        "Zeroizing<S> must call S::zeroize() on the original during unwind from S::clone() panic in try_init_with"
    );
}
