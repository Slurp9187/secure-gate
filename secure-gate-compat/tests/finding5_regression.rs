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
use std::cell::Cell;
use zeroize::Zeroize;

// Thread-local, not a global `AtomicBool`. Both tests in this binary reset the flag,
// run their scenario, then assert it was set; cargo runs them on parallel threads, so
// a shared global let one test's reset land between the other's set and its assert.
// That raced about once per full-workspace run and never in isolation, which is the
// worst shape a failure can have. The panic, the unwind and the `zeroize` call all
// happen on the calling thread -- `catch_unwind` runs its closure inline -- so a
// thread-local is not a workaround, it is the correct scope for the observation.
//
// No inline `const` block: that needs 1.79 and this branch is on 1.70. Modern clippy
// asks for one via `missing_const_for_thread_local`, hence the allow, paired with
// `unknown_lints` because 1.70's clippy predates that name and `-D warnings` would
// otherwise reject the allow itself.
thread_local! {
    #[allow(unknown_lints)] // 1.70's clippy predates the lint named below
    #[allow(clippy::missing_const_for_thread_local)] // `const {}` needs 1.79; MSRV is 1.70
    static ORIGINAL_ZEROIZED: Cell<bool> = Cell::new(false);
}

struct PanicOnClone(Vec<u8>);

impl Zeroize for PanicOnClone {
    fn zeroize(&mut self) {
        self.0.zeroize();
        ORIGINAL_ZEROIZED.with(|f| f.set(true));
    }
}

impl Clone for PanicOnClone {
    fn clone(&self) -> Self {
        panic!("simulated S::clone() failure");
    }
}

#[test]
fn init_with_zeros_original_on_clone_panic() {
    ORIGINAL_ZEROIZED.with(|f| f.set(false));

    let result = std::panic::catch_unwind(|| {
        let _: SecretBox<PanicOnClone> = SecretBox::init_with(|| PanicOnClone(vec![0xAAu8; 64]));
    });

    assert!(
        result.is_err(),
        "catch_unwind should have captured the clone panic"
    );
    assert!(
        ORIGINAL_ZEROIZED.with(|f| f.get()),
        "Zeroizing<S> must call S::zeroize() on the original during unwind from S::clone() panic"
    );
}

#[test]
fn try_init_with_zeros_original_on_clone_panic() {
    ORIGINAL_ZEROIZED.with(|f| f.set(false));

    let result = std::panic::catch_unwind(|| {
        let _: Result<SecretBox<PanicOnClone>, ()> =
            SecretBox::try_init_with(|| Ok(PanicOnClone(vec![0xBBu8; 64])));
    });

    assert!(
        result.is_err(),
        "catch_unwind should have captured the clone panic"
    );
    assert!(
        ORIGINAL_ZEROIZED.with(|f| f.get()),
        "Zeroizing<S> must call S::zeroize() on the original during unwind from S::clone() panic in try_init_with"
    );
}
