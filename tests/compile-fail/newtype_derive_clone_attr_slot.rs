//! `#[derive(Clone)]` through the attribute slot still fails, and now says why.
//!
//! The `derive: [Clone]` argument is refused by name with a full explanation
//! (see `newtype_derive_clone_rejected.rs`). This is the other route to the same
//! place: the macros accept `$(#[$attr:meta])*` before the name so that ordinary
//! `///` comments work, and a `#[derive(Clone)]` smuggled in there never reaches
//! that guard. A `:meta` fragment is opaque once captured, so the macro cannot
//! inspect it and refuse.
//!
//! The gate itself always held — the derive expands to a `Clone` impl that
//! forwards to the wrapper's, which requires `CloneableSecret` on the inner
//! type. What was missing was any explanation: the error was a bare
//! "the trait bound `[u8; 32]: CloneableSecret` is not satisfied", naming a
//! marker the caller had likely never heard of and saying nothing about what to
//! do. The `#[diagnostic::on_unimplemented]` attribute on that trait is what
//! this fixture pins.
//!
//! Note what is *not* covered: with the `cloneable` feature off, the trait and
//! the wrapper's `Clone` impl both cease to exist, so the failure is
//! `Fixed<[u8; 32]>: Clone` and no secure-gate trait appears in the bound chain
//! for a diagnostic to attach to. That case keeps the bare message.
use secure_gate::fixed_newtype;

fixed_newtype!(
    #[derive(Clone)]
    pub EncKey, 32
);

fn main() {}
