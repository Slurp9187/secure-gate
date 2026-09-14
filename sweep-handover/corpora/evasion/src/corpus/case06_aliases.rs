//! Class 6 — the name at the call site is not the name of the operation.
//!
//! * `Buf` is `Vec<u8>` under another name, so a type-shaped check for `Vec<u8>` misses the closure
//!   parameter's annotation.
//! * `absorb!` is a consumer macro defined in `super::util_bits`. The invocation contains no growth
//!   identifier, and in a real consumer the definition would as likely be in another crate.
//! * `Mutator` holds a function pointer: the call site reads `m.apply(buf, extra)` and which
//!   operation runs is a run-time choice, so no static text names it at all.
//! * `fill_byte_by_byte` is the `new_with` constructor closure — the route the crate offers
//!   precisely so the secret is never in an unprotected buffer. Every reallocation during the fill
//!   abandons one anyway.

use secure_gate::RevealSecretMut;

use super::roles::SessionToken;
use super::util_bits::Put as _;

/// The inner type, renamed.
pub type Buf = std::vec::Vec<u8>;

/// Growth through the macro. The call site names nothing.
pub fn via_macro(tok: &mut SessionToken, extra: &[u8]) {
    tok.with_secret_mut(|buf: &mut Buf| crate::absorb!(buf, extra));
}

/// A late-bound mutation. Which operation runs is a run-time choice.
pub struct Mutator {
    op: fn(&mut Buf, &[u8]),
}

impl Mutator {
    /// The appending strategy.
    pub fn appending() -> Self {
        Self {
            op: super::util_pad::pad,
        }
    }

    /// Applies whatever strategy was installed.
    pub fn apply(&self, target: &mut Buf, material: &[u8]) {
        (self.op)(target, material);
    }
}

/// Growth through a function pointer held in a field.
pub fn via_mutator(tok: &mut SessionToken, m: &Mutator, extra: &[u8]) {
    tok.with_secret_mut(|buf| m.apply(buf, extra));
}

/// One byte at a time, through a consumer trait, inside the protected constructor.
pub fn fill_byte_by_byte(bytes: &[u8]) -> SessionToken {
    SessionToken::new_with(|buf| {
        for &b in bytes {
            buf.put(b);
        }
    })
}
