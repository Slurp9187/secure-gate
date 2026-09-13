//! Class 7 — a false `FixedStorage` assertion where the growable field is indirect.
//!
//! `FixedStorage` is a safe marker trait: the consumer asserts "this type owns no buffer whose
//! capacity can change", and nothing checks. The crate documents it as an assertion rather than an
//! enforcement, and the one-level version of this lie (`struct Liar { v: Vec<u8> }` plus
//! `impl FixedStorage for Liar {}`) is the example everybody writes.
//!
//! Here the `Vec` is two structs down. `Credential` holds a `Payload`; `Payload` holds the `Vec`.
//! `impl FixedStorage for Credential {}` sits in a file where the token `Vec` appears nowhere, so a
//! scan that reads the `impl` and then looks at the struct body next to it finds a single `Payload`
//! field and no reason to object.
//!
//! `Fixed<Credential>` then stores the *struct* inline, as advertised, and the secret on the heap —
//! which is exactly the situation `FixedStorage` exists to prevent.

use secure_gate::{Fixed, FixedStorage, RevealSecret, RevealSecretMut};
use zeroize::Zeroize;

/// The indirection. Nothing asserts anything about this type.
pub struct Payload {
    pub material: Vec<u8>,
}

impl Zeroize for Payload {
    fn zeroize(&mut self) {
        self.material.zeroize();
    }
}

/// The type that lies. Its own body mentions no growable container.
pub struct Credential {
    pub payload: Payload,
    pub version: u16,
}

impl Zeroize for Credential {
    fn zeroize(&mut self) {
        self.payload.zeroize();
        self.version = 0;
    }
}

// The assertion. One line, no `Vec` in sight.
impl FixedStorage for Credential {}

/// Builds the wrapper the marker was supposed to make impossible.
pub fn wrap(material: Vec<u8>) -> Fixed<Credential> {
    Fixed::new(Credential {
        payload: Payload { material },
        version: 1,
    })
}

/// Grows the heap buffer inside the "fixed" storage.
pub fn grow(cred: &mut Fixed<Credential>, more: &[u8]) {
    cred.with_secret_mut(|c| super::util_pad::pad(&mut c.payload.material, more));
}

/// Address of the heap buffer, for the instrument.
pub fn material_ptr(cred: &Fixed<Credential>) -> *const u8 {
    cred.with_secret(|c| c.payload.material.as_ptr())
}
