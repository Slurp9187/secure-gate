//! EVASION CORPUS. Every item here contains a REAL instance of the weakness
//! (an abandoned, unwiped heap buffer holding secret bytes) and is written so
//! secure_gate_sweep.py reports nothing.
use secure_gate::{Dynamic, Fixed, FixedStorage, RevealSecret, RevealSecretMut};
use zeroize::Zeroize;

// =====================================================================
// E1  field access through a composite secret held in Dynamic
//     The most idiomatic way to hold a struct-shaped secret. Every
//     mutation goes through a FIELD, and the op regex requires the
//     receiver to be the closure parameter itself.
// =====================================================================
#[derive(Default)]
pub struct Session {
    pub id: [u8; 8],
    pub token: Vec<u8>,
}
impl Zeroize for Session {
    fn zeroize(&mut self) {
        self.id.zeroize();
        self.token.zeroize();
    }
}

pub fn e1_grow(d: &mut Dynamic<Session>, b: u8) {
    d.with_secret_mut(|s| s.token.push(b));
}

// =====================================================================
// E2  rebind the &mut inside the closure
// =====================================================================
pub fn e2_grow(d: &mut Dynamic<Vec<u8>>, b: u8) {
    d.with_secret_mut(|v| {
        let buf = v;
        buf.push(b);
    });
}

// =====================================================================
// E3  UFCS trait call: no leading `.`
// =====================================================================
pub fn e3_grow(d: &mut Dynamic<Vec<u8>>, b: u8) {
    RevealSecretMut::with_secret_mut(d, |v| v.push(b));
}

// =====================================================================
// E4  a named fn item instead of an inline closure
// =====================================================================
fn grow_it(v: &mut Vec<u8>) {
    v.push(0xAA);
}
pub fn e4_grow(d: &mut Dynamic<Vec<u8>>) {
    d.with_secret_mut(grow_it);
}

// =====================================================================
// E5  clone_from: reallocates when the source is longer. Not in the
//     tool's growth vocabulary at all.
// =====================================================================
pub fn e5_grow(d: &mut Dynamic<Vec<u8>>, src: &Vec<u8>) {
    d.with_secret_mut(|v| v.clone_from(src));
}

// =====================================================================
// E6  UFCS method call form
// =====================================================================
pub fn e6_grow(d: &mut Dynamic<Vec<u8>>, b: u8) {
    d.with_secret_mut(|v| Vec::push(v, b));
}

// =====================================================================
// E7  non-ASCII type name: the marker-impl regex anchors on [A-Za-z_]
// =====================================================================
pub struct Ключ {
    pub payload: Vec<u8>,
}
impl Zeroize for Ключ {
    fn zeroize(&mut self) {
        self.payload.zeroize();
    }
}
impl FixedStorage for Ключ {}

pub fn e7_build(payload: Vec<u8>) -> Fixed<Ключ> {
    Fixed::new(Ключ { payload })
}

// =====================================================================
// E8  the growable field hidden behind a plain type alias
// =====================================================================
pub type Blob = Vec<u8>;
pub struct Sneaky {
    pub tag: [u8; 4],
    pub body: Blob,
}
impl Zeroize for Sneaky {
    fn zeroize(&mut self) {
        self.tag.zeroize();
        self.body.zeroize();
    }
}
impl FixedStorage for Sneaky {}

pub fn e8_build(body: Blob) -> Fixed<Sneaky> {
    Fixed::new(Sneaky { tag: [1, 2, 3, 4], body })
}

// =====================================================================
// E9  generic carrier, marker asserted on the growable instantiation
// =====================================================================
pub struct Holder<T>(pub T);
impl<T: Zeroize> Zeroize for Holder<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl FixedStorage for Holder<Vec<u8>> {}

pub fn e9_build(v: Vec<u8>) -> Fixed<Holder<Vec<u8>>> {
    Fixed::new(Holder(v))
}

// =====================================================================
// E10 helper fn reached from the closure (documented blind spot, counted)
// =====================================================================
fn helper(v: &mut Vec<u8>, b: u8) {
    v.reserve(64);
    v.push(b);
}
pub fn e10_grow(d: &mut Dynamic<Vec<u8>>, b: u8) {
    d.with_secret_mut(|v| helper(v, b));
}

// =====================================================================
// E11 renamed import (documented blind spot, counted)
// =====================================================================
use secure_gate::Dynamic as Buf;
pub fn e11_grow(d: &mut Buf<Vec<u8>>, b: u8) {
    let v = d.expose_secret_mut();
    let r = &mut *v;
    r.push(b);
}

// read-side helpers so the tests can measure
pub fn e1_cap(d: &Dynamic<Session>) -> (usize, *const u8) {
    d.with_secret(|s| (s.token.capacity(), s.token.as_ptr()))
}
