//! FALSE-POSITIVE CORPUS. Everything here is CORRECT, idiomatic consumer code
//! that abandons no unwiped buffer. Anything the sweep reports on this file is a
//! product defect.
use secure_gate::{dynamic_newtype, Dynamic, Fixed, FixedStorage, RevealSecret, RevealSecretMut};
use zeroize::Zeroize;

// ---------------------------------------------------------------- FP1
// A struct with NO growable field. The only occurrence of the word "Vec" in the
// declaration is a doc comment explaining that there is no Vec.
pub struct AesKey {
    /// Exactly 32 bytes, inline. Deliberately not a Vec<u8>: no capacity can change.
    pub bytes: [u8; 32],
}
impl Zeroize for AesKey {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}
impl FixedStorage for AesKey {}

pub fn fp1() -> Fixed<AesKey> {
    Fixed::new(AesKey { bytes: [7u8; 32] })
}

// ---------------------------------------------------------------- FP2
// Rotating a fixed-size key in place. No heap, nothing to abandon.
pub fn fp2_rotate(k: &mut Fixed<[u8; 32]>, new: [u8; 32]) {
    k.with_secret_mut(|v| *v = new);
}

// ---------------------------------------------------------------- FP3
// A monotonic secret counter in inline storage.
pub fn fp3_bump(c: &mut Fixed<u64>) {
    c.with_secret_mut(|n| *n += 1);
}

// ---------------------------------------------------------------- FP4
// A fixed-capacity inline buffer: `push` here CANNOT allocate. This is the
// standard no_std shape.
pub struct ArrayBuf {
    data: [u8; 64],
    len: usize,
}
impl ArrayBuf {
    pub fn push(&mut self, b: u8) -> Result<(), ()> {
        if self.len == 64 {
            return Err(());
        }
        self.data[self.len] = b;
        self.len += 1;
        Ok(())
    }
}
impl Zeroize for ArrayBuf {
    fn zeroize(&mut self) {
        self.data.zeroize();
        self.len = 0;
    }
}
impl FixedStorage for ArrayBuf {}

pub fn fp4_append(b: &mut Fixed<ArrayBuf>, byte: u8) {
    b.with_secret_mut(|v| {
        let _ = v.push(byte);
    });
}

// ---------------------------------------------------------------- FP5
// Refill a growable secret the safe way: wipe the whole buffer (contents AND
// spare capacity) before any growth can abandon it.
pub fn fp5_refill(d: &mut Dynamic<Vec<u8>>, new: &[u8]) {
    d.with_secret_mut(|v| {
        v.zeroize();
        v.extend_from_slice(new);
    });
}

// ---------------------------------------------------------------- FP6
// The tool's own recommended mitigation: hold the source in zeroize::Zeroizing.
pub fn fp6_from_zeroizing(src: &zeroize::Zeroizing<Vec<u8>>) -> Dynamic<Vec<u8>> {
    Dynamic::from(src.as_slice())
}

// ---------------------------------------------------------------- FP7
// A public RFC test vector. Not a credential; there is no caller buffer.
pub fn fp7_rfc4231_key() -> Dynamic<Vec<u8>> {
    Dynamic::from(&[0x0bu8; 20][..])
}

// ---------------------------------------------------------------- FP8
// A machine identifier. Not a secret. "MachineId" contains the substring "mac".
dynamic_newtype!(
    pub MachineIdBlock,
    generic Vec<u32>,
    "An opaque, non-secret machine identifier block.",
    derive: [WrapperAccess]
);

// ---------------------------------------------------------------- FP9
// An author name cache. Not a secret. "Author" contains the substring "auth".
dynamic_newtype!(
    pub AuthorTagBlock,
    generic Vec<u32>,
    "A public author tag block.",
    derive: [WrapperAccess]
);

// ---------------------------------------------------------------- FP10
// One readability alias, used once, in a private module.
mod internal {
    pub type KeyBytes = secure_gate::Fixed<[u8; 32]>;
    pub fn zero() -> KeyBytes {
        secure_gate::Fixed::new([0u8; 32])
    }
}
pub use internal::zero;

// ---------------------------------------------------------------- FP11
// Single bulk write into a fresh buffer: one allocation, nothing abandoned.
pub fn fp11(src: &[u8]) -> Dynamic<Vec<u8>> {
    Dynamic::<Vec<u8>>::new_with(|v| {
        v.extend_from_slice(src);
    })
}

// read helper
pub fn fp5_len(d: &Dynamic<Vec<u8>>) -> usize {
    d.with_secret(|v| v.len())
}

pub fn make_arraybuf() -> ArrayBuf {
    ArrayBuf { data: [0xC3u8; 64], len: 0 }
}
