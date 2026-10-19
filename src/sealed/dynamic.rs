use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::prekey::{Prekey, SALT_LEN, TAG_LEN, scrub_stack};
use crate::{Dynamic, RevealSecret};

mod private {
    pub trait Sealed {}
    impl Sealed for alloc::vec::Vec<u8> {}
    impl Sealed for alloc::string::String {}
}

/// The inner types a [`SealedDynamic`] can hold: `Vec<u8>` and `String`. Sealed; it cannot
/// be implemented outside this crate, because sealing needs a byte view of the secret.
pub trait SealedPayload: zeroize::Zeroize + private::Sealed + Sized {
    /// What [`SealedDynamic::with_secret_mut`] hands out: `[u8]` for `Vec<u8>`, `str` for
    /// `String`. Fixed length, so the closure cannot grow the buffer and leave a
    /// reallocated copy of the plaintext behind.
    type Mut: ?Sized;

    #[doc(hidden)]
    fn bytes(&self) -> &[u8];

    #[doc(hidden)]
    fn from_plain(plain: Dynamic<Vec<u8>>) -> Dynamic<Self>;

    #[doc(hidden)]
    fn view_mut(buf: &mut [u8]) -> &mut Self::Mut;
}

impl SealedPayload for Vec<u8> {
    type Mut = [u8];

    fn bytes(&self) -> &[u8] {
        self
    }

    fn from_plain(plain: Dynamic<Vec<u8>>) -> Dynamic<Self> {
        plain
    }

    fn view_mut(buf: &mut [u8]) -> &mut [u8] {
        buf
    }
}

impl SealedPayload for String {
    type Mut = str;

    fn bytes(&self) -> &[u8] {
        self.as_bytes()
    }

    /// Reuses the `Vec`'s buffer; nothing is copied.
    fn from_plain(plain: Dynamic<Vec<u8>>) -> Dynamic<Self> {
        let s = String::from_utf8(plain.into_inner())
            .expect("authenticated plaintext of a sealed String is UTF-8");
        Dynamic::new(s)
    }

    fn view_mut(buf: &mut [u8]) -> &mut str {
        core::str::from_utf8_mut(buf).expect("authenticated plaintext of a sealed String is UTF-8")
    }
}

/// A variable-length secret (`Vec<u8>` or `String`) held encrypted in RAM while idle,
/// opened for one closure call at a time. The sealed counterpart of [`Dynamic`]. Requires
/// the `sealed` feature.
///
/// The ciphertext lives in an exact-size `Box<[u8]>`. Each access decrypts into an
/// exact-capacity [`Dynamic`] that its `Drop` wipes. As with [`SealedFixed`](crate::SealedFixed)
/// there is no `expose_secret` and no [`RevealSecret`] impl.
///
/// ```rust
/// use secure_gate::{Dynamic, Prekey, SealedDynamic};
///
/// let prekey = Prekey::new();
/// let mut pw = SealedDynamic::seal(Dynamic::new(String::from("hunter2")), &prekey);
/// pw.with_secret(|s: &String| assert_eq!(s, "hunter2"));
/// pw.with_secret_mut(|s: &mut str| s.make_ascii_uppercase());
/// pw.with_secret(|s| assert_eq!(s, "HUNTER2"));
/// ```
///
/// # Panics
///
/// Every access panics if the sealed bytes fail to authenticate. The partial plaintext is
/// wiped first.
#[must_use = "holds secret material; bind it or chain a method call"]
pub struct SealedDynamic<T: SealedPayload> {
    ct: Box<[u8]>,
    tag: [u8; TAG_LEN],
    salt: [u8; SALT_LEN],
    prekey: Arc<Prekey>,
    _payload: core::marker::PhantomData<fn() -> T>,
}

impl<T: SealedPayload> SealedDynamic<T> {
    /// Seals `secret` under `prekey`. The plain wrapper is consumed and wiped on drop.
    pub fn seal(secret: Dynamic<T>, prekey: &Arc<Prekey>) -> Self {
        let salt = Prekey::fresh_salt();
        // Held in a wiping buffer until it is ciphertext: if the encrypt panics, the
        // plaintext copy is wiped as it unwinds instead of going back to the allocator.
        let mut buf =
            zeroize::Zeroizing::new(secret.with_secret(|plain| Box::<[u8]>::from(plain.bytes())));
        let tag = prekey.seal_in_place(&salt, &mut buf);
        let ct = core::mem::take(&mut *buf);
        scrub_stack();
        Self {
            ct,
            tag,
            salt,
            prekey: Arc::clone(prekey),
            _payload: core::marker::PhantomData,
        }
    }

    /// Decrypts into a temporary for the length of `f`, then wipes the temporary.
    pub fn with_secret<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&T) -> R,
    {
        let result = {
            let plain = T::from_plain(self.open());
            plain.with_secret(f)
        };
        scrub_stack();
        result
    }

    /// Decrypts into a temporary, lets `f` change it in place, then seals the result under
    /// a fresh salt and wipes the temporary.
    ///
    /// `f` gets `&mut [u8]` or `&mut str`, never `&mut Vec` or `&mut String`: the length is
    /// fixed, so the buffer can never reallocate and abandon an unwiped copy of the
    /// plaintext. To change the length, [`unseal`](Self::unseal), edit, and seal again.
    ///
    /// If `f` panics, the temporary is still wiped and the sealed value is left as it was.
    pub fn with_secret_mut<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut T::Mut) -> R,
    {
        let result = {
            let mut plain = self.open();
            let result =
                crate::RevealSecretMut::with_secret_mut(&mut plain, |buf| f(T::view_mut(buf)));
            let salt = Prekey::fresh_salt();
            plain.with_secret(|p| self.ct.copy_from_slice(p));
            self.tag = self.prekey.seal_in_place(&salt, &mut self.ct);
            self.salt = salt;
            result
        };
        scrub_stack();
        result
    }

    /// Opens the secret back into a plain [`Dynamic`]. Protection from sealing ends here;
    /// the returned wrapper still wipes on drop.
    pub fn unseal(self) -> Dynamic<T> {
        let plain = T::from_plain(self.open());
        scrub_stack();
        plain
    }

    /// The secret's length in bytes. Length can itself be sensitive for passwords; it is
    /// not printed by `Debug`.
    #[inline]
    pub fn len(&self) -> usize {
        self.ct.len()
    }

    /// `true` if the secret is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.ct.is_empty()
    }

    fn open(&self) -> Dynamic<Vec<u8>> {
        Dynamic::<Vec<u8>>::new_with(self.ct.len(), |buf| {
            buf.copy_from_slice(&self.ct);
            self.prekey.open_in_place(&self.salt, &self.tag, buf);
        })
    }
}

impl<T: SealedPayload> crate::scoped::RevealScoped for SealedDynamic<T> {
    type Inner = T;

    #[inline]
    fn with_secret<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&T) -> R,
    {
        SealedDynamic::with_secret(self, f)
    }
}

/// Constant-time equality: opens both sides and compares the plaintext with `subtle`.
/// Unequal lengths compare unequal without opening either side.
#[cfg(feature = "ct-eq")]
impl<T: SealedPayload> crate::ConstantTimeEq for SealedDynamic<T> {
    fn ct_eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }
        self.with_secret(|a| {
            other.with_secret(|b| crate::ConstantTimeEq::ct_eq(a.bytes(), b.bytes()))
        })
    }
}

/// Copies the sealed bytes and shares the pre-key. The copy opens to the same plaintext
/// under the same key and nonce, so no nonce is reused for a second message.
#[cfg(feature = "cloneable")]
impl<T: SealedPayload> Clone for SealedDynamic<T> {
    fn clone(&self) -> Self {
        Self {
            ct: self.ct.clone(),
            tag: self.tag,
            salt: self.salt,
            prekey: Arc::clone(&self.prekey),
            _payload: core::marker::PhantomData,
        }
    }
}

/// Always prints `[REDACTED]`: no salt, no tag, no length.
impl<T: SealedPayload> core::fmt::Debug for SealedDynamic<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ciphertext_is_not_the_plaintext_and_differs_per_seal() {
        let prekey = Prekey::new();
        let a = SealedDynamic::seal(Dynamic::<Vec<u8>>::new(alloc::vec![7u8; 40]), &prekey);
        let b = SealedDynamic::seal(Dynamic::<Vec<u8>>::new(alloc::vec![7u8; 40]), &prekey);
        assert_ne!(&*a.ct, &[7u8; 40][..]);
        assert_ne!(a.salt, b.salt);
        assert_ne!(a.ct, b.ct);
    }

    #[test]
    fn with_secret_mut_reseals_under_a_fresh_salt() {
        let prekey = Prekey::new();
        let mut s = SealedDynamic::seal(Dynamic::<String>::new(String::from("abc")), &prekey);
        let (salt, ct) = (s.salt, s.ct.clone());
        s.with_secret_mut(|p: &mut str| p.make_ascii_uppercase());
        assert_ne!(s.salt, salt);
        assert_ne!(s.ct, ct);
        s.with_secret(|p| assert_eq!(p, "ABC"));
    }

    #[test]
    #[should_panic(expected = "sealed memory was modified or corrupted")]
    fn a_flipped_tag_bit_panics() {
        let prekey = Prekey::new();
        let mut s = SealedDynamic::seal(Dynamic::<Vec<u8>>::new(alloc::vec![1u8; 5]), &prekey);
        s.tag[15] ^= 0x80;
        s.with_secret(|_| ());
    }
}
