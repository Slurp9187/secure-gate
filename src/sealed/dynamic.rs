use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::prekey::{Prekey, SALT_LEN, TAG_LEN, scrubbed};
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
        match String::from_utf8(plain.into_inner()) {
            Ok(s) => Dynamic::new(s),
            Err(not_utf8) => {
                // Unreachable for plaintext that authenticated; wipe it before panicking anyway.
                let mut bytes = not_utf8.into_bytes();
                zeroize::Zeroize::zeroize(&mut bytes);
                panic!("authenticated plaintext of a sealed String is UTF-8");
            }
        }
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
/// Every access panics if the sealed bytes fail to authenticate. The temporary is wiped and
/// the stack below the call scrubbed before the panic continues.
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
        let tag = scrubbed(|| prekey.seal_in_place(&salt, &mut buf));
        let ct = core::mem::take(&mut *buf);
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
        scrubbed(|| {
            let plain = T::from_plain(self.open());
            plain.with_secret(f)
        })
    }

    /// Decrypts into a temporary, lets `f` change it in place, then seals the result under
    /// a fresh salt and wipes the temporary.
    ///
    /// `f` gets `&mut [u8]` or `&mut str`, never `&mut Vec` or `&mut String`: the length is
    /// fixed, so the buffer can never reallocate and abandon an unwiped copy of the
    /// plaintext. To change the length, [`unseal`](Self::unseal), edit, and seal again.
    ///
    /// If `f` panics, the temporary is still wiped, the stack scrubbed, and the sealed value
    /// left as it was.
    pub fn with_secret_mut<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut T::Mut) -> R,
    {
        scrubbed(|| {
            let mut plain = self.open();
            let result =
                crate::RevealSecretMut::with_secret_mut(&mut plain, |buf| f(T::view_mut(buf)));
            let salt = Prekey::fresh_salt();
            self.tag = plain.with_secret(|p| self.prekey.seal_into(&salt, p, &mut self.ct));
            self.salt = salt;
            result
        })
    }

    /// Opens the secret back into a plain [`Dynamic`]. Protection from sealing ends here;
    /// the returned wrapper still wipes on drop.
    pub fn unseal(self) -> Dynamic<T> {
        scrubbed(|| T::from_plain(self.open()))
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
        Dynamic::<Vec<u8>>::new_with(self.ct.len(), |buf| self.open_into(buf))
    }

    fn open_into(&self, buf: &mut [u8]) {
        buf.copy_from_slice(&self.ct);
        self.prekey.open_in_place(&self.salt, &self.tag, buf);
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

/// Always prints `[REDACTED]`: no salt, no tag, no length.
impl<T: SealedPayload> core::fmt::Debug for SealedDynamic<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sealed::prekey::tests::quota;

    #[test]
    fn the_ciphertext_is_not_the_plaintext_and_differs_per_seal() {
        let _q = quota();
        let prekey = Prekey::new();
        let a = SealedDynamic::seal(Dynamic::<Vec<u8>>::new(alloc::vec![7u8; 40]), &prekey);
        let b = SealedDynamic::seal(Dynamic::<Vec<u8>>::new(alloc::vec![7u8; 40]), &prekey);
        assert_ne!(&*a.ct, &[7u8; 40][..]);
        assert_ne!(a.salt, b.salt);
        assert_ne!(a.ct, b.ct);
    }

    /// As for `SealedFixed`: a re-seal whose key derivation fails leaves the old
    /// ciphertext, never the new plaintext.
    #[test]
    fn a_failed_reseal_leaves_ciphertext_not_plaintext() {
        let _q = quota();
        let prekey = Prekey::new();
        let mut s = SealedDynamic::seal(Dynamic::<Vec<u8>>::new(vec![0x42u8; 40]), &prekey);
        let before = s.ct.clone();
        let r = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
            s.with_secret_mut(|b| {
                b.fill(0x99);
                crate::sealed::prekey::tests::fail_next_derivation();
            });
        }));
        assert!(r.is_err());
        assert!(
            s.ct.iter().any(|&x| x != 0x99),
            "the new plaintext was left in the ciphertext"
        );
        assert_eq!(s.ct, before);
        s.with_secret(|b| assert_eq!(b.as_slice(), &[0x42u8; 40]));
    }

    #[test]
    fn with_secret_mut_reseals_under_a_fresh_salt() {
        let _q = quota();
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
        let _q = quota();
        let prekey = Prekey::new();
        let mut s = SealedDynamic::seal(Dynamic::<Vec<u8>>::new(alloc::vec![1u8; 5]), &prekey);
        s.tag[15] ^= 0x80;
        s.with_secret(|_| ());
    }
}
