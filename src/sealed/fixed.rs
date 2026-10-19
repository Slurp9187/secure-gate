use alloc::sync::Arc;

use super::prekey::{Prekey, SALT_LEN, TAG_LEN, scrub_stack};
use crate::{Fixed, RevealSecret, RevealSecretMut};

/// A fixed-size byte secret held encrypted in RAM while idle, opened for one closure call
/// at a time. The sealed counterpart of [`Fixed<[u8; N]>`](Fixed). Requires the `sealed`
/// feature.
///
/// The ciphertext, tag and salt sit inline and are not secret. Each access derives the
/// sealing key from the [`Prekey`], decrypts in place into a stack [`Fixed<[u8; N]>`](Fixed),
/// hands the closure a reference, and lets that wrapper's `Drop` wipe it. Nothing is
/// allocated per access.
///
/// There is no `expose_secret`, and the type does not implement [`RevealSecret`]: a
/// reference that outlives the call would need plaintext that outlives it too, which is
/// what sealing exists to prevent. Generic code that only needs scoped access can take
/// [`RevealScoped`](crate::scoped::RevealScoped), which this type and every
/// `RevealSecret` type implement.
///
/// ```rust
/// use secure_gate::{Fixed, Prekey, SealedFixed};
///
/// let prekey = Prekey::new();
/// let key = SealedFixed::seal(Fixed::new([0xAB; 32]), &prekey);
/// key.with_secret(|bytes| assert_eq!(bytes[0], 0xAB));
/// assert_eq!(format!("{key:?}"), "[REDACTED]");
/// ```
///
/// # Panics
///
/// Every access panics if the sealed bytes fail to authenticate: they were modified or
/// corrupted in memory and cannot be recovered. The partial plaintext is wiped first.
#[must_use = "holds secret material; bind it or chain a method call"]
pub struct SealedFixed<const N: usize> {
    ct: [u8; N],
    tag: [u8; TAG_LEN],
    salt: [u8; SALT_LEN],
    prekey: Arc<Prekey>,
}

impl<const N: usize> SealedFixed<N> {
    /// Seals `secret` under `prekey`. The plain wrapper is consumed and wiped on drop.
    pub fn seal(secret: Fixed<[u8; N]>, prekey: &Arc<Prekey>) -> Self {
        let salt = Prekey::fresh_salt();
        let mut ct = [0u8; N];
        secret.with_secret(|plain| ct.copy_from_slice(plain));
        let tag = prekey.seal_in_place(&salt, &mut ct);
        scrub_stack();
        Self {
            ct,
            tag,
            salt,
            prekey: Arc::clone(prekey),
        }
    }

    /// Generates the secret from the system RNG and seals it.
    ///
    /// # Panics
    ///
    /// Panics if the system RNG fails, as [`Fixed::from_random`] does.
    pub fn from_random(prekey: &Arc<Prekey>) -> Self {
        Self::seal(Fixed::from_random(), prekey)
    }

    /// Decrypts into a temporary for the length of `f`, then wipes the temporary.
    #[inline]
    pub fn with_secret<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[u8; N]) -> R,
    {
        let result = self.open_and_call(f);
        scrub_stack();
        result
    }

    // The plaintext temporary lives in this frame, below the caller's, so the
    // `scrub_stack` that follows lies over it and over anything a move left there. It is
    // built as zeros and decrypted in place: a `Fixed` returned by value would be moved,
    // leaving an unwiped copy in the slot it left.
    #[inline(never)]
    fn open_and_call<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[u8; N]) -> R,
    {
        let mut plain = Fixed::new([0u8; N]);
        plain.with_secret_mut(|buf| self.open_into(buf));
        plain.with_secret(f)
    }

    /// Decrypts into a temporary, lets `f` change it, then seals the result under a fresh
    /// salt and wipes the temporary.
    ///
    /// If `f` panics, the temporary is still wiped and the sealed value is left as it was.
    pub fn with_secret_mut<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8; N]) -> R,
    {
        let result = self.open_mutate_reseal(f);
        scrub_stack();
        result
    }

    // As `open_and_call`: the temporary lives in this frame so the scrub reaches it.
    #[inline(never)]
    fn open_mutate_reseal<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8; N]) -> R,
    {
        let mut plain = Fixed::new([0u8; N]);
        plain.with_secret_mut(|buf| self.open_into(buf));
        let result = plain.with_secret_mut(f);
        let salt = Prekey::fresh_salt();
        plain.with_secret(|p| self.ct.copy_from_slice(p));
        self.tag = self.prekey.seal_in_place(&salt, &mut self.ct);
        self.salt = salt;
        result
    }

    /// Opens into a temporary, hands it to `wrap` (a `fixed_newtype!` role's constructor)
    /// and `f` gets the wrapped value; scrubbed like [`with_secret`](Self::with_secret).
    /// The plumbing behind `sealed_fixed_newtype!`'s `with_role`; not a public API.
    #[doc(hidden)]
    #[inline]
    pub fn __with_wrapped<T, W, F, R>(&self, wrap: W, f: F) -> R
    where
        W: FnOnce(Fixed<[u8; N]>) -> T,
        F: FnOnce(&T) -> R,
    {
        let result = self.open_wrap_call(wrap, f);
        scrub_stack();
        result
    }

    // The move into `wrap` copies the plaintext within this frame, which the scrub covers.
    #[inline(never)]
    fn open_wrap_call<T, W, F, R>(&self, wrap: W, f: F) -> R
    where
        W: FnOnce(Fixed<[u8; N]>) -> T,
        F: FnOnce(&T) -> R,
    {
        let mut plain = Fixed::new([0u8; N]);
        plain.with_secret_mut(|buf| self.open_into(buf));
        let wrapped = wrap(plain);
        f(&wrapped)
    }

    /// As [`__with_wrapped`](Self::__with_wrapped), mutably; `unwrap` gives the `Fixed` back
    /// to re-seal under a fresh salt. Not a public API.
    #[doc(hidden)]
    #[inline]
    pub fn __with_wrapped_mut<T, W, U, F, R>(&mut self, wrap: W, unwrap: U, f: F) -> R
    where
        W: FnOnce(Fixed<[u8; N]>) -> T,
        U: FnOnce(T) -> Fixed<[u8; N]>,
        F: FnOnce(&mut T) -> R,
    {
        let result = self.open_wrap_mutate_reseal(wrap, unwrap, f);
        scrub_stack();
        result
    }

    #[inline(never)]
    fn open_wrap_mutate_reseal<T, W, U, F, R>(&mut self, wrap: W, unwrap: U, f: F) -> R
    where
        W: FnOnce(Fixed<[u8; N]>) -> T,
        U: FnOnce(T) -> Fixed<[u8; N]>,
        F: FnOnce(&mut T) -> R,
    {
        let mut plain = Fixed::new([0u8; N]);
        plain.with_secret_mut(|buf| self.open_into(buf));
        let mut wrapped = wrap(plain);
        let result = f(&mut wrapped);
        let plain = unwrap(wrapped);
        let salt = Prekey::fresh_salt();
        plain.with_secret(|p| self.ct.copy_from_slice(p));
        self.tag = self.prekey.seal_in_place(&salt, &mut self.ct);
        self.salt = salt;
        result
    }

    /// Opens the secret back into a plain [`Fixed`]. Protection from sealing ends here;
    /// the returned wrapper still wipes on drop.
    pub fn unseal(self) -> Fixed<[u8; N]> {
        let mut plain = Fixed::new([0u8; N]);
        plain.with_secret_mut(|buf| self.open_into(buf));
        scrub_stack();
        plain
    }

    /// The secret's length in bytes, `N`.
    #[inline(always)]
    pub const fn len(&self) -> usize {
        N
    }

    /// `true` only for `SealedFixed<0>`.
    #[inline(always)]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    #[inline(always)]
    fn open_into(&self, buf: &mut [u8; N]) {
        buf.copy_from_slice(&self.ct);
        self.prekey.open_in_place(&self.salt, &self.tag, buf);
    }
}

impl<const N: usize> crate::scoped::RevealScoped for SealedFixed<N> {
    type Inner = [u8; N];

    #[inline]
    fn with_secret<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[u8; N]) -> R,
    {
        SealedFixed::with_secret(self, f)
    }
}

/// Constant-time equality: opens both sides and compares the plaintext with `subtle`.
/// Comparing ciphertexts could not work, since every seal has its own salt.
#[cfg(feature = "ct-eq")]
impl<const N: usize> crate::ConstantTimeEq for SealedFixed<N> {
    fn ct_eq(&self, other: &Self) -> bool {
        self.with_secret(|a| other.with_secret(|b| crate::ConstantTimeEq::ct_eq(a, b)))
    }
}

/// Copies the sealed bytes and shares the pre-key. The copy opens to the same plaintext
/// under the same key and nonce, so no nonce is reused for a second message.
#[cfg(feature = "cloneable")]
impl<const N: usize> Clone for SealedFixed<N> {
    fn clone(&self) -> Self {
        Self {
            ct: self.ct,
            tag: self.tag,
            salt: self.salt,
            prekey: Arc::clone(&self.prekey),
        }
    }
}

/// Always prints `[REDACTED]`: no salt, no tag, no length.
impl<const N: usize> core::fmt::Debug for SealedFixed<N> {
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
        let a = SealedFixed::seal(Fixed::new([0x42u8; 32]), &prekey);
        let b = SealedFixed::seal(Fixed::new([0x42u8; 32]), &prekey);
        assert_ne!(a.ct, [0x42u8; 32]);
        assert_ne!(a.salt, b.salt);
        assert_ne!(a.ct, b.ct);
    }

    #[test]
    fn with_secret_mut_reseals_under_a_fresh_salt() {
        let prekey = Prekey::new();
        let mut s = SealedFixed::seal(Fixed::new([1u8; 16]), &prekey);
        let (salt, ct) = (s.salt, s.ct);
        s.with_secret_mut(|_| {});
        assert_ne!(s.salt, salt);
        assert_ne!(s.ct, ct);
        s.with_secret(|p| assert_eq!(p, &[1u8; 16]));
    }

    #[test]
    #[should_panic(expected = "sealed memory was modified or corrupted")]
    fn a_flipped_ciphertext_bit_panics() {
        let prekey = Prekey::new();
        let mut s = SealedFixed::seal(Fixed::new([1u8; 32]), &prekey);
        s.ct[3] ^= 0x10;
        s.with_secret(|_| ());
    }

    #[test]
    #[should_panic(expected = "sealed memory was modified or corrupted")]
    fn a_flipped_salt_bit_panics() {
        let prekey = Prekey::new();
        let mut s = SealedFixed::seal(Fixed::new([1u8; 32]), &prekey);
        s.salt[31] ^= 1;
        let _ = s.unseal();
    }
}
