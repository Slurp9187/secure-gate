//! The pre-key: 16 KiB of random bytes every sealing key is derived from.

use alloc::sync::Arc;

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use rand::{TryRng, rngs::SysRng};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::{Fixed, RevealSecret};

/// Size of the pre-key in bytes: four 4 KiB pages, 131,072 bits.
pub(crate) const PREKEY_LEN: usize = 16 * 1024;

/// Size of the detached ChaCha20-Poly1305 tag stored beside each ciphertext.
pub(crate) const TAG_LEN: usize = 16;

/// Size of the random salt drawn for every seal.
pub(crate) const SALT_LEN: usize = 32;

/// The pre-key's storage. Aligned to its own size, so it starts on a page boundary and
/// fills whole pages on both 4 KiB- and 16 KiB-page systems: locking it locks nothing
/// else, and unlocking it on drop cannot unlock a neighbor's pages.
#[repr(C, align(16384))]
struct Block([u8; PREKEY_LEN]);

/// Why the pre-key's pages are not locked in RAM. Returned by [`Prekey::lock_status`].
///
/// Not fatal: the sealed types work the same either way. What is lost is the guarantee
/// that the pre-key never reaches the swap file. On Windows the usual cause is the
/// process working-set quota, which every `VirtualLock` in the process shares; on Unix it
/// is `RLIMIT_MEMLOCK`.
///
/// Carries the operating system's error code, never an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockError {
    os_code: Option<i32>,
}

impl LockError {
    fn from_region(err: &region::Error) -> Self {
        let os_code = match err {
            region::Error::SystemCall(code) | region::Error::MachCall(code) => Some(*code),
            _ => None,
        };
        Self { os_code }
    }

    /// The operating system's error code (`GetLastError` on Windows, `errno` on Unix), when
    /// the failure came from a system call.
    pub fn raw_os_error(&self) -> Option<i32> {
        self.os_code
    }
}

impl core::fmt::Display for LockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.os_code {
            Some(code) => write!(
                f,
                "the sealed-memory pre-key could not be locked in RAM (OS error {code})"
            ),
            None => f.write_str("the sealed-memory pre-key could not be locked in RAM"),
        }
    }
}

impl std::error::Error for LockError {}

/// The 16 KiB of random bytes that every sealing key is derived from, locked in RAM where
/// the operating system allows it.
///
/// Each [`SealedFixed`](crate::SealedFixed) and [`SealedDynamic`](crate::SealedDynamic)
/// keeps an `Arc` to the `Prekey` it was sealed under and derives its key afresh on every
/// access as `SHA-256(salt ‖ pre-key)`. The key itself is never stored. A lossy readout of
/// memory (Spectre-class side channels, Rowhammer, cold boot) that gets any one of the
/// pre-key's 131,072 bits wrong yields a useless key, with nothing to say which bit was
/// wrong. See the [`sealed`](crate::sealed) module for the whole threat model.
///
/// # Lifetime
///
/// The pre-key is not a `static`. It lives as long as the last sealed object, or the last
/// other `Arc`, that refers to it. When that one drops, the pre-key is wiped while its pages
/// are still locked, then unlocked, then freed. An application typically holds one `Prekey`
/// for a session and drops it, along with everything sealed under it, at lock or logout.
///
/// # Locking
///
/// [`new`](Self::new) asks the operating system to keep the pre-key's pages out of swap
/// (`VirtualLock` on Windows, `mlock` on Unix) and never fails because it could not:
/// [`lock_status`](Self::lock_status) reports the outcome so the caller can decide. Locking
/// covers swap only. Hibernation, crash and core dumps, and a clean read of the process's
/// memory (a debugger, `/proc/<pid>/mem`) all still see the pre-key.
///
/// # Fork
///
/// A child created by `fork()` shares the parent's pre-key bytes (copy-on-write) but not
/// its page locks. A child that should not hold the parent's sealing material creates its
/// own `Prekey` and re-seals what it keeps.
pub struct Prekey {
    // Field order matters only for the default drop; `Drop` below sequences it explicitly.
    block: alloc::boxed::Box<Block>,
    lock: Option<region::LockGuard>,
    lock_error: Option<LockError>,
}

impl Prekey {
    /// Generates a pre-key from the system RNG and tries to lock its pages in RAM.
    ///
    /// Returns an `Arc`, because every sealed object keeps one.
    ///
    /// # Panics
    ///
    /// Panics if the system RNG fails, as [`Fixed::from_random`] does. A failure to lock
    /// is not a panic; see [`lock_status`](Self::lock_status).
    pub fn new() -> Arc<Self> {
        let mut block = alloc::boxed::Box::new(Block([0u8; PREKEY_LEN]));
        SysRng
            .try_fill_bytes(&mut block.0)
            .expect("SysRng failure is a program error");
        let (lock, lock_error) = match region::lock(block.0.as_ptr(), PREKEY_LEN) {
            Ok(guard) => (Some(guard), None),
            Err(err) => (None, Some(LockError::from_region(&err))),
        };
        Arc::new(Self {
            block,
            lock,
            lock_error,
        })
    }

    /// `Ok(())` if the pre-key's pages are locked in RAM; otherwise why they are not.
    pub fn lock_status(&self) -> Result<(), LockError> {
        match self.lock_error {
            None => Ok(()),
            Some(err) => Err(err),
        }
    }

    /// `SHA-256(salt ‖ pre-key)`, written straight into a wrapper that wipes it on drop.
    #[inline]
    fn sealing_key(&self, salt: &[u8; SALT_LEN]) -> Fixed<[u8; 32]> {
        Fixed::new_with(|key: &mut [u8; 32]| {
            let mut hasher = Sha256::new();
            hasher.update(salt);
            hasher.update(&self.block.0);
            hasher.finalize_into(key.into());
        })
    }

    #[inline]
    fn cipher(&self, salt: &[u8; SALT_LEN]) -> ChaCha20Poly1305 {
        self.sealing_key(salt)
            .with_secret(|key| ChaCha20Poly1305::new(key.into()))
    }

    /// A fresh random salt, and so a fresh sealing key. Drawn before any plaintext is
    /// copied into a ciphertext buffer, so an RNG failure cannot leave plaintext behind.
    pub(crate) fn fresh_salt() -> [u8; SALT_LEN] {
        let mut salt = [0u8; SALT_LEN];
        SysRng
            .try_fill_bytes(&mut salt)
            .expect("SysRng failure is a program error");
        salt
    }

    /// Encrypts `buf` in place under the key for `salt`; returns the detached tag.
    ///
    /// The nonce is all-zero. That is sound only because every seal draws a new salt with
    /// [`fresh_salt`](Self::fresh_salt) and so a new key: no key ever encrypts twice.
    pub(crate) fn seal_in_place(&self, salt: &[u8; SALT_LEN], buf: &mut [u8]) -> [u8; TAG_LEN] {
        self.cipher(salt)
            .encrypt_inout_detached(&Nonce::default(), &[], buf.into())
            .expect("ChaCha20-Poly1305 rejects only inputs over 256 GiB")
            .into()
    }

    /// Decrypts `buf` in place. On a tag mismatch `buf` is wiped and this panics: sealed
    /// memory that fails to authenticate was modified or corrupted, and nothing can be
    /// recovered from it.
    pub(crate) fn open_in_place(&self, salt: &[u8; SALT_LEN], tag: &[u8; TAG_LEN], buf: &mut [u8]) {
        let opened = self.cipher(salt).decrypt_inout_detached(
            &Nonce::default(),
            &[],
            buf.into(),
            tag.into(),
        );
        if opened.is_err() {
            buf.zeroize();
            panic!("sealed memory was modified or corrupted");
        }
    }
}

impl Drop for Prekey {
    fn drop(&mut self) {
        // Wipe while the pages are still locked, then unlock, and only then let the box
        // free them: unlocking after the free could unlock whatever reuses the pages.
        self.block.0.zeroize();
        drop(self.lock.take());
    }
}

/// Always prints `[REDACTED]`.
impl core::fmt::Debug for Prekey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}
