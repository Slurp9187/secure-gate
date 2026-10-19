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
/// It is also returned, without asking the operating system, when the page size is larger
/// than the pre-key (64 KiB pages on some Linux builds): the pre-key would then share a page
/// with other memory, and unlocking it on drop would unlock that memory too.
///
/// Carries the operating system's error code or the page size, never an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockError {
    os_code: Option<i32>,
    page_size: Option<usize>,
}

impl LockError {
    fn from_region(err: &region::Error) -> Self {
        let os_code = match err {
            region::Error::SystemCall(code) | region::Error::MachCall(code) => Some(*code),
            _ => None,
        };
        Self {
            os_code,
            page_size: None,
        }
    }

    /// The operating system's error code (`GetLastError` on Windows, `errno` on Unix), when
    /// the failure came from a system call.
    pub fn raw_os_error(&self) -> Option<i32> {
        self.os_code
    }

    /// The page size, when locking was not attempted because a page is larger than the
    /// pre-key.
    pub fn page_too_large(&self) -> Option<usize> {
        self.page_size
    }
}

impl core::fmt::Display for LockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match (self.os_code, self.page_size) {
            (_, Some(size)) => write!(
                f,
                "the sealed-memory pre-key was not locked: the {size}-byte page would be \
                 shared with other memory"
            ),
            (Some(code), None) => write!(
                f,
                "the sealed-memory pre-key could not be locked in RAM (OS error {code})"
            ),
            (None, None) => f.write_str("the sealed-memory pre-key could not be locked in RAM"),
        }
    }
}

impl std::error::Error for LockError {}

/// The 16 KiB of random bytes that every sealing key is derived from, locked in RAM where
/// the operating system allows it.
///
/// Each [`SealedFixed`](crate::SealedFixed) and [`SealedDynamic`](crate::SealedDynamic)
/// keeps an `Arc` to the `Prekey` it was sealed under and derives its key afresh on every
/// access as `SHA-256(salt ‖ pre-key)`. The key itself is never stored, and the stack the
/// cipher used is overwritten after each access, since the cipher leaves a copy there. A
/// lossy readout of memory (Spectre-class side channels, Rowhammer, cold boot) that gets any
/// one of the pre-key's 131,072 bits wrong yields a useless key, with nothing to say which
/// bit was wrong. See the [`sealed`](crate::sealed) module for the whole threat model.
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
        // Locked while it still holds zeros, then filled: the random bytes never sit in
        // pages that could be swapped, unless the lock is refused.
        let lock = lock_block(&block, region::page::size());
        SysRng
            .try_fill_bytes(&mut block.0)
            .expect("SysRng failure is a program error");
        Arc::new(Self::from_parts(block, lock))
    }

    fn from_parts(
        block: alloc::boxed::Box<Block>,
        lock: Result<region::LockGuard, LockError>,
    ) -> Self {
        let (lock, lock_error) = match lock {
            Ok(guard) => (Some(guard), None),
            Err(err) => (None, Some(err)),
        };
        Self {
            block,
            lock,
            lock_error,
        }
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
        let mut rng = SysRng;
        let words: [u64; SALT_LEN / 8] = core::array::from_fn(|_| {
            rng.try_next_u64()
                .expect("SysRng failure is a program error")
        });
        core::array::from_fn(|i| words[i / 8].to_le_bytes()[i % 8])
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
    /// recovered from it. (The tag is checked before any keystream is applied, so `buf`
    /// still holds ciphertext then; it is wiped regardless.)
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

/// Locks `block`'s pages, unless a page is larger than the block: locking it would then
/// lock, and later unlock, a neighbor's memory too.
fn lock_block(block: &Block, page_size: usize) -> Result<region::LockGuard, LockError> {
    if page_size > PREKEY_LEN {
        return Err(LockError {
            os_code: None,
            page_size: Some(page_size),
        });
    }
    region::lock(block.0.as_ptr(), PREKEY_LEN).map_err(|err| LockError::from_region(&err))
}

/// Size of the stack region [`scrub_stack`] overwrites.
const SCRUB_LEN: usize = 32 * 1024;

/// Overwrites the stack region below its caller with zeros.
///
/// The ChaCha20 backend leaves its state block (constant, then the 32-byte sealing key) on
/// the stack after a pass, and moves can leave a copy of a temporary plaintext. Neither is
/// reachable for a wipe. Called at the end of every seal and open, from the frame that made
/// the calls, this function's frame lies over the region those calls used and zeroes it.
/// The technique is sequoia's `zero_stack`; `[u64]` keeps the volatile writes word-sized.
///
/// Best effort: it covers what the calls left in `SCRUB_LEN` bytes below the caller, not
/// registers, and not copies a closure parks elsewhere.
#[inline(never)]
pub(crate) fn scrub_stack() {
    let mut area = [0u64; SCRUB_LEN / 8];
    area.zeroize();
    core::hint::black_box(&area);
}

/// Runs `f`, then [`scrub_stack`], on every exit: a panic from `f` (the caller's closure, or
/// a tag mismatch) is caught, the stack scrubbed, and the panic resumed. Without this an
/// unwind skips the scrub and leaves the cipher's copy of the sealing key behind. A `Drop`
/// guard is not a substitute: on Windows, unwinding runs cleanup below the frames that
/// threw, so the guard's scrub would not lie over them. Under `panic = "abort"` there is
/// no unwind to survive.
#[inline(always)]
pub(crate) fn scrubbed<R>(f: impl FnOnce() -> R) -> R {
    let result = std::panic::catch_unwind(core::panic::AssertUnwindSafe(f));
    scrub_stack();
    match result {
        Ok(value) => value,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

impl Prekey {
    /// Wipe while the pages are still locked, then unlock. `Drop` calls this before the box
    /// frees the pages: unlocking after the free could unlock whatever reuses them.
    fn wipe_and_unlock(&mut self) {
        self.block.0.zeroize();
        drop(self.lock.take());
    }
}

impl Drop for Prekey {
    fn drop(&mut self) {
        self.wipe_and_unlock();
    }
}

/// Always prints `[REDACTED]`.
impl core::fmt::Debug for Prekey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Every test in this crate's unit tests that creates a pre-key takes this first: they
    /// share one per-process lock quota (about 11 pre-keys under Windows' default), and the
    /// quota test below needs it to itself.
    pub(crate) fn quota() -> std::sync::MutexGuard<'static, ()> {
        static QUOTA: std::sync::Mutex<()> = std::sync::Mutex::new(());
        QUOTA
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn random_block() -> alloc::boxed::Box<Block> {
        let mut block = alloc::boxed::Box::new(Block([0u8; PREKEY_LEN]));
        SysRng.try_fill_bytes(&mut block.0).unwrap();
        block
    }

    #[test]
    fn block_is_page_aligned_and_fills_whole_pages() {
        let block = random_block();
        let addr = block.0.as_ptr() as usize;
        assert_eq!(addr % 16384, 0);
        assert_eq!(core::mem::size_of::<Block>(), PREKEY_LEN);
        let page = region::page::size();
        if page <= PREKEY_LEN {
            assert_eq!(PREKEY_LEN % page, 0);
        } else {
            let _q = quota();
            assert_eq!(
                Prekey::new().lock_status().unwrap_err().page_too_large(),
                Some(page)
            );
        }
    }

    #[test]
    fn a_failed_lock_is_reported_and_sealing_still_works() {
        let _q = quota();
        let prekey = Arc::new(Prekey::from_parts(
            random_block(),
            Err(LockError::from_region(&region::Error::SystemCall(1453))),
        ));
        let err = prekey.lock_status().unwrap_err();
        assert_eq!(err.raw_os_error(), Some(1453));
        assert_eq!(err.page_too_large(), None);
        assert_eq!(
            format!("{err:?}"),
            "LockError { os_code: Some(1453), page_size: None }"
        );
        assert_eq!(
            err.to_string(),
            "the sealed-memory pre-key could not be locked in RAM (OS error 1453)"
        );

        let salt = Prekey::fresh_salt();
        let mut buf = *b"still sealed";
        let tag = prekey.seal_in_place(&salt, &mut buf);
        assert_ne!(&buf, b"still sealed");
        prekey.open_in_place(&salt, &tag, &mut buf);
        assert_eq!(&buf, b"still sealed");
    }

    #[test]
    fn a_non_os_lock_failure_has_no_code() {
        let prekey = Prekey::from_parts(
            random_block(),
            Err(LockError::from_region(&region::Error::InvalidParameter(
                "size",
            ))),
        );
        let err = prekey.lock_status().unwrap_err();
        assert_eq!(err.raw_os_error(), None);
        assert_eq!(
            format!("{err:?}"),
            "LockError { os_code: None, page_size: None }"
        );
    }

    #[test]
    fn wipe_and_unlock_zeroes_the_prekey_and_releases_the_lock() {
        let _q = quota();
        let lock = region::lock(core::ptr::null::<u8>(), 0).map_err(|_| ());
        assert!(lock.is_err(), "a zero-length lock is rejected");
        let block = random_block();
        let guard = region::lock(block.0.as_ptr(), PREKEY_LEN);
        // Other tests lock pages too and share the quota; a refused lock still exercises
        // the wipe, and `tests/sealed_lock.rs` covers the unlock in a process of its own.
        let locked = guard.is_ok();
        let mut prekey = Prekey::from_parts(block, guard.map_err(|e| LockError::from_region(&e)));
        assert!(prekey.block.0.iter().any(|&b| b != 0));
        assert_eq!(prekey.lock.is_some(), locked);
        prekey.wipe_and_unlock();
        assert!(prekey.block.0.iter().all(|&b| b == 0));
        assert!(prekey.lock.is_none());
    }

    /// Exhausts the lock quota with pre-keys whose blocks stay allocated, unlocks them,
    /// and checks the quota came back. The blocks must stay allocated: on Windows freeing
    /// one decommits its pages, which releases the lock with or without an unlock.
    /// Every other pre-key test in this binary takes the same `quota()` guard, so this one
    /// has the quota to itself; it still asks only that most of the freed quota be usable
    /// again, and a missing unlock frees none of it.
    #[test]
    fn wipe_and_unlock_returns_the_quota() {
        let _q = quota();
        let mut held = Vec::new();
        while held.len() < 1024 {
            let block = random_block();
            let lock = region::lock(block.0.as_ptr(), PREKEY_LEN);
            let refused = lock.is_err();
            held.push(Prekey::from_parts(
                block,
                lock.map_err(|e| LockError::from_region(&e)),
            ));
            if refused {
                break;
            }
        }
        let locked = held.iter().filter(|p| p.lock.is_some()).count();
        if locked == held.len() {
            return; // No refusal within the cap: this platform's quota is out of reach.
        }
        for p in &mut held {
            p.wipe_and_unlock();
        }
        let relocked: Vec<_> = (0..locked)
            .map(|_| {
                let block = random_block();
                let lock = region::lock(block.0.as_ptr(), PREKEY_LEN);
                Prekey::from_parts(block, lock.map_err(|e| LockError::from_region(&e)))
            })
            .collect();
        let ok = relocked.iter().filter(|p| p.lock.is_some()).count();
        assert!(
            ok * 2 >= locked,
            "only {ok} of {locked} relocked after unlocking"
        );
        drop(held);
    }

    #[test]
    fn the_sealing_key_depends_on_every_prekey_bit() {
        let _q = quota();
        let mut prekey = Arc::try_unwrap(Prekey::new()).unwrap();
        let salt = Prekey::fresh_salt();
        let before = prekey.sealing_key(&salt);
        prekey.block.0[PREKEY_LEN - 1] ^= 1;
        let after = prekey.sealing_key(&salt);
        assert_ne!(before.with_secret(|k| *k), after.with_secret(|k| *k));
    }

    #[test]
    fn the_sealing_key_is_sha256_of_salt_then_prekey() {
        let _q = quota();
        let prekey = Prekey::new();
        let salt = Prekey::fresh_salt();
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(prekey.block.0);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(prekey.sealing_key(&salt).with_secret(|k| *k), expected);
    }

    #[test]
    fn every_salt_is_fresh() {
        assert_ne!(Prekey::fresh_salt(), Prekey::fresh_salt());
    }

    #[test]
    #[should_panic(expected = "sealed memory was modified or corrupted")]
    fn a_wrong_tag_panics() {
        let _q = quota();
        let prekey = Prekey::new();
        let salt = Prekey::fresh_salt();
        let mut buf = [1u8; 8];
        let mut tag = prekey.seal_in_place(&salt, &mut buf);
        tag[0] ^= 1;
        prekey.open_in_place(&salt, &tag, &mut buf);
    }

    #[test]
    fn a_failed_open_wipes_the_buffer_before_panicking() {
        let _q = quota();
        let prekey = Prekey::new();
        let salt = Prekey::fresh_salt();
        let mut buf = [1u8; 8];
        let tag = prekey.seal_in_place(&salt, &mut buf);
        buf[0] ^= 1;
        let result = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
            prekey.open_in_place(&salt, &tag, &mut buf);
        }));
        assert!(result.is_err());
        assert_eq!(buf, [0u8; 8]);
    }

    #[test]
    fn a_page_larger_than_the_prekey_is_refused_without_locking() {
        let block = random_block();
        // The real lock would succeed on this machine's pages; a 64 KiB page must not try.
        let Err(refused) = lock_block(&block, 65536) else {
            panic!("a page larger than the pre-key must be refused");
        };
        assert_eq!(refused.page_too_large(), Some(65536));
        assert_eq!(refused.raw_os_error(), None);
        assert_eq!(
            refused.to_string(),
            "the sealed-memory pre-key was not locked: the 65536-byte page would be shared \
             with other memory"
        );
        let prekey = Prekey::from_parts(block, Err(refused));
        assert!(prekey.lock.is_none());
        assert_eq!(
            prekey.lock_status().unwrap_err().page_too_large(),
            Some(65536)
        );
    }

    #[test]
    fn a_page_no_larger_than_the_prekey_is_locked() {
        let _q = quota();
        let block = random_block();
        let page = region::page::size().min(PREKEY_LEN);
        assert!(lock_block(&block, page).is_ok());
    }

    #[test]
    fn debug_is_redacted() {
        let _q = quota();
        assert_eq!(format!("{:?}", Prekey::new()), "[REDACTED]");
    }
}
