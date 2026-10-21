//! The pre-key: 16 KiB of random bytes every sealing key is derived from.

use alloc::sync::Arc;

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use guarded_block::GuardedBlock;
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

/// Why the pre-key's pages are not locked in RAM. Returned by [`Prekey::lock_status`].
///
/// Not fatal: the sealed types work the same either way. What is lost is the guarantee
/// that the pre-key never reaches the swap file. On Windows the usual cause is the
/// process working-set quota, which every `VirtualLock` in the process shares; on Unix it
/// is `RLIMIT_MEMLOCK`.
///
/// It is also returned, without asking the operating system, for a pre-key made with
/// [`Prekey::new_idle_noaccess`] on Windows, where a no-access page cannot stay locked, and
/// in a `fork()` child of the process that made the pre-key, which does not inherit its lock.
///
/// Carries the operating system's error code, never an address.
///
/// # Example
///
/// Report the reason, and raise the quota where it is the cause:
///
/// ```
/// use secure_gate::Prekey;
///
/// let prekey = Prekey::new();
/// match prekey.lock_status() {
///     Ok(()) => {}
///     // ERROR_WORKING_SET_QUOTA: every `VirtualLock` in a Windows process shares the
///     // working-set quota (about eleven pre-keys under the default). Raise it at startup
///     // with `SetProcessWorkingSetSize` if the application holds more.
///     Err(why) if why.raw_os_error() == Some(1453) => eprintln!("raise the quota: {why}"),
///     Err(why) => eprintln!("sealed secrets work, but may reach swap: {why}"),
/// }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockError {
    os_code: Option<i32>,
    idle_noaccess: bool,
    forked: bool,
}

impl LockError {
    fn from_guarded(err: guarded_block::LockError) -> Self {
        Self {
            os_code: err.raw_os_error(),
            idle_noaccess: err.idle_noaccess(),
            forked: err.forked(),
        }
    }

    /// The operating system's error code (`GetLastError` on Windows, `errno` on Unix), when
    /// the lock was attempted and refused.
    pub fn raw_os_error(&self) -> Option<i32> {
        self.os_code
    }

    /// `true` when locking was not attempted because the pre-key was made with
    /// [`Prekey::new_idle_noaccess`] on Windows: a no-access page leaves the process's
    /// working set, and its lock with it.
    pub fn idle_noaccess(&self) -> bool {
        self.idle_noaccess
    }

    /// `true` in a `fork()` child of the process that made the pre-key: page locks are not
    /// inherited, so the child holds the pre-key unlocked whatever the parent was granted.
    pub fn forked(&self) -> bool {
        self.forked
    }
}

impl core::fmt::Display for LockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.forked {
            return f.write_str(
                "the sealed-memory pre-key is not locked in RAM in this process: it was made \
                 before a fork, and page locks are not inherited",
            );
        }
        match (self.idle_noaccess, self.os_code) {
            (true, _) => f.write_str(
                "the sealed-memory pre-key is not locked in RAM: it is no-access while idle \
                 (Prekey::new_idle_noaccess), and on Windows a no-access page cannot stay locked",
            ),
            (false, Some(code)) => write!(
                f,
                "the sealed-memory pre-key could not be locked in RAM (OS error {code})"
            ),
            (false, None) => f.write_str("the sealed-memory pre-key could not be locked in RAM"),
        }
    }
}

impl std::error::Error for LockError {}

/// The 16 KiB of random bytes that every sealing key is derived from, in memory of its own
/// between no-access guard pages, read-only, and locked in RAM where the operating system
/// allows it.
///
/// Each [`SealedFixed`](crate::SealedFixed) and [`SealedDynamic`](crate::SealedDynamic)
/// keeps an `Arc` to the `Prekey` it was sealed under and derives its key afresh on every
/// access as `SHA-256(salt ‖ pre-key)`. The key itself is never stored, and the stack the
/// cipher used is overwritten after each access, since the cipher leaves a copy there. A
/// lossy readout of memory (Spectre-class side channels, Rowhammer, cold boot) that gets any
/// one of the pre-key's 131,072 bits wrong yields a useless key, with nothing to say which
/// bit was wrong. See the [`sealed`](crate::sealed) module for the whole threat model.
///
/// # Memory
///
/// The pre-key is not on the heap. It has a mapping of its own (from the
/// [`guarded-block`](https://crates.io/crates/guarded-block) crate, which holds the `unsafe`
/// this crate forbids), laid out as a no-access guard page, the pre-key's pages, and a
/// no-access guard page:
///
/// - A linear over-read from a buffer below it, such as a C library's in the same process
///   (Heartbleed-style), faults on the guard page instead of reading the pre-key.
/// - It is read-only from the moment it is filled until it drops.
/// - Its pages are locked (`VirtualLock` on Windows, `mlock` on Unix), and on Linux
///   marked `MADV_DONTDUMP`, which the kernel documents as leaving it out of core dumps.
/// - With [`new_idle_noaccess`](Self::new_idle_noaccess) it is also no-access except while a
///   sealing key is being derived from it (unless the system refuses to make it no-access
///   again), which on Windows costs the lock.
///
/// # Lifetime
///
/// The pre-key is not a `static`. It lives as long as the last sealed object, or the last
/// other `Arc`, that refers to it. When that one drops, the pre-key is wiped (while its
/// pages are still locked, if the lock was granted), then unlocked, then unmapped. An application typically holds one
/// `Prekey` for a session and drops it, along with everything sealed under it, at lock or
/// logout.
///
/// # Locking
///
/// [`new`](Self::new) asks the operating system to keep the pre-key's pages out of swap and
/// never fails because it could not: [`lock_status`](Self::lock_status) reports the outcome
/// so the caller can decide. Locking covers swap only. Hibernation and a clean read of the
/// process's memory (a debugger, `/proc/<pid>/mem`) still see the pre-key, and so does a
/// crash dump on Windows (unless the pre-key is idle no-access) and on macOS.
///
/// # Example
///
/// One pre-key per session, created at login and dropped at logout with everything sealed
/// under it:
///
/// ```
/// use std::sync::Arc;
/// use secure_gate::{Dynamic, Fixed, Prekey, RevealSecret, SealedDynamic, SealedFixed};
///
/// struct Session {
///     prekey: Arc<Prekey>,
///     db_key: SealedFixed<32>,
///     password: SealedDynamic<String>,
/// }
///
/// fn login(db_key: Fixed<[u8; 32]>, password: Dynamic<String>) -> Session {
///     let prekey = Prekey::new();
///     if let Err(why) = prekey.lock_status() {
///         eprintln!("{why}"); // not fatal; see `LockError`
///     }
///     Session {
///         db_key: SealedFixed::seal(db_key, &prekey),
///         password: SealedDynamic::seal(password, &prekey),
///         prekey,
///     }
/// }
///
/// let session = login(Fixed::new([7u8; 32]), Dynamic::new(String::from("hunter2")));
/// session.db_key.with_secret(|k| assert_eq!(k[0], 7));
/// session.password.with_secret(|p| assert_eq!(p, "hunter2"));
/// drop(session); // logout: the sealed values, then the pre-key, are wiped
/// ```
///
/// [`new_idle_noaccess`](Self::new_idle_noaccess) is the alternative where crash dumps or
/// same-user memory reads matter more than the pagefile; its docs compare the two.
///
/// # Fork
///
/// A child created by `fork()` shares the parent's pre-key bytes (copy-on-write) but not
/// its page locks, and [`lock_status`](Self::lock_status) says so in the child. A child that
/// should not hold the parent's sealing material creates its own `Prekey` and re-seals what
/// it keeps.
///
/// A child of a *multithreaded* parent must not use an inherited
/// [idle no-access](Self::new_idle_noaccess) pre-key at all: a thread that was mid-access at
/// the fork leaves the child its open window (the pre-key stays readable) or its held mutex
/// (the child's first access deadlocks). POSIX allows such a child only async-signal-safe
/// calls until it execs in any case.
pub struct Prekey {
    block: GuardedBlock<PREKEY_LEN>,
}

impl Prekey {
    /// Generates a pre-key from the system RNG into guarded, read-only memory, and tries
    /// to lock its pages in RAM.
    ///
    /// Returns an `Arc`, because every sealed object keeps one.
    ///
    /// # Panics
    ///
    /// Panics if the system RNG fails, as [`Fixed::from_random`] does, or if the operating
    /// system refuses to map the pre-key or protect its pages (memory or address-space
    /// exhaustion). A failure to lock is not a panic; see [`lock_status`](Self::lock_status).
    pub fn new() -> Arc<Self> {
        Arc::new(Self::create(false))
    }

    /// As [`new`](Self::new), and the pre-key is also no-access except while a sealing key
    /// is being derived from it (about 6 µs per access). If the system refuses to make it
    /// no-access again after an access, which happens only in exhaustion cases (out of
    /// memory mappings), it stays readable until a later access closes it; nothing reports
    /// that, and [`lock_status`](Self::lock_status) is about the lock only.
    ///
    /// What that adds: while idle, the pre-key cannot be read at its address at all. On
    /// Windows that keeps it out of other processes' `ReadProcessMemory` and out of a
    /// full-memory crash dump taken while it is idle, which a locked pre-key does not
    /// (measured; the repository's `docs/design/sealed_memory.md` has the numbers).
    ///
    /// What it costs:
    ///
    /// - **On Windows, the lock.** A no-access page leaves the process's working set, and
    ///   its `VirtualLock` is dropped (measured), so the pre-key may be written to the
    ///   pagefile while idle. This mode therefore does not lock on Windows, and
    ///   [`lock_status`](Self::lock_status) returns an error whose
    ///   [`idle_noaccess`](LockError::idle_noaccess) is `true`. On Linux the lock is kept.
    /// - **Time.** Measured at about 4 µs on top of an access's 6 µs hash in a quiet
    ///   process, 9 µs with 16 busy threads. On Windows most of it is faulting the pre-key's
    ///   pages back into the working set, which a no-access page leaves; on Linux it is the two
    ///   protection changes, which interrupt every CPU running one of the process's threads.
    /// - **A rare panic.** Making the pre-key readable for an access can fail where mapping
    ///   it would have (the process is out of memory mappings); the access then panics.
    ///
    /// Choose it where crash dumps or same-user memory reads are a larger risk than the
    /// pagefile, for example a Windows machine with an encrypted system drive that collects
    /// full crash dumps. [`new`](Self::new) is the default because, without an encrypted
    /// drive, a pre-key in the pagefile outlives the process.
    ///
    /// # Panics
    ///
    /// As [`new`](Self::new).
    pub fn new_idle_noaccess() -> Arc<Self> {
        Arc::new(Self::create(true))
    }

    fn create(idle: bool) -> Self {
        let fill = |block: &mut [u8; PREKEY_LEN]| {
            SysRng
                .try_fill_bytes(block)
                .expect("SysRng failure is a program error");
        };
        let block = if idle {
            GuardedBlock::new_with_idle_noaccess(fill)
        } else {
            GuardedBlock::new_with(fill)
        };
        Self {
            block: block.unwrap_or_else(|err| {
                panic!("the sealed-memory pre-key could not be set up: {err}")
            }),
        }
    }

    /// `Ok(())` if the pre-key's pages are locked in RAM; otherwise why they are not.
    pub fn lock_status(&self) -> Result<(), LockError> {
        self.block.lock_status().map_err(LockError::from_guarded)
    }

    /// `true` if this pre-key was made with [`new_idle_noaccess`](Self::new_idle_noaccess).
    pub fn is_idle_noaccess(&self) -> bool {
        self.block.is_idle_noaccess()
    }

    /// `SHA-256(salt ‖ pre-key)`, written straight into a wrapper that wipes it on drop.
    /// The pre-key is read only inside this call, which in idle no-access mode is its whole
    /// readable window.
    #[inline]
    fn sealing_key(&self, salt: &[u8; SALT_LEN]) -> Fixed<[u8; 32]> {
        #[cfg(test)]
        tests::maybe_fail_derivation();
        Fixed::new_with(|key: &mut [u8; 32]| {
            self.block.with(|prekey| {
                let mut hasher = Sha256::new();
                hasher.update(salt);
                hasher.update(prekey);
                hasher.finalize_into(key.into());
            });
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

    /// Copies `plain` into `out` and encrypts it there under the key for `salt`; returns
    /// the detached tag.
    ///
    /// The key is derived before `out` is written. Deriving it is the one step that can
    /// fail (for an idle no-access pre-key, when it cannot be made readable), and a failure
    /// after the copy would leave plaintext in `out`, a ciphertext buffer nothing wipes.
    /// Use this, not a copy followed by [`seal_in_place`](Self::seal_in_place), wherever
    /// `out` is not itself a wiping buffer.
    pub(crate) fn seal_into(
        &self,
        salt: &[u8; SALT_LEN],
        plain: &[u8],
        out: &mut [u8],
    ) -> [u8; TAG_LEN] {
        let cipher = self.cipher(salt);
        out.copy_from_slice(plain);
        cipher
            .encrypt_inout_detached(&Nonce::default(), &[], out.into())
            .expect("ChaCha20-Poly1305 rejects only inputs over 256 GiB")
            .into()
    }

    /// Encrypts `buf` in place under the key for `salt`; returns the detached tag. Only for
    /// a `buf` that wipes itself if this panics; see [`seal_into`](Self::seal_into).
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
    /// share one per-process lock quota (about 11 pre-keys under Windows' default).
    pub(crate) fn quota() -> std::sync::MutexGuard<'static, ()> {
        static QUOTA: std::sync::Mutex<()> = std::sync::Mutex::new(());
        QUOTA
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    std::thread_local! {
        static FAIL_NEXT_DERIVATION: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
    }

    /// Makes this thread's next sealing-key derivation panic, as it does in idle no-access
    /// mode when the pre-key cannot be made readable.
    pub(crate) fn fail_next_derivation() {
        FAIL_NEXT_DERIVATION.with(|f| f.set(true));
    }

    pub(super) fn maybe_fail_derivation() {
        if FAIL_NEXT_DERIVATION.with(|f| f.replace(false)) {
            panic!("injected: could not make the guarded block readable");
        }
    }

    /// A pre-key holding `bytes`, in the same guarded memory as a real one.
    fn with_bytes(bytes: &[u8; PREKEY_LEN]) -> Prekey {
        Prekey {
            block: GuardedBlock::new_with(|b| b.copy_from_slice(bytes)).unwrap(),
        }
    }

    fn protection_at(addr: usize) -> region::Protection {
        region::query(addr as *const u8).unwrap().protection()
    }

    #[test]
    fn the_prekey_lies_between_noaccess_guard_pages_and_is_read_only() {
        let _q = quota();
        let prekey = Prekey::new();
        let [below, block, above] = prekey.block.layout();
        assert!(block.len() >= PREKEY_LEN);
        assert_eq!(protection_at(below.start), region::Protection::NONE);
        assert_eq!(protection_at(block.start), region::Protection::READ);
        assert_eq!(protection_at(block.end - 1), region::Protection::READ);
        assert_eq!(protection_at(above.start), region::Protection::NONE);
        assert!(!prekey.is_idle_noaccess());
    }

    #[test]
    fn an_idle_noaccess_prekey_is_noaccess_between_accesses() {
        let _q = quota();
        let prekey = Prekey::new_idle_noaccess();
        assert!(prekey.is_idle_noaccess());
        let block = prekey.block.layout()[1].clone();
        assert_eq!(protection_at(block.start), region::Protection::NONE);
        let salt = Prekey::fresh_salt();
        let mut buf = *b"idle";
        let tag = prekey.seal_in_place(&salt, &mut buf);
        prekey.open_in_place(&salt, &tag, &mut buf);
        assert_eq!(&buf, b"idle");
        assert_eq!(protection_at(block.start), region::Protection::NONE);
        if cfg!(windows) {
            let err = prekey.lock_status().unwrap_err();
            assert!(err.idle_noaccess());
            assert_eq!(err.raw_os_error(), None);
        }
    }

    #[test]
    fn lock_errors_say_why_and_carry_no_address() {
        let quota = LockError {
            os_code: Some(1453),
            idle_noaccess: false,
            forked: false,
        };
        assert_eq!(quota.raw_os_error(), Some(1453));
        assert!(!quota.idle_noaccess());
        assert_eq!(
            format!("{quota:?}"),
            "LockError { os_code: Some(1453), idle_noaccess: false, forked: false }"
        );
        assert_eq!(
            quota.to_string(),
            "the sealed-memory pre-key could not be locked in RAM (OS error 1453)"
        );
        let bare = LockError {
            os_code: None,
            idle_noaccess: false,
            forked: false,
        };
        assert_eq!(
            bare.to_string(),
            "the sealed-memory pre-key could not be locked in RAM"
        );
        let idle = LockError {
            os_code: None,
            idle_noaccess: true,
            forked: false,
        };
        assert_eq!(
            idle.to_string(),
            "the sealed-memory pre-key is not locked in RAM: it is no-access while idle \
             (Prekey::new_idle_noaccess), and on Windows a no-access page cannot stay locked"
        );
        let forked = LockError {
            os_code: None,
            idle_noaccess: false,
            forked: true,
        };
        assert_eq!(
            forked.to_string(),
            "the sealed-memory pre-key is not locked in RAM in this process: it was made \
             before a fork, and page locks are not inherited"
        );
    }

    /// The derivation is the one rc.13 shipped, checked against a vector computed outside
    /// Rust: Python's `hashlib.sha256(bytes([7]) * 32 + bytes(i % 251 for i in range(16384)))`.
    #[test]
    fn the_sealing_key_matches_an_independent_sha256_vector() {
        let _q = quota();
        let bytes: [u8; PREKEY_LEN] = core::array::from_fn(|i| (i % 251) as u8);
        let prekey = with_bytes(&bytes);
        let key = prekey.sealing_key(&[7u8; SALT_LEN]).with_secret(|k| *k);
        let hex: alloc::string::String = key.iter().map(|b| alloc::format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "5fdf15d9989af9c0c55f07f7ba974f74ac47ada2c2b21a6e0539eaebd833cd62"
        );
    }

    #[test]
    fn the_sealing_key_depends_on_every_prekey_bit() {
        let _q = quota();
        let bytes: [u8; PREKEY_LEN] = core::array::from_fn(|i| (i % 251) as u8);
        let mut flipped = bytes;
        flipped[PREKEY_LEN - 1] ^= 1;
        let salt = Prekey::fresh_salt();
        let a = with_bytes(&bytes).sealing_key(&salt).with_secret(|k| *k);
        let b = with_bytes(&flipped).sealing_key(&salt).with_secret(|k| *k);
        assert_ne!(a, b);
    }

    #[test]
    fn the_sealing_key_is_sha256_of_salt_then_prekey() {
        let _q = quota();
        let prekey = Prekey::new();
        let salt = Prekey::fresh_salt();
        let expected: [u8; 32] = prekey.block.with(|pk| {
            let mut hasher = Sha256::new();
            hasher.update(salt);
            hasher.update(pk);
            hasher.finalize().into()
        });
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
    fn debug_is_redacted() {
        let _q = quota();
        assert_eq!(format!("{:?}", Prekey::new()), "[REDACTED]");
        assert_eq!(format!("{:?}", Prekey::new_idle_noaccess()), "[REDACTED]");
    }
}
