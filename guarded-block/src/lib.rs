//! A fixed-size secret block in a memory mapping of its own, between two no-access guard
//! pages, read-only and locked in RAM while it lives.
//!
//! ```text
//! [ guard: no access ][ block: N bytes, rounded up to whole pages ][ guard: no access ]
//! ```
//!
//! What each part is for:
//!
//! - **Its own mapping.** The block does not come from the heap, so it never sits next to
//!   heap buffers, and no heap allocation can share its pages. The guard pages, the lock and
//!   the protection changes therefore touch this block's pages and nothing else.
//! - **Guard pages.** A linear over-read from memory below the block (a C buffer over-read
//!   in the same process, Heartbleed-style), or an over-run off its end, faults on a guard
//!   page instead of reading the block.
//! - **Read-only while live.** The block is written once, by the closure given to
//!   [`GuardedBlock::new_with`], and is read-only from then until it drops. A stray write
//!   faults.
//! - **Locked.** `VirtualLock` on Windows, `mlock` on Unix, so the block is not written to
//!   swap. A refused lock is reported by [`GuardedBlock::lock_status`], never fatal.
//! - **Not in core dumps (Linux).** `madvise(MADV_DONTDUMP)` on the block, best effort.
//! - **Optionally, no access while idle.** With [`GuardedBlock::new_with_idle_noaccess`] the
//!   block is readable only while a [`GuardedBlock::with`] call is running (unless the
//!   system refuses to make it no-access again; see [`GuardedBlock::with`]). On Windows that
//!   keeps it out of other processes' `ReadProcessMemory` and out of full-memory crash
//!   dumps taken while it is idle; everywhere, an in-process read of its address faults
//!   while it is idle. Its price on Windows is the lock: a no-access page leaves the
//!   process's working set and cannot stay locked, so this mode does not lock there, and
//!   [`GuardedBlock::lock_status`] says so.
//! - **Wiped on drop**, while still locked if the lock was granted, then unlocked and
//!   unmapped.
//!
//! **After `fork()`**, a child shares the block's bytes but not its page lock, and
//! [`GuardedBlock::lock_status`] says so there. A child of a *multithreaded* parent must not
//! use an inherited idle no-access block at all: if another thread was inside
//! [`GuardedBlock::with`] at the fork, the child inherits its open window (the block stays
//! readable) or its held mutex (the child's first access deadlocks). POSIX allows such a
//! child only async-signal-safe calls until it execs anyway.
//!
//! What it does not do: hide the block from a debugger, from `/proc/<pid>/mem` (both read
//! through page protection on Linux), or from code in the same process that changes the
//! protection back. It does not cover copies of the block's bytes that the caller's closure
//! makes.
//!
//! All the `unsafe` code is in this crate; its API is safe.
//!
//! ```
//! use guarded_block::GuardedBlock;
//!
//! let key = GuardedBlock::<32>::new_with(|bytes| bytes.copy_from_slice(&[7u8; 32]))?;
//! key.with(|bytes| assert_eq!(bytes[0], 7));
//! if let Err(why) = key.lock_status() {
//!     eprintln!("not locked in RAM: {why}");
//! }
//! # Ok::<(), guarded_block::MapError>(())
//! ```
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

use core::fmt;
use std::sync::Mutex;

use region::Protection;
use zeroize::Zeroize;

/// Why a [`GuardedBlock`] could not be created: a mapping or protection system call failed.
///
/// Carries the operating system's error code, never an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapError {
    step: MapStep,
    os_code: Option<i32>,
}

/// Which step of [`GuardedBlock::new_with`] failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MapStep {
    /// Reserving and committing the mapping, or sizing it (`N` rounded up to whole pages,
    /// plus two guard pages, must fit in `isize::MAX`).
    Map,
    /// Making a guard page no-access.
    Guard,
    /// Making the filled block read-only (or no-access, in idle no-access mode).
    Seal,
}

impl MapError {
    fn new(step: MapStep, err: &region::Error) -> Self {
        Self {
            step,
            os_code: os_code(err),
        }
    }

    /// The step that failed.
    pub fn step(&self) -> MapStep {
        self.step
    }

    /// The operating system's error code (`GetLastError` on Windows, `errno` on Unix), when
    /// the failure came from a system call.
    pub fn raw_os_error(&self) -> Option<i32> {
        self.os_code
    }
}

impl fmt::Display for MapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self.step {
            MapStep::Map => "map the block",
            MapStep::Guard => "make a guard page no-access",
            MapStep::Seal => "protect the filled block",
        };
        match self.os_code {
            Some(code) => write!(f, "could not {what} (OS error {code})"),
            None => write!(f, "could not {what}"),
        }
    }
}

impl std::error::Error for MapError {}

/// Why a [`GuardedBlock`]'s pages are not locked in RAM. Returned by
/// [`GuardedBlock::lock_status`].
///
/// Not fatal: the block works the same either way. What is lost is the guarantee that it is
/// never written to swap.
///
/// Carries the operating system's error code, never an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockError {
    cause: LockCause,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LockCause {
    /// The lock was attempted and refused.
    Refused(Option<i32>),
    /// Not attempted: idle no-access mode on Windows.
    IdleNoaccess,
    /// This process is a `fork()` child of the one that made the block.
    Forked,
}

impl LockError {
    fn from_region(err: &region::Error) -> Self {
        Self {
            cause: LockCause::Refused(os_code(err)),
        }
    }

    /// The operating system's error code (`GetLastError` on Windows, `errno` on Unix), when
    /// the lock was attempted and refused. On Windows the usual cause is the process
    /// working-set quota (1453), which every `VirtualLock` in the process shares; on Unix,
    /// `RLIMIT_MEMLOCK`.
    pub fn raw_os_error(&self) -> Option<i32> {
        match self.cause {
            LockCause::Refused(code) => code,
            _ => None,
        }
    }

    /// `true` when the lock was not attempted because the block was made with
    /// [`GuardedBlock::new_with_idle_noaccess`] on Windows, where a no-access page cannot
    /// stay locked.
    pub fn idle_noaccess(&self) -> bool {
        self.cause == LockCause::IdleNoaccess
    }

    /// `true` when this process is a `fork()` child of the one that made the block: page
    /// locks are not inherited across `fork`, so whatever the parent was granted, the child
    /// holds the block unlocked.
    pub fn forked(&self) -> bool {
        self.cause == LockCause::Forked
    }
}

impl fmt::Display for LockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.cause {
            LockCause::IdleNoaccess => f.write_str(
                "the block is not locked in RAM: it is no-access while idle, and on Windows \
                 a no-access page cannot stay locked",
            ),
            LockCause::Forked => f.write_str(
                "the block is not locked in RAM in this process: it was made before a fork, \
                 and page locks are not inherited",
            ),
            LockCause::Refused(Some(code)) => {
                write!(f, "the block could not be locked in RAM (OS error {code})")
            }
            LockCause::Refused(None) => f.write_str("the block could not be locked in RAM"),
        }
    }
}

impl std::error::Error for LockError {}

fn os_code(err: &region::Error) -> Option<i32> {
    match err {
        region::Error::SystemCall(code) | region::Error::MachCall(code) => Some(*code),
        _ => None,
    }
}

/// `N` bytes in a mapping of their own, between no-access guard pages, read-only and
/// locked while live. See the [crate documentation](crate) for what each part covers.
///
/// `Send` and `Sync`: after construction the block is only read, and in idle no-access
/// mode every protection change happens under a mutex.
pub struct GuardedBlock<const N: usize> {
    /// The whole mapping: guard page, block pages, guard page. Unmapped when this drops.
    map: region::Allocation,
    /// The page size, which is also the block's offset into the mapping.
    page: usize,
    /// `N` rounded up to whole pages: the span that is locked and protected.
    block_len: usize,
    lock: Option<region::LockGuard>,
    lock_error: Option<LockError>,
    /// The process that made the block and holds its lock; a `fork()` child does not.
    pid: u32,
    /// `Some` in idle no-access mode: how many [`with`](Self::with) calls are running. The
    /// first to start makes the block readable, the last to finish makes it no-access.
    open: Option<Mutex<usize>>,
}

// SAFETY: the mapping is owned exclusively by this value and freed only by its `Drop`.
// After construction its bytes are only read, through `&self`; the one mutable state, the
// protection in idle no-access mode, changes only while `open`'s mutex is held, and is
// readable whenever any `with` call is between its open and its close.
unsafe impl<const N: usize> Send for GuardedBlock<N> {}
// SAFETY: as above.
unsafe impl<const N: usize> Sync for GuardedBlock<N> {}

impl<const N: usize> GuardedBlock<N> {
    /// Maps a guarded block, locks it, lets `fill` write it, then makes it read-only.
    ///
    /// The block holds zeros when `fill` runs, and is already locked (if the lock was
    /// granted), so what `fill` writes never sits in pages that could be swapped unless the
    /// lock was refused. A refused lock is not an error; see [`lock_status`](Self::lock_status).
    ///
    /// # Errors
    ///
    /// When the mapping, a guard page, or the final protection cannot be set up. Nothing is
    /// left mapped.
    ///
    /// # Panics
    ///
    /// At compile time if `N` is zero. If `fill` panics, the block is wiped and unmapped
    /// before the panic continues.
    pub fn new_with(fill: impl FnOnce(&mut [u8; N])) -> Result<Self, MapError> {
        Self::create(fill, false)
    }

    /// As [`new_with`](Self::new_with), and the block is also no-access whenever no
    /// [`with`](Self::with) call is running.
    ///
    /// On Windows this mode does not lock the block: a no-access page leaves the working set
    /// and its lock is dropped, so the block may be written to the pagefile while idle.
    /// [`lock_status`](Self::lock_status) then returns an error whose
    /// [`idle_noaccess`](LockError::idle_noaccess) is `true`. On Linux the lock survives the
    /// protection change and is kept. Each access costs two extra protection changes, a few
    /// microseconds, more with many busy threads, since each change interrupts every CPU
    /// running one of the process's threads.
    ///
    /// # Errors
    ///
    /// As [`new_with`](Self::new_with).
    pub fn new_with_idle_noaccess(fill: impl FnOnce(&mut [u8; N])) -> Result<Self, MapError> {
        Self::create(fill, true)
    }

    fn create(fill: impl FnOnce(&mut [u8; N]), idle: bool) -> Result<Self, MapError> {
        const { assert!(N > 0, "a guarded block holds at least one byte") };
        let page = region::page::size();
        // Checked, not wrapping: a wrapped `total` would map less than the `[u8; N]` formed
        // below. (rustc already rejects `[u8; N]` above `isize::MAX`, and no `N` up to that
        // can overflow here, but the soundness of `fill` should not rest on that.)
        let sizes = N
            .div_ceil(page)
            .checked_mul(page)
            .and_then(|block_len| Some((block_len, block_len.checked_add(2 * page)?)))
            .filter(|&(_, total)| total <= isize::MAX as usize);
        let Some((block_len, total)) = sizes else {
            return Err(MapError {
                step: MapStep::Map,
                os_code: None,
            });
        };
        let map = region::alloc(total, Protection::READ_WRITE)
            .map_err(|e| MapError::new(MapStep::Map, &e))?;
        let mut this = Self {
            map,
            page,
            block_len,
            lock: None,
            lock_error: None,
            pid: std::process::id(),
            open: idle.then(|| Mutex::new(0)),
        };
        // From here on an early return or a panic drops `this`, which wipes and unmaps.
        let base = this.map.as_ptr::<u8>();
        // SAFETY: both guard pages lie inside the mapping `this` owns; nothing else refers
        // to them.
        unsafe {
            region::protect(base, page, Protection::NONE)
                .map_err(|e| MapError::new(MapStep::Guard, &e))?;
            region::protect(base.add(page + block_len), page, Protection::NONE)
                .map_err(|e| MapError::new(MapStep::Guard, &e))?;
        }
        if idle && cfg!(windows) {
            this.lock_error = Some(LockError {
                cause: LockCause::IdleNoaccess,
            });
        } else {
            match region::lock(this.block_ptr(), block_len) {
                Ok(guard) => this.lock = Some(guard),
                Err(e) => this.lock_error = Some(LockError::from_region(&e)),
            }
        }
        dont_dump(this.block_ptr(), block_len);
        // SAFETY: the block is `READ_WRITE`, inside the mapping, and `&mut this` is the only
        // reference to it; it is page-aligned, so it is aligned for `[u8; N]`.
        fill(unsafe { &mut *this.block_ptr().cast_mut().cast::<[u8; N]>() });
        let resting = if idle {
            Protection::NONE
        } else {
            Protection::READ
        };
        // SAFETY: the block lies inside the mapping; nothing refers to it once `fill` has
        // returned.
        unsafe { region::protect(this.block_ptr(), block_len, resting) }
            .map_err(|e| MapError::new(MapStep::Seal, &e))?;
        Ok(this)
    }

    fn block_ptr(&self) -> *const u8 {
        // SAFETY: `page` is less than the mapping's length (`block_len + 2 * page`).
        unsafe { self.map.as_ptr::<u8>().add(self.page) }
    }

    /// Calls `f` with the block's bytes.
    ///
    /// In idle no-access mode the block is made readable for the call and no-access again
    /// after it, even if `f` panics. Concurrent calls share one readable window. If the
    /// system refuses to make it no-access again, which it does only in exhaustion cases
    /// (out of memory mappings), the block stays readable until a later call closes it;
    /// nothing reports this, and [`lock_status`](Self::lock_status) is about the lock only.
    ///
    /// # Panics
    ///
    /// In idle no-access mode, if the block cannot be made readable (the system refused the
    /// protection change; on Linux, typically because the process has run out of memory
    /// mappings). Panics from `f` propagate.
    pub fn with<R>(&self, f: impl FnOnce(&[u8; N]) -> R) -> R {
        let _window = self.open_window();
        // SAFETY: the block is inside the mapping, page-aligned, initialized by `fill`, and
        // readable: `READ` for the block's whole life outside idle no-access mode, and in
        // that mode for as long as `_window` is alive. Nothing writes it until `Drop`.
        f(unsafe { &*self.block_ptr().cast::<[u8; N]>() })
    }

    fn open_window(&self) -> Option<Window<'_, N>> {
        let open = self.open.as_ref()?;
        let mut count = open
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *count == 0 {
            // SAFETY: the block lies inside the mapping; the mutex serializes every
            // protection change.
            unsafe { region::protect(self.block_ptr(), self.block_len, Protection::READ) }
                .expect("could not make the guarded block readable");
        }
        *count += 1;
        Some(Window { block: self })
    }

    /// `Ok(())` if the block's pages are locked in RAM; otherwise why they are not.
    ///
    /// In a `fork()` child of the process that made the block this is always an error whose
    /// [`forked`](LockError::forked) is `true`: page locks are not inherited.
    pub fn lock_status(&self) -> Result<(), LockError> {
        if std::process::id() != self.pid {
            return Err(LockError {
                cause: LockCause::Forked,
            });
        }
        match self.lock_error {
            None => Ok(()),
            Some(err) => Err(err),
        }
    }

    /// `true` if this block was made with [`new_with_idle_noaccess`](Self::new_with_idle_noaccess).
    pub fn is_idle_noaccess(&self) -> bool {
        self.open.is_some()
    }

    /// The block's pages and the guard pages around it, as
    /// `(guard below, block, guard above)` address ranges, for tests that check the layout
    /// with [`region::query`]. Addresses only; nothing is read.
    #[doc(hidden)]
    pub fn layout(&self) -> [core::ops::Range<usize>; 3] {
        let b = self.block_ptr() as usize;
        [
            b - self.page..b,
            b..b + self.block_len,
            b + self.block_len..b + self.block_len + self.page,
        ]
    }
}

/// One `with` call's readable window in idle no-access mode.
struct Window<'a, const N: usize> {
    block: &'a GuardedBlock<N>,
}

impl<const N: usize> Drop for Window<'_, N> {
    fn drop(&mut self) {
        let Some(open) = self.block.open.as_ref() else {
            return;
        };
        let mut count = open
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *count -= 1;
        if *count == 0 {
            // SAFETY: as in `open_window`. A failure leaves the block readable until a later
            // window closes it, which loses the idle protection but not the data; `with`'s
            // docs say so, since there is no one to report it to here.
            let _ = unsafe {
                region::protect(
                    self.block.block_ptr(),
                    self.block.block_len,
                    Protection::NONE,
                )
            };
        }
    }
}

impl<const N: usize> GuardedBlock<N> {
    /// Makes the block writable and zeroes it. Returns `false` if it could not be made
    /// writable, in which case it is left as is; unmapping it next returns its pages to the
    /// operating system, which zeroes them before handing them out again.
    fn wipe(&mut self) -> bool {
        // SAFETY: `&mut self`: no `with` call is running, so nothing refers to the block.
        if unsafe { region::protect(self.block_ptr(), self.block_len, Protection::READ_WRITE) }
            .is_err()
        {
            return false;
        }
        // SAFETY: the block is `READ_WRITE`, inside the mapping, and exclusively ours.
        unsafe { core::slice::from_raw_parts_mut(self.block_ptr().cast_mut(), self.block_len) }
            .zeroize();
        true
    }
}

impl<const N: usize> GuardedBlock<N> {
    /// What `Drop` does before the unmap: wipe, then unlock. Separate so a test can watch
    /// both happen while the mapping still exists. Safe to repeat.
    fn release(&mut self) {
        self.wipe();
        drop(self.lock.take());
    }
}

impl<const N: usize> Drop for GuardedBlock<N> {
    /// Wipes the block (while it is still locked, if the lock was granted), then unlocks
    /// it, then unmaps the mapping.
    fn drop(&mut self) {
        self.release();
        // `self.map` drops after this, unmapping guard and block pages alike.
    }
}

/// Never shows the block's bytes or address.
impl<const N: usize> fmt::Debug for GuardedBlock<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GuardedBlock([REDACTED])")
    }
}

#[cfg(target_os = "linux")]
fn dont_dump(ptr: *const u8, len: usize) {
    // SAFETY: `madvise` only reads the range's bounds; the range lies inside a mapping this
    // process owns. Best effort: a failure leaves the block in core dumps, nothing else.
    let _ = unsafe { libc::madvise(ptr.cast_mut().cast(), len, libc::MADV_DONTDUMP) };
}

#[cfg(not(target_os = "linux"))]
fn dont_dump(_ptr: *const u8, _len: usize) {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether the block's first page is locked, asked of the operating system.
    #[cfg(windows)]
    fn is_locked(b: &GuardedBlock<100>) -> Option<bool> {
        // `VirtualUnlock` of a page that is not locked fails with ERROR_NOT_LOCKED (158).
        // Asking unlocks it, so lock it again after a "yes".
        // SAFETY (test): the block's pages are ours and stay mapped.
        match unsafe { region::unlock(b.block_ptr(), b.block_len) } {
            Ok(()) => {
                core::mem::forget(region::lock(b.block_ptr(), b.block_len).unwrap());
                Some(true)
            }
            Err(region::Error::SystemCall(158)) => Some(false),
            Err(e) => panic!("unexpected unlock error: {e}"),
        }
    }

    #[cfg(target_os = "linux")]
    fn is_locked(b: &GuardedBlock<100>) -> Option<bool> {
        let start = b.block_ptr() as usize;
        let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        let mut inside = false;
        for line in smaps.lines() {
            if let Some((range, _)) = line.split_once(' ') {
                if let Some((lo, hi)) = range.split_once('-') {
                    if let (Ok(lo), Ok(hi)) =
                        (usize::from_str_radix(lo, 16), usize::from_str_radix(hi, 16))
                    {
                        inside = lo <= start && start < hi;
                        continue;
                    }
                }
            }
            if inside && line.starts_with("VmFlags:") {
                return Some(line.split_whitespace().any(|f| f == "lo"));
            }
        }
        panic!("block mapping not in smaps")
    }

    #[cfg(not(any(windows, target_os = "linux")))]
    fn is_locked(_: &GuardedBlock<100>) -> Option<bool> {
        None
    }

    /// The drop path, observed while the mapping still exists: `release` (all `Drop` does
    /// before the unmap) leaves the block zeroed and unlocked. Deleting the wipe or the
    /// unlock from `release` fails this.
    #[test]
    fn release_wipes_then_unlocks() {
        let mut b = GuardedBlock::<100>::new_with(|x| x.fill(0xA5)).unwrap();
        let locked = b.lock_status().is_ok();
        if locked {
            assert_ne!(is_locked(&b), Some(false), "a granted lock is held");
        }
        b.release();
        // SAFETY (test): `release` left the block `READ_WRITE` (its wipe did).
        let bytes = unsafe { core::slice::from_raw_parts(b.block_ptr(), b.block_len) };
        assert!(bytes.iter().all(|&v| v == 0), "release wiped the block");
        assert!(b.lock.is_none());
        if locked {
            assert_ne!(is_locked(&b), Some(true), "release unlocked the block");
        }
    }

    #[test]
    fn wipe_zeroes_the_whole_block() {
        let mut b = GuardedBlock::<100>::new_with(|x| x.fill(0xA5)).unwrap();
        assert!(b.with(|x| x.iter().all(|&v| v == 0xA5)));
        assert!(b.wipe());
        // SAFETY (test): `wipe` left the block `READ_WRITE`.
        let bytes = unsafe { core::slice::from_raw_parts(b.block_ptr(), b.block_len) };
        assert!(bytes.iter().all(|&v| v == 0));
    }

    #[test]
    fn wipe_zeroes_an_idle_noaccess_block_too() {
        let mut b = GuardedBlock::<100>::new_with_idle_noaccess(|x| x.fill(0x5A)).unwrap();
        assert!(b.wipe());
        // SAFETY (test): `wipe` left the block `READ_WRITE`.
        let bytes = unsafe { core::slice::from_raw_parts(b.block_ptr(), b.block_len) };
        assert!(bytes.iter().all(|&v| v == 0));
    }
}
