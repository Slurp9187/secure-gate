# Changelog

All notable changes to this crate are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/); the crate follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `a_fork_child_can_drop_an_inherited_block`, on every Unix: a child's drop unlocks pages it
  never locked, and no system in CI refuses that.

### Changed
- `GuardedBlock`'s lock field is declared before its mapping, so field drop order also
  unlocks before it unmaps. No behavior change: `Drop` already did both in that order.
- Lock file moved to `region` 4.0.2 (documentation changes only). The requirement stays
  4.0.1.
- Documentation: `region` makes the map, protect and lock calls, and this crate calls
  `madvise` itself; a block that never drops (`mem::forget`, a `static`, `process::exit`,
  an abort) is never wiped; idle no-access keeps the lock on Linux and FreeBSD, measured,
  and on macOS no test reads it back yet. One safety comment corrected.

## [0.1.1] - 2026-11-14

### Added
- FreeBSD: the block is marked `MADV_NOCORE`, FreeBSD's `MADV_DONTDUMP`, so it is left out
  of core dumps there too (best effort, as on Linux). A test reads the flag back from the
  kernel's VM map (`KVME_FLAG_NOCOREDUMP`).
- FreeBSD tests read the lock back from the kernel's VM map (`KVME_FLAG_USER_WIRED`) when
  the block is made, after idle no-access accesses, and after the unlock on drop; and the
  `fork()` test runs on every Unix. Each was checked to fail with the call it guards
  removed. FreeBSD runs in CI in a VM.

### Changed
- `zeroize` requirement raised from 1.8 to 1.9, in step with secure-gate. zeroize 1.9.x
  declares `rust-version` 1.85, so the MSRV is unchanged.
- Documentation states four limits more exactly; no behavior changes. Idle no-access on
  Windows makes `ReadProcessMemory` fail and keeps the block out of user-mode full-memory
  dumps, but not from a process that may change the page protection first, nor from a kernel
  memory dump. When `N` is not a whole number of pages, a read past the block's last byte
  gets zeros to the end of the page before it faults. A `fork()` child's copy is not reached
  by the parent's wipe on drop. A lock does not cover hibernation.
- The wipe on drop is documented as best effort: if the block cannot be made writable again
  it is unmapped unwiped, and the operating system zeroes its pages before reuse.
  `lock_status` documents that a `fork()` child is told apart by process ID, so a child
  with the parent's ID in a new PID namespace is not detected.

## [0.1.0] - 2026-10-20

### Added
- `GuardedBlock<N>`: `N` bytes in a mapping of their own between two no-access guard pages,
  locked in RAM and read-only once filled; on Linux marked `MADV_DONTDUMP`. Wiped on drop
  (while still locked, if the lock was granted), then unlocked and unmapped. `new_with`
  fills it through a closure; `with` reads it; `lock_status` reports a refused lock
  (`LockError`, with the OS error code and never an address), and in a `fork()` child reports
  the lock as not inherited (`LockError::forked`); `MapError` reports a failed mapping or
  protection change, or a size that does not fit (checked arithmetic, never a wrapped
  mapping smaller than the block).
- `GuardedBlock::new_with_idle_noaccess`: also no-access except during `with` calls, which
  share one readable window under a mutex and close it again on a panic. On Windows a
  no-access page cannot stay locked (measured: the lock is dropped and the page leaves the
  working set), so this mode does not lock there and `lock_status` returns a `LockError` whose
  `idle_noaccess()` is `true`. On Linux the lock is kept.
- Tests that read every promised protection back from the operating system with
  `region::query`; each was checked to fail with the protection call it guards removed.
