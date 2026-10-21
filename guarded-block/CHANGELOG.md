# Changelog

All notable changes to this crate are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/); the crate follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - Unreleased

### Added
- `GuardedBlock<N>`: `N` bytes in a mapping of their own between two no-access guard pages,
  locked in RAM and read-only once filled; on Linux marked `MADV_DONTDUMP`. Wiped on drop
  (while still locked, if the lock was granted), then unlocked and unmapped. `new_with`
  fills it through a closure; `with` reads it; `lock_status` reports a refused lock
  (`LockError`, with the OS error code and never an address), and in a `fork()` child reports
  the lock as not inherited (`LockError::forked`); `MapError` reports a failed mapping or
  protection change.
- `GuardedBlock::new_with_idle_noaccess`: also no-access except during `with` calls, which
  share one readable window under a mutex and close it again on a panic. On Windows a
  no-access page cannot stay locked (measured: the lock is dropped and the page leaves the
  working set), so this mode does not lock there and `lock_status` returns a `LockError` whose
  `idle_noaccess()` is `true`. On Linux the lock is kept.
- Tests that read every promised protection back from the operating system with
  `region::query`; each was checked to fail with the protection call it guards removed.
