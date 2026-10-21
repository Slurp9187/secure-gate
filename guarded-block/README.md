# guarded-block

A fixed-size secret block in a memory mapping of its own, between two no-access guard pages,
read-only and locked in RAM while it lives. A safe API over
[`region`](https://crates.io/crates/region)'s page protection; all the `unsafe` is in this
crate.

```text
[ guard: no access ][ block: N bytes, rounded up to whole pages ][ guard: no access ]
```

```rust
use guarded_block::{GuardedBlock, MapError};

fn main() -> Result<(), MapError> {
    let key = GuardedBlock::<32>::new_with(|bytes| bytes.copy_from_slice(&[7u8; 32]))?;
    key.with(|bytes| assert_eq!(bytes[0], 7));
    if let Err(why) = key.lock_status() {
        eprintln!("not locked in RAM: {why}");
    }
    Ok(())
}
```

(An equivalent example runs as a doctest on the crate's documentation page.)

What each part is for:

- **Its own mapping**, not the heap: nothing else shares its pages, so the lock and the
  protection changes touch only this block.
- **Guard pages**: a linear over-read from memory below it (a C buffer over-read in the same
  process, Heartbleed-style), or an over-run off its end, faults instead of reading it.
- **Read-only while live**: written once by the closure given to `new_with`, then read-only
  until it drops.
- **Locked** (`VirtualLock` / `mlock`), so it is not written to swap. A refused lock is
  reported by `lock_status()`, never fatal.
- **Not in core dumps** on Linux (`MADV_DONTDUMP`, best effort).
- **Optionally no-access while idle** (`new_with_idle_noaccess`): readable only during a
  `with` call (unless the system refuses the change back to no-access, in which case a later
  call closes it). On Windows that keeps it out of `ReadProcessMemory` and full-memory crash
  dumps taken while idle, but a no-access page cannot stay locked there, so this mode does
  not lock on Windows and `lock_status()` says so. On Linux the lock is kept.
- **Wiped on drop** (while still locked, if the lock was granted), then unlocked and
  unmapped.
- **Honest after `fork()`**: a child does not inherit page locks, and `lock_status()` says so
  there. A child of a multithreaded parent must not use an inherited idle no-access block.

What it does not do: hide the block from a debugger, from `/proc/<pid>/mem`, or from code in
the same process that changes the protection back; or cover copies the caller's closure makes.

Measurements behind these claims (over-reads from live C buffers, lock survival across
protection changes, crash dumps, per-access cost) are in the secure-gate repository, under
`docs/design/receipts/guarded-prekey/`. Written for
[secure-gate](https://crates.io/crates/secure-gate)'s sealed-memory pre-key; usable on its own.

MSRV 1.85. Licensed under MIT or Apache-2.0, at your option.
