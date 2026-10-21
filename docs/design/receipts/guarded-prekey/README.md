# Receipt: where the sealed pre-key can be read from, by layout

`docs/design/sealed_memory.md` (*Locking, and the guarded mapping*) and `SECURITY.md` §3 say
that, since rc.15, a linear over-read from a C buffer in the same process does not reach the
pre-key, and they quote the measurements below. A request to split the pre-key into four heap
pages was measured with this probe before anything was built, beside three alternatives. This
directory holds the probe and its captured output.

## What is here

| File | What it is |
|---|---|
| `probe.rs`, `probe.Cargo.toml` | The probe: a standalone binary, `unsafe` throughout because it performs real over-reads. Its own crate (it does not depend on secure-gate); it rebuilds each layout the way the library does or would. Kept here, not in `tests/`. |
| `win_adj.txt`, `linux_adj.txt` | Adjacency and capture: 4 layouts × 3 workloads × 20 fresh processes, per platform. |
| `win_real.txt`, `linux_real.txt` | The same with the real over-read performed (`real_captured=`), 5 seeds per case. The last six lines of `win_real.txt` are a first version of the neighbor test that tried to map memory just below the pre-key's mapping and found that address space taken (`space below is not free`); superseded by `win_neighbor.txt`. |
| `win_neighbor.txt` (and the tail of `linux_real.txt`) | Worst case for a mapping: readable memory directly below and above it, then a 64 KiB read starting 1 KiB below it. |
| `win_misc.txt`, `linux_misc.txt` | Lock quota per layout, the per-access benchmark at 0 / 4 / 16 busy threads, and on Linux the `MADV_DONTDUMP` flag. The three dump lines at the end of `win_misc.txt` are the flawed first dump run (see below). |
| `win_dump.txt` | Full-memory crash dumps, after the fix to the probe. |
| `win_lockcycle.txt`, `linux_lockcycle.txt` | Whether a lock survives a protection change. On Linux the quota is never reached, so its "extra lock SUCCEEDED" lines say nothing; the smaps `lo` flag and the unlock counts are the evidence there. |
| `win_wsex.txt` | `QueryWorkingSetEx` residency of a locked block across protection changes. |

## Hosts

Windows 11 Pro 10.0.26200, x86_64, 32 hardware threads, rustc stable (1.98). Linux: WSL2 on
the same machine, Ubuntu, kernel 6.18.33.2-microsoft-standard-WSL2, glibc 2.43, rustc 1.85.1.
4 KiB pages on both. Release profile.

## Method

Layouts: **block** is rc.13–rc.14's pre-key, a `Box` of 16 KiB aligned to 16 KiB; **split**
is four `Box`es of 4 KiB aligned to 4 KiB, as requested; **bare** is one `region::alloc`
mapping; **guarded** is one mapping with a no-access page each side and the block read-only,
which is what `guarded-block` builds.

Each run is a fresh process. C `malloc` buffers of 16 B–16 KiB (log-uniform, like TLS
records and library structs) are allocated around the pre-key: *cold* (none before it, 400
after), *warm* (400 with 40% freed before it, 400 with 30% freed after), *interleaved* (warm,
plus 8 between each split page; for the other layouts the same as warm). For every live C
buffer below the pre-key's end, the probe finds how far a 64 KiB read from its start gets
before it hits an unreadable page (`region::query`), and counts the pre-key bytes in that
span. 64 KiB is Heartbleed's maximum. `capture_full` counts buffers whose read gets the whole
pre-key; `max_captured` is the best single read. In the `real` runs that best read is then
performed with `libc::memcpy` and the copy compared byte for byte (`real_captured`).

Reading notes:

- `real_from` is the read's start relative to the pre-key's lowest page. In split runs where
  the best buffer lies *between* two pages it prints as a huge number (unsigned wraparound);
  the capture counts are unaffected.
- In bare and guarded `real` runs no C buffer was within reach, so the probe fell back to a
  start 64 bytes below the mapping, which is unmapped: the fault there (`exit=139`) shows
  nothing about guard pages. The neighbor test is the guard-page evidence.
- `exit=139` is how Git Bash on Windows reports the access violation.

## Results

Full capture by one 64 KiB read, runs out of 20:

| Layout | Windows cold / warm / interleaved | Linux cold / warm / interleaved |
|---|---|---|
| block | 20 / 20 / 20 | 20 / 20 / 20 |
| split | 20 / 6 / 0 (part of it in 20/20 each; interleaved median 8 KiB) | 20 / 7 / 0 (part of it in 20/20 each; interleaved median 8 KiB) |
| bare | 0 / 0 / 0 | 0 / 0 / 0 |
| guarded | 0 / 0 / 0 | 0 / 0 / 0 |

Real over-reads matched in every case run: block 10/10 full per platform; split 7/10 full and
3/10 partial (8–12 KiB) per platform.

Neighbor test (3 runs each, per platform): bare gives up 16384/16384 bytes; guarded faults
before reading any.

Lock quota: Windows' default working set locks 11 pre-keys before error 1453 in every layout.
Linux (`ulimit -l` 65536 KiB): at least 1024 in every layout.

Per access, SHA-256 over salt + 16 KiB, median of 9 × 5000:

| Busy threads | Windows: one update / four updates / idle no-access | Linux: one / four / idle no-access |
|---|---|---|
| 0 | 5.95 / 5.95 / 9.61 µs | 5.91 / 5.93 / 10.61 µs |
| 4 | 6.30 / 6.16 / 11.66 µs | 6.11 / 6.17 / 12.16 µs |
| 16 | 6.52 / 6.53 / 15.05 µs | 6.49 / 6.50 / 15.95 µs |

`split_hash_equals_concat=true` in all six bench runs: hashing the salt and then the pages in
order equals hashing the salt and the joined bytes.

Crash dumps (Windows, `MiniDumpWriteDump` with `MiniDumpWithFullMemory`, searched for a
32-byte marker taken from the pre-key; 2 runs each): heap block — `ReadProcessMemory` reads
it, marker in the dump; guarded and readable — same; guarded and idle no-access —
`ReadProcessMemory` fails, marker not in the dump. The first run (end of `win_misc.txt`) found
the marker in the no-access dump too; the cause was the probe's own heap copy of the marker,
which it now wipes before the dump is taken. Recorded so the result is not read as stronger
than it is. Linux: `madvise(MADV_DONTDUMP)` adds `dd` to the block's smaps `VmFlags`; the
kernel's omission of `dd` mappings from core dumps was not exercised here.

Locks across protection changes (11 locked blocks, each `READ_WRITE → X → READ`, then each
unlocked by hand): Windows with X = `READ`, the quota stays full and 11/11 unlocks succeed;
with X = `NONE`, the quota frees (an extra lock succeeds) and 11/11 unlocks fail with error
158, "the segment is already unlocked" (2 runs each). Linux with X = `READ` or `NONE` (64 blocks;
the quota was not reached): smaps keeps `lo` throughout and 64/64 unlocks succeed. `win_wsex.txt`:
after `NONE` all four pages leave the working set, and the first one read back in is not
locked.
