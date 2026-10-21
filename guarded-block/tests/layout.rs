//! The layout and protections a `GuardedBlock` promises, read back from the operating system
//! with `region::query`, so a missing or wrong protection call fails here.

use guarded_block::{GuardedBlock, LockError};
use region::Protection;

fn protection_at(addr: usize) -> Protection {
    region::query(addr as *const u8)
        .expect("address is mapped")
        .protection()
}

#[test]
fn guards_are_noaccess_and_the_block_is_read_only() {
    let b = GuardedBlock::<16384>::new_with(|x| x.fill(7)).unwrap();
    let [below, block, above] = b.layout();
    assert_eq!(protection_at(below.start), Protection::NONE);
    assert_eq!(protection_at(below.end - 1), Protection::NONE);
    assert_eq!(protection_at(block.start), Protection::READ);
    assert_eq!(protection_at(block.end - 1), Protection::READ);
    assert_eq!(protection_at(above.start), Protection::NONE);
    assert_eq!(protection_at(above.end - 1), Protection::NONE);
    let page = region::page::size();
    assert_eq!(below.len(), page);
    assert_eq!(above.len(), page);
    assert_eq!(block.len() % page, 0);
    assert!(block.len() >= 16384);
    assert_eq!(block.start % page, 0);
    assert!(b.with(|x| x.iter().all(|&v| v == 7)));
}

#[test]
fn a_block_smaller_than_a_page_still_owns_whole_pages() {
    let b = GuardedBlock::<1>::new_with(|x| x[0] = 9).unwrap();
    let [below, block, above] = b.layout();
    let page = region::page::size();
    assert_eq!(block.len(), page);
    assert_eq!(below.end, block.start);
    assert_eq!(block.end, above.start);
    assert_eq!(b.with(|x| x[0]), 9);
}

#[test]
fn idle_noaccess_is_readable_only_inside_with() {
    let b = GuardedBlock::<4096>::new_with_idle_noaccess(|x| x.fill(3)).unwrap();
    assert!(b.is_idle_noaccess());
    let [below, block, above] = b.layout();
    assert_eq!(protection_at(block.start), Protection::NONE);
    let inside = b.with(|x| {
        assert_eq!(x[4095], 3);
        protection_at(block.start)
    });
    assert_eq!(inside, Protection::READ);
    assert_eq!(protection_at(block.start), Protection::NONE);
    assert_eq!(protection_at(below.start), Protection::NONE);
    assert_eq!(protection_at(above.start), Protection::NONE);
}

#[test]
fn idle_noaccess_closes_again_after_a_panic() {
    let b = GuardedBlock::<64>::new_with_idle_noaccess(|x| x.fill(1)).unwrap();
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        b.with(|_| panic!("closure panicked"));
    }));
    assert!(r.is_err());
    assert_eq!(protection_at(b.layout()[1].start), Protection::NONE);
    assert_eq!(b.with(|x| x[0]), 1, "still usable after the panic");
}

#[test]
fn nested_and_concurrent_access_share_one_window() {
    let b = GuardedBlock::<64>::new_with_idle_noaccess(|x| x.fill(2)).unwrap();
    let start = b.layout()[1].start;
    b.with(|outer| {
        b.with(|inner| assert_eq!(inner[0], 2));
        // The inner call closing must not close the outer window.
        assert_eq!(protection_at(start), Protection::READ);
        assert_eq!(outer[63], 2);
    });
    std::thread::scope(|s| {
        for _ in 0..8 {
            s.spawn(|| {
                for _ in 0..2000 {
                    assert_eq!(b.with(|x| x[17]), 2);
                }
            });
        }
    });
    assert_eq!(protection_at(start), Protection::NONE);
}

#[test]
fn the_default_mode_is_not_idle_noaccess() {
    let b = GuardedBlock::<64>::new_with(|_| {}).unwrap();
    assert!(!b.is_idle_noaccess());
}

#[test]
fn lock_status_reports_the_windows_idle_trade() {
    let locked = GuardedBlock::<64>::new_with(|_| {}).unwrap();
    let idle = GuardedBlock::<64>::new_with_idle_noaccess(|_| {}).unwrap();
    if cfg!(windows) {
        assert_eq!(
            locked.lock_status(),
            Ok(()),
            "a lone block locks under the default quota"
        );
        let e: LockError = idle.lock_status().unwrap_err();
        assert!(e.idle_noaccess());
        assert_eq!(e.raw_os_error(), None);
        assert_eq!(
            e.to_string(),
            "the block is not locked in RAM: it is no-access while idle, and on Windows a \
             no-access page cannot stay locked"
        );
    } else if locked.lock_status().is_ok() {
        // Where the host grants locks at all, idle no-access keeps its lock off Windows.
        assert_eq!(idle.lock_status(), Ok(()));
    }
}

#[test]
fn debug_shows_neither_bytes_nor_address() {
    let b = GuardedBlock::<8>::new_with(|x| x.fill(0x41)).unwrap();
    let s = format!("{b:?}");
    assert_eq!(s, "GuardedBlock([REDACTED])");
    let e = format!(
        "{:?}",
        GuardedBlock::<8>::new_with_idle_noaccess(|_| {})
            .unwrap()
            .lock_status()
    );
    assert!(!e.contains("0x"), "{e}");
}

/// The panic reaches the caller. (That the half-built block is then wiped and unmapped is
/// `Drop` running on a local; `release_wipes_then_unlocks` in the unit tests covers what that
/// `Drop` does.)
#[test]
fn a_panicking_fill_propagates_its_panic() {
    let r = std::panic::catch_unwind(|| {
        GuardedBlock::<64>::new_with(|_| panic!("fill failed")).map(|_| ())
    });
    assert!(r.is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn the_block_is_excluded_from_core_dumps() {
    let b = GuardedBlock::<64>::new_with(|_| {}).unwrap();
    let start = b.layout()[1].start;
    let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
    let mut inside = false;
    let mut flags = None;
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
            flags = Some(line.to_string());
        }
    }
    let flags = flags.expect("block mapping in smaps");
    assert!(flags.split_whitespace().any(|f| f == "dd"), "{flags}");
}

#[cfg(target_os = "linux")]
fn smaps_flags(addr: usize) -> String {
    let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
    let mut inside = false;
    for line in smaps.lines() {
        if let Some((range, _)) = line.split_once(' ') {
            if let Some((lo, hi)) = range.split_once('-') {
                if let (Ok(lo), Ok(hi)) =
                    (usize::from_str_radix(lo, 16), usize::from_str_radix(hi, 16))
                {
                    inside = lo <= addr && addr < hi;
                    continue;
                }
            }
        }
        if inside && line.starts_with("VmFlags:") {
            return line.to_string();
        }
    }
    panic!("address not in smaps")
}

/// On Linux an idle no-access block keeps its lock through real accesses, read back from
/// the kernel rather than from the cached result of the first `mlock`.
#[cfg(target_os = "linux")]
#[test]
fn on_linux_idle_noaccess_keeps_the_lock_across_accesses() {
    let b = GuardedBlock::<4096>::new_with_idle_noaccess(|x| x.fill(4)).unwrap();
    if b.lock_status().is_err() {
        return; // This host refuses locks at all (RLIMIT_MEMLOCK of 0).
    }
    for _ in 0..3 {
        assert_eq!(b.with(|x| x[0]), 4);
    }
    let flags = smaps_flags(b.layout()[1].start);
    assert!(flags.split_whitespace().any(|f| f == "lo"), "{flags}");
}

/// A `fork()` child does not inherit page locks, and `lock_status` must say so there rather
/// than repeat the parent's result. The child only calls async-signal-safe functions
/// (`getpid` inside `lock_status`, `_exit`), since the test harness is multithreaded.
#[cfg(target_os = "linux")]
#[test]
fn after_fork_the_child_reports_the_lock_as_not_inherited() {
    let b = GuardedBlock::<64>::new_with(|x| x.fill(5)).unwrap();
    let parent = b.lock_status();
    // SAFETY (test): the child runs only `lock_status` (no allocation: it returns a `Copy`
    // value) and `_exit`.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        let code = match b.lock_status() {
            Err(e) if e.forked() => 0,
            Err(_) => 2,
            Ok(()) => 3,
        };
        // SAFETY (test): ends the child without running the parent's destructors.
        unsafe { libc::_exit(code) };
    }
    let mut status = 0;
    // SAFETY (test): waits for the child created above.
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert!(libc::WIFEXITED(status));
    assert_eq!(
        libc::WEXITSTATUS(status),
        0,
        "child: 2 = another lock error, 3 = reported locked"
    );
    assert_eq!(
        b.lock_status(),
        parent,
        "the parent's own status is unchanged"
    );
}
