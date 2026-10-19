//! Pre-key page locking, in a process of its own: every lock in a process draws on one
//! quota (the working set on Windows, `RLIMIT_MEMLOCK` on Unix), so this binary holds a
//! single test and runs nothing beside it.
#![cfg(feature = "sealed")]

use secure_gate::{Fixed, Prekey, SealedFixed};

/// Enough pre-keys (16 KiB each) to exhaust Windows' default working-set quota many times
/// over; on Unix the limit may be higher than this, which the test allows.
const MANY: usize = 1024;

#[test]
fn locks_succeed_fail_softly_and_are_released_on_drop() {
    // A first pre-key, alone in the process, locks. Required on Windows, where the default
    // quota allows it; elsewhere a zero RLIMIT_MEMLOCK (common in containers) or pages larger
    // than the pre-key refuse it by design, and the rest of this test has nothing to measure.
    let first = Prekey::new();
    if cfg!(windows) {
        assert_eq!(first.lock_status(), Ok(()), "a lone pre-key locks");
    } else if let Err(why) = first.lock_status() {
        eprintln!("skipping: this host refuses a lone pre-key lock ({why})");
        return;
    }
    drop(first);

    // Keep creating until the quota refuses one. A refusal is reported, never a panic, and
    // the refused pre-key still seals and opens.
    let mut held = Vec::new();
    let mut refused = None;
    for _ in 0..MANY {
        let k = Prekey::new();
        let status = k.lock_status();
        held.push(k);
        if let Err(e) = status {
            refused = Some(e);
            break;
        }
    }

    #[cfg(windows)]
    {
        let e = refused.expect("Windows' default working-set quota refuses a lock");
        assert_eq!(e.raw_os_error(), Some(1453), "ERROR_WORKING_SET_QUOTA");
    }

    if refused.is_some() {
        let last = held.last().unwrap();
        let s = SealedFixed::seal(Fixed::new([3u8; 32]), last);
        s.with_secret(|b| assert_eq!(b[0], 3));

        // After the drops a new pre-key locks again. This does not prove the unlock: on
        // Windows, freeing the block decommits its pages, which releases their lock anyway.
        // `wipe_and_unlock_returns_the_quota` in `src/sealed/prekey.rs` unlocks while the
        // blocks are still allocated, which is what tells a missing unlock apart.
        drop(s);
        held.clear();
        assert_eq!(Prekey::new().lock_status(), Ok(()));
    }
}
